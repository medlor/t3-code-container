"""Trusted PID1 for the isolated egress gateway; no host namespace operations."""
import argparse
import ctypes
import ipaddress
import json
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import tempfile
import time

from t3_sandbox.denials import MAX_DECISION_BYTES, append_denial, parse_denial
from t3_sandbox.policy import MAX_SNAPSHOT_BYTES, CompiledPolicy, compile_policy, decode_snapshot

PROXY_UID = 2001
RELAY_UID = 2002
SUPERVISOR_UID = 2003
RUN = Path('/run/t3-proxy')
READY = RUN / 'ready.json'
_LIBC = ctypes.CDLL(None, use_errno=True)


def prctl(option, value):
    if _LIBC.prctl(option, value, 0, 0, 0) != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))


def clear_capabilities():
    class Header(ctypes.Structure):
        _fields_ = [('version', ctypes.c_uint32), ('pid', ctypes.c_int)]
    class Data(ctypes.Structure):
        _fields_ = [('effective', ctypes.c_uint32), ('permitted', ctypes.c_uint32), ('inheritable', ctypes.c_uint32)]
    header = Header(0x20080522, 0)
    data = (Data * 2)()
    if _LIBC.capset(ctypes.byref(header), ctypes.byref(data)) != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
    prctl(47, 4)  # PR_CAP_AMBIENT / PR_CAP_AMBIENT_CLEAR_ALL


def drop_privileges(uid):
    # Drop every supported bounding capability while SETPCAP is still present.
    last = int(Path('/proc/sys/kernel/cap_last_cap').read_text())
    for capability in range(last + 1):
        prctl(24, capability)  # PR_CAPBSET_DROP
    prctl(38, 1)  # PR_SET_NO_NEW_PRIVS
    os.setgroups([])
    os.setresgid(uid, uid, uid)
    os.setresuid(uid, uid, uid)
    clear_capabilities()


def _child(uid):
    parent = os.getppid()
    drop_privileges(uid)
    prctl(1, signal.SIGKILL)  # Credential changes clear PDEATHSIG: apply last.
    if os.getppid() != parent:
        os._exit(1)


def validate_snapshot(path: Path) -> CompiledPolicy:
    with path.open('rb') as stream:
        allow, gateway = decode_snapshot(stream.read(MAX_SNAPSHOT_BYTES + 1))
    compiled = compile_policy(allow, gateway, proxy_uid=PROXY_UID, relay_uid=RELAY_UID)
    # Parsing never installs nft rules or starts Squid/relay listeners. nft's
    # --check requires NET_ADMIN and is performed only by privileged serve init.
    with tempfile.TemporaryDirectory(prefix='t3-proxy-validate-') as temporary:
        config = Path(temporary) / 'squid.conf'
        config.write_text(compiled.squid_conf)
        subprocess.run(['squid', '-k', 'parse', '-f', str(config)], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
    return compiled


def initialize(compiled):
    for setting in ('/proc/sys/net/ipv4/ip_forward', '/proc/sys/net/ipv6/conf/all/forwarding',
                    '/proc/sys/net/ipv6/conf/default/forwarding'):
        path = Path(setting)
        # Rootless container /proc/sys may be read-only. Host launcher must set
        # --sysctl values; accept a read-only zero, reject any nonzero value.
        if path.read_text().strip() != '0':
            path.write_text('0\n')
        if path.read_text().strip() != '0':
            raise ValueError('Gateway forwarding must be disabled')
    RUN.mkdir(mode=0o755, parents=True, exist_ok=True)
    # Root owns the config/readiness directory. Only the dedicated ephemeral
    # Squid PID/coredump subdirectory is owned by the proxy; never host data.
    os.chown(RUN, 0, 0)
    os.chmod(RUN, 0o755)
    squid_run = RUN / 'squid'
    squid_run.mkdir(mode=0o700, exist_ok=True)
    os.chown(squid_run, 0, 0)
    # Only our fixed PID file may survive a stopped container's /run layer.
    # PID1 initialization runs before any daemon, so it cannot identify a live
    # Squid here. Never recurse or remove any host state.
    (squid_run / 'squid.pid').unlink(missing_ok=True)
    os.chown(squid_run, PROXY_UID, PROXY_UID)
    (RUN / 'squid.conf').write_text(compiled.squid_conf)
    (RUN / 'nft.conf').write_text(compiled.nft_conf)
    subprocess.run(['nft', '--check', '-f', str(RUN / 'nft.conf')], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
    subprocess.run(['nft', '-f', str(RUN / 'nft.conf')], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
    fifo = RUN / 'decisions.fifo'
    fifo.unlink(missing_ok=True)
    os.mkfifo(fifo, 0o660)
    os.chmod(fifo, 0o660)
    os.chown(fifo, PROXY_UID, 0)
    # A fixed pre-created file lets the supervisor publish/clear readiness
    # without write access to the root-owned parent directory.
    READY.write_text('')
    os.chmod(READY, 0o644)
    os.chown(READY, SUPERVISOR_UID, SUPERVISOR_UID)


def listener_present(address, port, uid, rows=None):
    if rows is None:
        rows = Path('/proc/net/tcp').read_text()
    target = ipaddress.IPv4Address(address).packed[::-1].hex().upper() + ':' + f'{port:04X}'
    for row in rows.splitlines()[1:]:
        fields = row.split()
        if len(fields) > 7 and fields[1] == target and fields[3] == '0A' and fields[7] == str(uid):
            return True
    return False


class DecisionBuffer:
    """Incremental bounded framing; discard an oversized line until its LF."""
    def __init__(self):
        self.pending = b''
        self.discarding = False

    def feed(self, data):
        result = []
        for part in data.splitlines(keepends=True):
            ended = part.endswith(b'\n')
            if not self.discarding:
                if len(self.pending) + len(part) > MAX_DECISION_BYTES:
                    self.pending = b''
                    self.discarding = True
                else:
                    self.pending += part
                    if ended:
                        result.append(self.pending.decode('ascii', errors='replace'))
                        self.pending = b''
            if ended:
                self.discarding = False
        return result


def supervise(children, *, ready, reader, log_path, digest, ready_path=READY, gateway=None):
    stopping = False
    def stop(signum, frame):
        nonlocal stopping
        stopping = True
    previous = {sig: signal.signal(sig, stop) for sig in (signal.SIGTERM, signal.SIGINT)}
    buffer = DecisionBuffer()
    deadline = time.monotonic() + 30
    announced = False
    try:
        while not stopping:
            if any(child.poll() is not None for child in children):
                return 1
            if not announced:
                if ready():
                    ready_path.write_text(json.dumps({'digest': digest}, sort_keys=True) + '\n')
                    announced = True
                elif time.monotonic() >= deadline:
                    return 1
            if reader is not None and select.select([reader], [], [], 0.1)[0]:
                data = os.read(reader, 4096)
                if not data:
                    return 1
                for line in buffer.feed(data):
                    record = parse_denial(line, policy_digest=digest, gateway=gateway)
                    if record is not None:
                        append_denial(log_path, record)
            else:
                time.sleep(0.1)
        return 0
    finally:
        # Empty content is never a ready marker. Precreated file permissions
        # allow the supervisor to clear it without modifying the root directory.
        if ready_path.exists():
            ready_path.write_text('')
        for sig, handler in previous.items():
            signal.signal(sig, handler)


def serve(snapshot: Path, logs: Path) -> int:
    if os.getpid() != 1:
        print('Gateway serve must be namespace PID1', file=sys.stderr)
        return 1
    try:
        READY.unlink(missing_ok=True)
        compiled = validate_snapshot(snapshot)
        with snapshot.open('rb') as stream:
            _, gateway = decode_snapshot(stream.read(MAX_SNAPSHOT_BYTES + 1))
        initialize(compiled)
        if not logs.is_dir() or logs.stat().st_uid != SUPERVISOR_UID or logs.stat().st_mode & 0o077:
            raise ValueError('Dedicated log directory must be supervisor-owned with mode 0700')
        reader = os.open(RUN / 'decisions.fifo', os.O_RDONLY | os.O_NONBLOCK)
        anchor = os.open(RUN / 'decisions.fifo', os.O_WRONLY | os.O_NONBLOCK)
        children = [subprocess.Popen(['squid', '-N', '-f', str(RUN / 'squid.conf')],
                    preexec_fn=lambda: _child(PROXY_UID), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)]
        children.append(subprocess.Popen(['socat', 'TCP4-LISTEN:3773,bind=0.0.0.0,reuseaddr,fork',
                        f'TCP4:{gateway.t3_ip}:3773'], preexec_fn=lambda: _child(RELAY_UID),
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
        drop_privileges(SUPERVISOR_UID)
        try:
            return supervise(children, ready=lambda: listener_present(gateway.private_ip, 3128, PROXY_UID)
                and listener_present('0.0.0.0', 3773, RELAY_UID), reader=reader,
                log_path=logs / 'denials.jsonl', digest=compiled.digest, gateway=gateway)
        finally:
            os.close(reader)
            os.close(anchor)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
        # Never echo untrusted policy/snapshot/parser text into container logs.
        print('Gateway initialization or supervision failed', file=sys.stderr)
        return 1


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('command', choices=('validate', 'serve'))
    parser.add_argument('--snapshot', type=Path, required=True)
    parser.add_argument('--logs', type=Path, default=Path('/var/log/t3-proxy'))
    args = parser.parse_args()
    if args.command == 'serve':
        return serve(args.snapshot, args.logs)
    try:
        compiled = validate_snapshot(args.snapshot)
    except (OSError, ValueError, subprocess.SubprocessError):
        print('Invalid gateway policy', file=sys.stderr)
        return 1
    print(json.dumps({'digest': compiled.digest}, sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main())
