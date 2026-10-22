"""Bounded, credential-free proxy-policy denial records.

Only Squid's explicit local access-denial marker plus our decision annotation
produce a record. HTTP status codes alone never establish a policy denial.
"""
from dataclasses import asdict, dataclass
from contextlib import ExitStack, contextmanager
from datetime import datetime, timezone
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import time
from typing import Iterator
from urllib.parse import unquote_to_bytes

from .policy import GatewayConfig, is_protected_address

MAX_LOG_BYTES = 5 * 1024 * 1024
RETAINED_LOGS = 3
MAX_DECISION_BYTES = 4096
REASONS = frozenset(('unlisted_destination', 'forbidden_port', 'protected_address'))
_DOMAIN = re.compile(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*', re.ASCII)
_METHOD = re.compile(r'[A-Z]{1,32}', re.ASCII)


def _destination(value):
    value = value.lower().removesuffix('.')
    if not value or len(value) > 253 or not value.isascii() or '%' in value:
        raise ValueError('Invalid destination')
    if value.startswith('[') and value.endswith(']'):
        return str(ipaddress.IPv6Address(value[1:-1]))
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        if not _DOMAIN.fullmatch(value):
            raise ValueError('Invalid destination') from None
        return value


@dataclass(frozen=True)
class DenialRecord:
    timestamp: str
    destination: str
    port: int
    method: str
    reason: str
    policy_digest: str

    def __post_init__(self):
        if not re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z', self.timestamp):
            raise ValueError('Invalid timestamp')
        datetime.fromisoformat(self.timestamp.replace('Z', '+00:00'))
        if _destination(self.destination) != self.destination:
            raise ValueError('Destination must be normalized')
        if type(self.port) is not int or not 1 <= self.port <= 65535:
            raise ValueError('Invalid port')
        if not _METHOD.fullmatch(self.method) or self.reason not in REASONS:
            raise ValueError('Invalid decision')
        if not re.fullmatch('[0-9a-f]{64}', self.policy_digest):
            raise ValueError('Invalid digest')

    def json_line(self) -> str:
        return json.dumps(asdict(self), sort_keys=True, separators=(',', ':'), ensure_ascii=True) + '\n'


def parse_denial(line: str, *, policy_digest: str, gateway: GatewayConfig | None = None) -> DenialRecord | None:
    """Parse the seven-field t3decision format from the packaged Squid version.

    Percent escapes are decoded before validating; only DNS/IP authorities and
    alphabetic methods survive. No URL, header, username, or path is logged.
    """
    if not isinstance(line, str) or len(line) > MAX_DECISION_BYTES:
        return None
    parts = line.rstrip('\n').split(' ')
    if len(parts) != 7:
        return None
    stamp, status, error, reason, destination, port, method = parts
    if status != 'TCP_DENIED' or error != 'ERR_ACCESS_DENIED' or reason not in REASONS:
        return None
    try:
        if not re.fullmatch(r'\d{1,11}\.\d{3}', stamp) or not re.fullmatch(r'\d{1,5}', port):
            return None
        timestamp = datetime.fromtimestamp(float(stamp), timezone.utc).isoformat(timespec='milliseconds').replace('+00:00', 'Z')
        destination = _destination(unquote_to_bytes(destination).decode('ascii'))
        if gateway is not None:
            try:
                literal = str(ipaddress.ip_address(destination))
            except ValueError:
                pass  # Domain denial keeps Squid's decision; no new DNS lookup.
            else:
                if is_protected_address(literal, gateway):
                    reason = 'protected_address'
        return DenialRecord(timestamp, destination, int(port), method, reason, policy_digest)
    except (ValueError, UnicodeError, OverflowError, OSError, TypeError):
        return None


def append_denial(path: Path, record: DenialRecord) -> None:
    """Synchronously append one canonical line; bound disk use to four files.

    A single supervisor owns the directory. Errors propagate and stop the gateway
    rather than accumulating an in-memory queue or silently losing audit output.
    """
    data = record.json_line().encode('ascii')
    if len(data) > MAX_LOG_BYTES:
        raise ValueError('Record exceeds log bound')
    if path.exists() and path.stat().st_size + len(data) > MAX_LOG_BYTES:
        for index in range(RETAINED_LOGS, 0, -1):
            source = path if index == 1 else path.with_name(path.name + '.' + str(index - 1))
            target = path.with_name(path.name + '.' + str(index))
            if source.exists():
                source.replace(target)
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(data)


def _read_records(stream, state):
    """Consume complete bounded lines; leave an incomplete write for next poll."""
    offset, discarding = state
    if os.fstat(stream.fileno()).st_size < offset:
        offset, discarding = 0, False
    stream.seek(offset)
    while True:
        start = stream.tell()
        line = stream.readline(MAX_DECISION_BYTES + 1)
        if not line:
            break
        if not line.endswith(b'\n'):
            if len(line) > MAX_DECISION_BYTES or discarding:
                discarding = True
                offset = stream.tell()
                continue
            stream.seek(start)
            break
        offset = stream.tell()
        if discarding or len(line) > MAX_DECISION_BYTES:
            discarding = False
            continue
        try:
            value = json.loads(line)
            if type(value) is not dict or not all(isinstance(value.get(key), str) for key in
                    ('timestamp', 'destination', 'method', 'reason', 'policy_digest')):
                continue
            yield DenialRecord(**value), (offset, discarding)
        except (ValueError, TypeError, UnicodeError):
            continue
    return offset, discarding


@contextmanager
def _log_snapshot(directory):
    """Pin a coherent retained-inode order before reading or emitting records."""
    paths = [directory / ('denials.jsonl' + ('.' + str(index) if index else ''))
             for index in range(RETAINED_LOGS, -1, -1)]
    while True:
        with ExitStack() as files:
            streams, captured = [], []
            for path in paths:
                try:
                    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                except FileNotFoundError:
                    captured.append(None)
                    continue
                stream = files.enter_context(os.fdopen(descriptor, 'rb'))
                info = os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode):
                    raise ValueError('Denial log must be a regular file')
                inode = info.st_dev, info.st_ino
                captured.append(inode)
                streams.append((inode, stream))
            observed = []
            for path in paths:
                try:
                    info = path.stat(follow_symlinks=False)
                except FileNotFoundError:
                    observed.append(None)
                else:
                    observed.append((info.st_dev, info.st_ino))
            if captured == observed:
                # Descriptors retain this order even if paths rotate afterwards.
                yield streams
                return
        # A rotation crossed the scan. Close all descriptors and retry without
        # committing offsets or a partial tail from the inconsistent snapshot.
        time.sleep(0.01)


def read_denials(directory: Path, *, tail: int = 100, follow: bool = True) -> Iterator[DenialRecord]:
    """Tail canonical records across retention; follow inode renames and restart.

    Retain only requested tail records, at most four pinned files/inode offsets,
    and one bounded line. No mutation lock is held; files are closed before sleeping.
    Invalid/incomplete records never enter JSONL output.
    """
    from collections import deque

    if type(tail) is not int or tail < 0:
        raise ValueError('TAIL must be nonnegative')
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError('Denial log directory is unavailable')
    positions = {}
    initial = True
    recent = deque(maxlen=tail)
    while True:
        seen = set()
        with _log_snapshot(directory) as streams:
            for inode, stream in streams:
                if inode in seen:
                    continue
                seen.add(inode)
                records = _read_records(stream, positions.get(inode, (0, False)))
                while True:
                    try:
                        record, state = next(records)
                    except StopIteration as end:
                        positions[inode] = end.value
                        break
                    positions[inode] = state
                    if initial:
                        recent.append(record)
                    else:
                        yield record
        positions = {inode: state for inode, state in positions.items() if inode in seen}
        if initial:
            initial = False
            yield from recent
            recent.clear()
            if not follow:
                return
        time.sleep(0.1)
