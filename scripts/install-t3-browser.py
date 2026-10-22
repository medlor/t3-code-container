#!/usr/bin/env python3
"""Invoke the installed T3's authenticated local preview API at image build time.

No download URLs or browser versions are chosen here. T3 owns the installer,
including its pinned archive length/SHA-256 validation and atomic cache publish.
All auth/server state lives inside one TemporaryDirectory in this RUN layer.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import uuid

from t3_sandbox.browser import sha256, version


class CompatibilityError(ValueError):
    pass


def t3_files(t3):
    launcher = t3.resolve()
    # Native installs and the official npm package are both supported. Resolve
    # the npm platform package through Node, never by scraping executable bytes.
    if launcher.suffix != '.js':
        return [launcher]
    script = '''const {createRequire}=require('node:module');
const path=require('node:path'); const req=createRequire(process.argv[1]);
console.log(path.join(path.dirname(req.resolve('@t3code/t3-'+process.platform+'-'+process.arch+'/package.json')),'t3'));'''
    result = subprocess.run(['node', '-e', script, str(launcher)], capture_output=True, text=True, timeout=30)
    if result.returncode:
        raise CompatibilityError('Installed T3 npm package lacks its supported native platform executable')
    binary = Path(result.stdout.strip()).resolve(strict=True)
    if version(binary) != version(t3):
        raise CompatibilityError('Installed T3 launcher and native executable versions differ')
    return [launcher, binary]


def materialize(t3, base, destination):
    """Replace npm's home-dependent launcher with its verified release binary."""
    launcher = t3.resolve()
    if launcher.suffix not in ('.js', '.mjs'):
        return [launcher]
    if launcher.suffix == '.js':
        binary = t3_files(t3)[-1]
        observed = version(t3)
    else:
        package = launcher.parent.parent / 'package.json'
        if launcher.name != 't3.mjs' or not package.is_file():
            raise CompatibilityError('Unsupported installed T3 npm package layout')
        release = json.loads(package.read_text()).get('version', '')
        if not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?', release):
            raise CompatibilityError('Unsupported installed T3 npm package version')
        state = base / 'native-state'
        home = base / 'native-home'
        home.mkdir(parents=True)
        env = {key: value for key, value in os.environ.items() if not key.startswith(('T3CODE_', 'XDG_'))}
        env.update(HOME=str(home), T3CODE_HOME=str(state))
        result = subprocess.run([str(t3), '--version'], env=env, capture_output=True, text=True, timeout=900)
        if result.returncode:
            raise CompatibilityError('Installed T3 npm launcher could not provision its exact native release')
        observed = result.stdout.strip()
        directory = state / 'runtime/versions' / release
        binary = directory / 't3'
        if not binary.is_file() or not (directory / '.install-complete').is_file() or (directory / '.install-complete').read_text().strip() != release:
            raise CompatibilityError('Installed T3 npm runtime cache layout/completion marker is incompatible')
        if observed != 't3 v' + release:
            raise CompatibilityError('Installed T3 npm release and native version differ')
    if version(binary) != observed:
        raise CompatibilityError('Installed T3 native binary version mismatch')
    # The release includes client assets, native modules and resource-monitor
    # sidecars. Copy the verified release directory, never the enclosing HOME.
    shutil.copytree(binary.parent, destination.parent, dirs_exist_ok=True, symlinks=True)
    # The official launcher makes its private cache directory mode 0700. The
    # immutable image release must also be traversable by the runtime user.
    destination.parent.chmod(0o755)
    if destination.name != binary.name:
        (destination.parent / binary.name).rename(destination)
    destination.chmod(0o755)
    t3.unlink()
    t3.symlink_to(destination)
    return [launcher, destination]


def publish(cache, destination, t3, binaries):
    entries = list(cache.glob('*/*/chrome-headless-shell'))
    if len(entries) != 1:
        raise CompatibilityError('Installed T3 did not publish exactly one supported browser cache entry')
    executable = entries[0]
    platform, browser_version, _ = executable.relative_to(cache).parts
    if not re.fullmatch(r'\d+\.\d+\.\d+\.\d+', browser_version) or browser_version not in version(executable):
        raise ValueError('Installed browser version does not match its T3 cache directory')
    assets = {}
    for path in executable.parent.rglob('*'):
        if path.is_symlink():
            raise ValueError('Unexpected symlink in installed browser assets')
        if path.is_file():
            assets[str(path.relative_to(cache))] = sha256(path)
    manifest = {'schema': 1, 't3_version': version(t3),
                't3_files': {str(path.resolve()): sha256(path) for path in binaries},
                'platform': platform, 'browser_version': browser_version,
                'executable': str(executable.relative_to(cache)), 'assets': assets}
    destination.mkdir(parents=True, exist_ok=False)
    shutil.copytree(executable.parent, destination / platform / browser_version)
    # Archive extraction under the build server's private umask can leave
    # resources mode 0600. Assets are immutable and shared by the runtime user.
    for asset in destination.rglob('*'):
        asset.chmod(0o755 if asset.is_dir() or asset.stat().st_mode & 0o111 else 0o644)
    (destination / 'executable').symlink_to(manifest['executable'])
    (destination / 'manifest.json').write_text(json.dumps(manifest, sort_keys=True, indent=2) + '\n')
    print(f"Provisioned {manifest['t3_version']} browser {platform}/{browser_version} ({len(assets)} verified files)")


def request(port, token, path, payload=None, session=None):
    headers = {'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json',
               'Accept': 'application/json, text/event-stream'}
    headers.update(session or {})
    req = urllib.request.Request(f'http://127.0.0.1:{port}{path}',
        data=json.dumps(payload).encode() if payload else None, headers=headers)
    # Explicitly bypass inherited build proxies for the disposable local server.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        response = opener.open(req, timeout=60)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        if session is not None and response.headers.get('Mcp-Session-Id'):
            session['Mcp-Session-Id'] = response.headers['Mcp-Session-Id']
        if 'text/event-stream' in response.headers.get('Content-Type', ''):
            for line in response:
                if line.startswith(b'data:'):
                    return json.loads(line[5:])
            raise CompatibilityError('Installed T3 MCP returned no tool response')
        return json.load(response)


def preview_socket(port, token, protocol):
    if type(protocol) is not int:
        raise CompatibilityError('Installed T3 does not advertise an integer orchestration protocol')
    connection = socket.create_connection(('127.0.0.1', port), timeout=30)
    key = base64.b64encode(os.urandom(16)).decode()
    connection.sendall((f'GET /ws?orchestrationProtocol={protocol} HTTP/1.1\r\n'
        f'Host: 127.0.0.1:{port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n'
        f'Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n'
        f'Authorization: Bearer {token}\r\n\r\n').encode())
    header = bytearray()
    while not header.endswith(b'\r\n\r\n') and len(header) < 16384:
        chunk = connection.recv(1)
        if not chunk:
            break
        header.extend(chunk)
    accept = base64.b64encode(hashlib.sha1((key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest())
    if not header.startswith(b'HTTP/1.1 101 ') or accept not in header:
        connection.close()
        raise CompatibilityError('Installed T3 rejected the authenticated local preview WebSocket')
    payload = json.dumps({'_tag': 'Request', 'id': '1', 'tag': 'preview.open',
        'payload': {'threadId': str(uuid.uuid4()), 'runtime': 'server'},
        'headers': []}).encode()
    mask = os.urandom(4)
    connection.sendall(b'\x81\xfe' + struct.pack('!H', len(payload)) + mask +
        bytes(byte ^ mask[i % 4] for i, byte in enumerate(payload)))
    connection.settimeout(1)
    return connection


def trigger_preview(port, issue):
    token = issue('mcp-client')
    session = {}
    initialized = request(port, token, '/mcp', {'jsonrpc': '2.0', 'id': 0,
        'method': 'initialize', 'params': {'protocolVersion': '2025-06-18', 'capabilities': {},
        'clientInfo': {'name': 't3-browser-build', 'version': '1'}}}, session=session)
    if 'result' not in initialized or not session.get('Mcp-Session-Id'):
        raise CompatibilityError('Installed T3 MCP initialize/session interface is incompatible')
    result = request(port, token, '/mcp', {'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call',
        'params': {'name': 'html_preview', 'arguments': {'html': '<!doctype html><p>build</p>'}}},
        session=session)
    failed = 'error' in result or result.get('result', {}).get('isError', False)
    description = json.dumps(result).lower()
    if failed and ('outside a thread' in description or 'requires thread scope' in description):
        print('T3 MCP requires thread scope; using authenticated local preview.open')
        token = issue('browser-build-client')
        protocol = request(port, token, '/ws').get('orchestrationProtocolVersion')
        return preview_socket(port, token, protocol)
    if failed and 'installing' not in description:
        raise CompatibilityError('Installed T3 MCP rejected html_preview (not a thread-scope response)')
    return None


def provision(t3, destination):
    with tempfile.TemporaryDirectory(prefix='t3-browser-build-') as temporary:
        base = Path(temporary)
        binaries = materialize(t3, base, Path('/opt/t3-runtime/t3'))
        env = {key: value for key, value in os.environ.items() if not key.startswith(('T3CODE_', 'XDG_'))}
        env.update(HOME=str(base / 'home'), XDG_CONFIG_HOME=str(base / 'config'),
                   XDG_CACHE_HOME=str(base / 'cache'), XDG_DATA_HOME=str(base / 'data'))
        Path(env['HOME']).mkdir()
        state = base / 't3'
        def issue(subject):
            result = subprocess.run([str(t3), 'auth', 'session', 'issue', '--base-dir', str(state),
                '--subject', subject, '--ttl', '20m', '--token-only'], env=env, capture_output=True,
                text=True, timeout=30)
            if result.returncode or not result.stdout.strip():
                raise CompatibilityError('Installed T3 lacks auth session issue --base-dir --token-only')
            return result.stdout.strip()
        with socket.socket() as reservation:
            reservation.bind(('127.0.0.1', 0))
            port = reservation.getsockname()[1]
        process = subprocess.Popen([str(t3), 'serve', '--base-dir', str(state), '--host',
            '127.0.0.1', '--port', str(port), '--no-browser'], env=env, cwd=base,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        connection = None
        try:
            deadline = time.monotonic() + 60
            while True:
                try:
                    with socket.create_connection(('127.0.0.1', port), timeout=1):
                        break
                except OSError:
                    if process.poll() is not None or time.monotonic() >= deadline:
                        raise CompatibilityError('Installed T3 local build server did not become ready')
                    time.sleep(.2)
            connection = trigger_preview(port, issue)
            cache = state / 'tools/chrome-headless-shell'
            deadline = time.monotonic() + 900
            while not list(cache.glob('*/*/chrome-headless-shell')):
                if time.monotonic() >= deadline or process.poll() is not None:
                    raise CompatibilityError('Installed T3 preview API did not publish a verified browser within 15 minutes')
                if connection:
                    try:
                        data = connection.recv(65536)
                        if not data:
                            raise CompatibilityError('Installed T3 closed preview RPC before browser installation')
                        if b'"_tag":"Failure"' in data or b'"_tag":"Defect"' in data:
                            raise CompatibilityError('Installed T3 rejected the public preview.open RPC')
                    except socket.timeout:
                        pass
                else:
                    time.sleep(1)
            # T3 atomically renames the extracted release only after verifying it.
            # Browser launch may fail under build sandbox policies; --version and
            # asset integrity remain mandatory, and no sandbox flag is disabled.
            publish(cache, destination, t3, binaries)
        finally:
            if connection:
                connection.close()
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--t3', type=Path, required=True)
    parser.add_argument('--destination', type=Path, required=True)
    args = parser.parse_args()
    try:
        provision(args.t3, args.destination)
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        # Never include auth command output, server logs, or credential headers.
        print(f'T3 browser provisioning failed: {error}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
