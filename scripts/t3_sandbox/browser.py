"""Local manifest verification and cache seeding. Never contacts the network."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys


def sha256(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def version(executable):
    return subprocess.run([str(executable), '--version'], check=True, capture_output=True,
                          text=True, timeout=30).stdout.strip()


def relative_asset(value):
    path = Path(value)
    if path.is_absolute() or '..' in path.parts or not path.parts:
        raise ValueError('Invalid browser asset path in manifest')
    return path


def verify(image, t3):
    manifest = json.loads((image / 'manifest.json').read_text())
    if manifest['schema'] != 1 or manifest['t3_version'] != version(t3):
        raise ValueError('T3 browser manifest version mismatch; rebuild the image')
    if str(t3.resolve()) not in manifest['t3_files']:
        raise ValueError('T3 launcher is not recorded in the browser manifest')
    for name, digest in manifest['t3_files'].items():
        if sha256(name) != digest:
            raise ValueError('T3 binary hash mismatch; rebuild the image')
    for name, digest in manifest['assets'].items():
        asset = image / relative_asset(name)
        if asset.is_symlink() or sha256(asset) != digest:
            raise ValueError('Browser asset hash mismatch; rebuild the image')
    executable = relative_asset(manifest['executable'])
    if str(executable) not in manifest['assets'] or not os.access(image / executable, os.X_OK):
        raise ValueError('Browser executable missing from verified assets')
    if manifest['browser_version'] not in version(image / executable):
        raise ValueError('Browser version mismatch; rebuild the image')
    return manifest


def seed(image, t3, cache, wrapper, mountinfo=Path('/proc/self/mountinfo')):
    # Check the *actual mount* before any mkdir/write: the underlying .t3 can be
    # a shared host bind. A directory existing or being writable is insufficient.
    actual = cache.resolve()
    if actual != cache.absolute():
        raise ValueError('Browser cache must be an exact tmpfs mount, without symlink parents')
    mounted = False
    for line in mountinfo.read_text().splitlines():
        left, right = line.split(' - ', 1)
        fields = left.split()
        target = re.sub(r'\\([0-7]{3})', lambda m: chr(int(m[1], 8)), fields[4])
        if target == str(actual) and right.split()[0] == 'tmpfs' and 'rw' in fields[5].split(','):
            mounted = True
    if not mounted:
        raise ValueError('Browser cache is not a writable tmpfs mount; refusing to touch shared state')
    manifest = verify(image, t3)
    target = cache / relative_asset(manifest['executable'])
    # Reject residual symlinks on a restarted container too.
    if target.resolve() != target.absolute():
        raise ValueError('Browser cache contains an unsafe symlink')
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_name('.launcher.tmp')
    with temporary.open('xb') as stream:
        stream.write(wrapper.read_bytes())
    temporary.chmod(0o755)
    temporary.replace(target)


def main():
    try:
        seed(Path('/opt/t3-browser'), Path('/usr/local/bin/t3'),
             Path.home() / '.t3/tools/chrome-headless-shell',
             Path('/usr/local/libexec/t3-browser-launcher'))
    except (ValueError, OSError, KeyError, subprocess.SubprocessError) as error:
        print(f'Browser cache initialization failed: {error}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
