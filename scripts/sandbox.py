#!/usr/bin/env python3
"""Host CLI: selectors are data, never shell configuration."""
import argparse
import os
from pathlib import Path
import pwd
import subprocess
import sys

from t3_sandbox.launcher import Launcher
from t3_sandbox.paths import HostContext, validate_profile_name
from t3_sandbox.podman import Podman


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('command', choices=('init', 'doctor', 'build', 'rebuild', 'start', 'stop', 'restart',
        'recreate', 'remove', 'status', 'logs', 'proxy-restart', 'firewall-logs', 'shell', 'exec', 'pair', 'smoke', 'config'))
    parser.add_argument('--profile', default=os.environ.get('PROFILE', 'default'))
    parser.add_argument('--profile-dir', type=Path, default=os.environ.get('PROFILE_DIR') or None)
    parser.add_argument('--cmd', default=os.environ.get('CMD'))
    parser.add_argument('--follow', choices=('0', '1'), default=os.environ.get('FOLLOW', '1'))
    parser.add_argument('--tail', type=int, default=os.environ.get('TAIL', '100'))
    args = parser.parse_args()
    try:
        validate_profile_name(args.profile)
        if args.follow not in ('0', '1') or args.tail < 0:
            raise ValueError('FOLLOW must be 0 or 1 and TAIL must be nonnegative')
        home = Path.home()
        profile_dir = args.profile_dir or home / '.config/t3-sandbox/profiles'
        if not profile_dir.is_absolute():
            raise ValueError('PROFILE_DIR must be an absolute path')
        host = HostContext(home, os.getuid(), os.getgid(), pwd.getpwuid(os.getuid()).pw_name)
        return Launcher(Podman(), host, profile_dir.resolve()).dispatch(args.command, args.profile,
            cmd=args.cmd, follow=args.follow == '1', tail=args.tail)
    except (ValueError, OSError, subprocess.SubprocessError) as exc:
        # Podman errors can contain runtime env values; do not echo argv/stderr.
        message = 'Podman command failed; inspect make logs or host Podman diagnostics' if isinstance(exc, subprocess.SubprocessError) else str(exc)
        print('Error: ' + message, file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
