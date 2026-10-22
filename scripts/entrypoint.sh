#!/usr/bin/env bash
set -euo pipefail
umask 022
if [[ $(id -u) == 0 ]]; then
    echo 'Run this image as your non-root user with --userns=keep-id.' >&2
    exit 1
fi
mkdir -p "$HOME/.local/bin" "$HOME/.cache" "$HOME/.config" "$HOME/.npm-global"
if [[ ! -w /workspace || ! -w $HOME ]]; then
    echo 'Project or home is not writable. Check the host ownership and UID/GID mapping.' >&2
    exit 1
fi
/usr/bin/python3 -I -S /usr/local/lib/t3-sandbox/browser.py
exec "$@"
