#!/usr/bin/env bash
set -euo pipefail
# Version probes must be identical to the immutable executable's output.
for arg in "$@"; do
    case "$arg" in --version|-version) exec /opt/t3-browser/executable "$@" ;; esac
done
if [[ -z ${T3_SANDBOX_BROWSER_PROXY:-} ]]; then
    exec /opt/t3-browser/executable "$@"
fi
# T3's HTML renderer supplies its own SOCKS flag. Chromium accepts only one
# selected proxy; remove conflicting switches and keep local pages direct.
args=()
skip=0
for arg in "$@"; do
    if (( skip )); then skip=0; continue; fi
    case "$arg" in
        --proxy-server|--proxy-bypass-list|--proxy-pac-url) skip=1 ;;
        --proxy-server=*|--proxy-bypass-list=*|--proxy-pac-url=*|--no-proxy-server|--proxy-auto-detect) ;;
        *) args+=("$arg") ;;
    esac
done
exec /opt/t3-browser/executable "${args[@]}" \
    "--proxy-server=${T3_SANDBOX_BROWSER_PROXY}" \
    '--proxy-bypass-list=localhost;127.0.0.1;[::1]'
