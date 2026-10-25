#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
if ! command -v uv >/dev/null 2>&1; then
    echo 'uv is required: https://docs.astral.sh/uv/getting-started/installation/' >&2
    exit 1
fi
exec uv run --project "$ROOT" --locked python "$ROOT/scripts/sandbox.py" "$@"
