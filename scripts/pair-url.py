#!/usr/bin/env python3
"""Translate T3's internal pairing URL to the host's published endpoint."""
import sys
from urllib.parse import parse_qs, urlsplit, urlunsplit


def translate(output: str, endpoint: str) -> str:
    for line in output.splitlines():
        if line.startswith("Pairing URL: "):
            original = urlsplit(line.removeprefix("Pairing URL: ").strip())
            target = urlsplit(endpoint)
            if not parse_qs(original.fragment).get("token"):
                raise ValueError("T3 pairing URL has no token fragment; inspect `make exec CMD='t3 pair'`.")
            return urlunsplit((target.scheme, target.netloc, original.path, original.query, original.fragment))
    raise ValueError("T3 returned no pairing URL. Check `make logs` and `make exec CMD='t3 pair'`.")


if __name__ == "__main__":
    try:
        print("Pairing URL: " + translate(sys.stdin.read(), sys.argv[1]))
        print("Paste this one-time URL into T3 Settings → Connections → Add environment.")
    except ValueError as error:
        sys.exit(str(error))
