"""Immutable network allowlist shared with the policy compiler."""
from dataclasses import dataclass


@dataclass(frozen=True)
class Allowlist:
    domains: tuple[str, ...]
    ips: tuple[str, ...]
    ports: tuple[int, ...]
