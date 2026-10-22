"""Host identity and deterministic profile resource paths."""
from dataclasses import dataclass
from pathlib import Path
import re


def validate_profile_name(name: str) -> str:
    if not isinstance(name, str) or not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]*", name):
        raise ValueError("Profile name must start with a letter or digit and contain only letters, digits, _, . and -")
    return name


@dataclass(frozen=True)
class HostContext:
    home: Path
    uid: int
    gid: int
    user: str


@dataclass(frozen=True)
class ProfileIdentity:
    name: str
    uid: int

    def __post_init__(self):
        validate_profile_name(self.name)

    @property
    def container(self) -> str:
        return f"t3-sandbox-{self.uid}-{self.name}"

    @property
    def proxy(self) -> str:
        return f"{self.container}-proxy"

    @property
    def private_network(self) -> str:
        return f"{self.container}-private"

    @property
    def external_network(self) -> str:
        return f"{self.container}-external"

    @property
    def image(self) -> str:
        return f"localhost/t3-code-sandbox:{self.uid}-{self.name}"

    @property
    def proxy_image(self) -> str:
        return f"localhost/t3-code-proxy:{self.uid}-{self.name}"


@dataclass(frozen=True)
class ProfilePaths:
    profile_file: Path
    home: Path
    runtime: Path
    logs: Path
    lock: Path


def profile_paths(identity: ProfileIdentity, profile_dir: Path, host: HostContext) -> ProfilePaths:
    base = host.home / ".local/share/t3-sandbox" / identity.name
    return ProfilePaths(profile_dir / f"{identity.name}.yaml", base / "home", base / "runtime",
                        base / "logs", base / ".mutation.lock")
