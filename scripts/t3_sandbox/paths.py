"""Host identity and deterministic profile resource paths."""
from dataclasses import dataclass
from contextlib import contextmanager
import fcntl
import os
from pathlib import Path
import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .podman import Podman
    from .profiles import Profile


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


def _overlaps(left: Path, right: Path) -> bool:
    return left.is_relative_to(right) or right.is_relative_to(left)


def _mounts(profile: 'Profile', paths: ProfilePaths, host: HostContext) -> list[tuple[Path, str]]:
    home = f'/home/{host.user}'
    mounts = [(paths.home, home), (profile.project.directory, '/workspace')]
    if profile.state.share_host_provider_state:
        mounts.extend([(profile.state.codex_directory, f'{home}/.codex'),
                       (profile.state.claude_directory, f'{home}/.claude')])
    if profile.state.share_host_t3_state:
        mounts.append((profile.state.t3_directory, f'{home}/.t3'))
    return mounts


def validate_storage(profile: 'Profile', paths: ProfilePaths, host: HostContext) -> None:
    """Reject writable binds that expose management files, before creating anything.

    Resolve both ends: a runtime directory may itself point into a writable tree.
    Existing symlinks within trees are checked without following them recursively.
    This is a preflight boundary, not protection against concurrent host edits.
    """
    protected = [paths.profile_file.parent, paths.profile_file, profile.source,
                 paths.runtime, paths.logs, paths.lock]
    data_root = host.home / '.local/share/t3-sandbox'
    if data_root.is_dir():
        for sibling in data_root.iterdir():
            if sibling.is_dir():
                protected.extend(sibling / leaf for leaf in ('runtime', 'logs', '.mutation.lock'))
    protected = [path.resolve() for path in protected]
    sources = [source for source, _ in _mounts(profile, paths, host)]
    # Even shared modes retain private state in the persistent home. Validate
    # these targets too so creating them cannot follow a link into runtime/logs.
    sources.extend(paths.home / leaf for leaf in ('.codex', '.claude', '.t3'))

    def sensitive(real):
        targets = protected
        # Protect not-yet-created sibling metadata too. A bind of other/home
        # is safe; a bind of other/runtime or the whole other directory is not.
        if real.is_relative_to(data_root.resolve()):
            parts = real.relative_to(data_root.resolve()).parts
            if parts:
                sibling = data_root / parts[0]
                targets = protected + [(sibling / leaf).resolve() for leaf in ('runtime', 'logs', '.mutation.lock')]
        return any(_overlaps(real, target) for target in targets)

    def check(path):
        real = path.resolve()
        if real in (Path('/'), host.home.resolve()) or sensitive(real):
            raise ValueError(f'Writable storage overlaps protected host paths: {path}')
        if path.exists() and not path.is_dir():
            raise ValueError(f'Storage source is not a directory: {path}')

    for source in sources:
        check(source)
        if source.is_dir():
            def fail(error):
                raise error
            for root, directories, files in os.walk(source, followlinks=False, onerror=fail):
                for name in directories + files:
                    child = Path(root) / name
                    if child.is_symlink():
                        # Symlinks can refer to files as well as directories.
                        real = child.resolve()
                        if sensitive(real):
                            raise ValueError(f'Writable storage symlink exposes protected host paths: {child}')
    if not profile.project.directory.exists() and not profile.project.create_if_missing:
        raise ValueError(f'Project does not exist and project.create_if_missing is false: {profile.project.directory}')


def prepare_home(profile: 'Profile', paths: ProfilePaths, host: HostContext) -> list[tuple[Path, str]]:
    """Prepare ordinary bind directories without copying or changing existing state."""
    validate_storage(profile, paths, host)
    mounts = _mounts(profile, paths, host)
    directories = [source for source, _ in mounts]
    directories.extend(paths.home / leaf for leaf in ('.codex', '.claude', '.t3'))
    # Podman creates missing tmpfs mount ancestors as container root. Prepare
    # this parent as the host user before mounting the browser cache beneath it.
    t3_state = profile.state.t3_directory if profile.state.share_host_t3_state else paths.home / '.t3'
    if (t3_state / 'tools').is_symlink():
        raise ValueError('Browser tmpfs parent must not be a symlink')
    directories.append(t3_state / 'tools')
    for directory in directories:
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    # Return canonical sources, including any safe pre-existing state symlinks.
    return [(source.resolve(), destination) for source, destination in mounts]


@contextmanager
def mutation_lock(paths: ProfilePaths):
    """Serialize a profile's mutations without locking other profiles or runtime."""
    paths.lock.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    # Do not follow a writable-home symlink to an unrelated host file.
    descriptor = os.open(paths.lock, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)


def validate_t3_state_sharing(profile: 'Profile', paths: ProfilePaths, host: HostContext, podman: 'Podman') -> None:
    """Check active managed containers' actual state sources, without reading YAML.

    Call under the mutation lock before starting T3. T3's own process lock remains
    authoritative for concurrent host servers and cross-profile startup races.
    """
    from .podman import assert_owned, resource_labels
    identity = ProfileIdentity(profile.name, host.uid)
    source = (profile.state.t3_directory if profile.state.share_host_t3_state else paths.home / '.t3').resolve()
    for resource in podman.managed_containers():
        labels = resource_labels(resource)
        if labels.get('io.t3-sandbox.uid') != str(host.uid) or labels.get('io.t3-sandbox.role') != 't3':
            continue
        other = ProfileIdentity(labels.get('io.t3-sandbox.profile', ''), host.uid)
        assert_owned(resource, other)
        if other == identity or not resource.get('State', {}).get('Running', False):
            continue
        # Longest destination wins when .t3 is mounted over the home bind.
        state_destination = Path(f'/home/{host.user}/.t3')
        candidates = []
        for mount in resource.get('Mounts', []):
            destination = Path(mount['Destination'])
            if mount.get('Type') == 'bind' and state_destination.is_relative_to(destination):
                actual_source = Path(mount['Source']) / state_destination.relative_to(destination)
                candidates.append((len(destination.parts), actual_source.resolve()))
        if candidates and _overlaps(source, max(candidates, key=lambda item: item[0])[1]):
            raise ValueError(f'T3 state is already in use by profile {other.name}; stop its T3 server or use private state')
