"""Strict YAML profiles and exclusive, persistent default initialization."""
from dataclasses import dataclass
import fcntl
import ipaddress
import math
import os
from pathlib import Path
import re
import socket
import tempfile
from urllib.parse import urlsplit

try:
    import yaml
except ImportError as exc:
    raise ImportError("PyYAML is required: run make python-env and use uv run python scripts/sandbox.py") from exc

from .paths import HostContext, validate_profile_name
from .policy import Allowlist, normalize_allowlist

MAX_PROFILE_BYTES = 1024 * 1024
# T3's own default port, usually taken by a host/Windows T3 UI. WSL bind probes
# cannot observe Windows listeners, so never allocate it to a sandbox.
HOST_T3_PORT = 3773
DEFAULT_PROFILE_PORT = 3774
MAX_MANAGEMENT_PORT = 65535
_TEMPLATE = Path(__file__).resolve().parents[2] / "config/profile.default.yaml"


@dataclass(frozen=True)
class ProjectSettings:
    directory: Path
    create_if_missing: bool


@dataclass(frozen=True)
class ServerSettings:
    bind_address: str
    port: int
    advertised_url: str | None


@dataclass(frozen=True)
class BuildSettings:
    ubuntu_image: str
    node_image: str
    codex_version: str
    claude_version: str
    t3_version: str


@dataclass(frozen=True)
class ResourceSettings:
    memory: str | None
    cpus: int | float | None
    pids_limit: int


@dataclass(frozen=True)
class StateSettings:
    share_host_provider_state: bool
    share_host_t3_state: bool
    t3_directory: Path
    codex_directory: Path
    claude_directory: Path
    share_host_gh_state: bool
    gh_directory: Path
    gitconfig_file: Path


@dataclass(frozen=True)
class RuntimeSettings:
    env_file: Path | None
    automatic_healthcheck: bool
    hostname: str | None


@dataclass(frozen=True)
class NetworkSettings:
    restricted: bool
    allow: Allowlist


@dataclass(frozen=True)
class Profile:
    name: str
    source: Path
    project: ProjectSettings
    server: ServerSettings
    build: BuildSettings
    resources: ResourceSettings
    state: StateSettings
    runtime: RuntimeSettings
    network: NetworkSettings


class _StrictLoader(yaml.SafeLoader):
    def compose_node(self, parent, index):
        event = self.peek_event()
        if isinstance(event, yaml.AliasEvent) or getattr(event, "anchor", None) is not None:
            raise ValueError("YAML aliases and anchors are not supported")
        return super().compose_node(parent, index)

    def construct_mapping(self, node, deep=False):
        result = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if not isinstance(key, str):
                raise ValueError("YAML mapping keys must be strings")
            if key in result:
                raise ValueError(f"Duplicate YAML key: {key}")
            result[key] = self.construct_object(value_node, deep=deep)
        return result


# YAML 1.1's yes/no/on/off coercions are unsuitable for strict settings.
_StrictLoader.yaml_implicit_resolvers = {
    key: [(tag, pattern) for tag, pattern in resolvers if tag != "tag:yaml.org,2002:bool"]
    for key, resolvers in yaml.SafeLoader.yaml_implicit_resolvers.items()
}
_StrictLoader.add_implicit_resolver("tag:yaml.org,2002:bool", re.compile(r"^(?:true|false)$"), list("tf"))


def _read_yaml(data: bytes) -> dict:
    if len(data) > MAX_PROFILE_BYTES:
        raise ValueError("Profile exceeds the 1 MiB limit")
    try:
        value = yaml.load(data.decode("utf-8"), Loader=_StrictLoader)
    except (yaml.YAMLError, UnicodeError, RecursionError) as exc:
        raise ValueError("Invalid or unsupported profile YAML") from exc
    if not isinstance(value, dict):
        raise ValueError("Profile must be a YAML mapping")
    return value


def _mapping(value, allowed, label):
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a mapping")
    unknown = value.keys() - set(allowed)
    if unknown:
        raise ValueError(f"Unknown {label} fields: {', '.join(sorted(unknown))}")
    return value


def _bool(value, label):
    if type(value) is not bool:
        raise ValueError(f"{label} must be an unquoted true or false")
    return value


def _string(value, label):
    if not isinstance(value, str) or not value or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError(f"{label} must be a nonempty string without control characters")
    return value


def _port(value, label):
    if type(value) is not int or not 1 <= value <= 65535:
        raise ValueError(f"{label} must be an integer from 1 to 65535")
    return value


def _path(value, label, host):
    value = _string(value, label)
    if "`" in value or "$" in value.replace("${HOME}", ""):
        raise ValueError(f"{label} supports only ~ and ${{HOME}} expansion")
    value = value.replace("${HOME}", str(host.home))
    if value == "~" or value.startswith("~/"):
        value = str(host.home) + value[1:]
    if "~" in value or not Path(value).is_absolute():
        raise ValueError(f"{label} must be an absolute host path")
    return Path(value).resolve()


def _argument(value, label):
    value = _string(value, label)
    if value.startswith("-") or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_./:@+~-]*", value):
        raise ValueError(f"{label} is not a valid build selector")
    return value


def _list(value, label, validator):
    if not isinstance(value, list):
        raise ValueError(f"{label} must be a list")
    return tuple(validator(item, label) for item in value)


def decode_profile(data: bytes, *, name: str, source: Path, host: HostContext) -> Profile:
    validate_profile_name(name)
    raw = _mapping(_read_yaml(data), ("version", "project", "server", "build", "resources", "state", "runtime", "network"), "profile")
    if type(raw.get("version", 1)) is not int or raw.get("version", 1) != 1:
        raise ValueError("version must be integer 1")
    defaults = _read_yaml(_TEMPLATE.read_bytes())
    defaults["project"]["directory"] = f"~/projects/t3-sandbox/{name}"
    defaults["state"]["share_host_t3_state"] = name == "default"
    sections = {}
    for section in ("project", "server", "build", "resources", "state", "runtime", "network"):
        supplied = _mapping(raw.get(section, {}), defaults[section], section)
        sections[section] = {**defaults[section], **supplied}
    project, server, build, resources, state, runtime, network = (sections[key] for key in sections)
    allow = {**defaults["network"]["allow"], **_mapping(network["allow"], ("domains", "ips", "ports"), "network.allow")}
    bind_address = _string(server["bind_address"], "server.bind_address")
    try:
        ipaddress.ip_address(bind_address)
    except ValueError as exc:
        raise ValueError("server.bind_address must be an IP address") from exc
    advertised = server["advertised_url"]
    if advertised is not None:
        advertised = _string(advertised, "server.advertised_url")
        try:
            url = urlsplit(advertised)
            valid = url.scheme in ("http", "https") and url.hostname and not url.username and not url.password
            url.port
        except ValueError as exc:
            raise ValueError("server.advertised_url must be an HTTP(S) URL") from exc
        if not valid:
            raise ValueError("server.advertised_url must be an HTTP(S) URL without credentials")
    memory = resources["memory"]
    if memory is not None and (not isinstance(memory, str) or not re.fullmatch(r"[1-9][0-9]*(?:[bkmgBKMG])?", memory)):
        raise ValueError("resources.memory must be a positive memory size or null")
    cpus = resources["cpus"]
    if cpus is not None:
        try:
            valid_cpus = type(cpus) in (int, float) and cpus > 0 and math.isfinite(cpus)
        except OverflowError:
            valid_cpus = False
        if not valid_cpus:
            raise ValueError("resources.cpus must be a finite positive number or null")
    pids = resources["pids_limit"]
    if type(pids) is not int or pids < 1:
        raise ValueError("resources.pids_limit must be a positive integer")
    hostname = runtime["hostname"]
    if hostname is not None:
        hostname = _string(hostname, "runtime.hostname")
        if len(hostname) > 253 or any(not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
                                      for label in hostname.split(".")):
            raise ValueError("runtime.hostname must be a valid DNS hostname (up to 253 characters, labels up to 63)")
    return Profile(
        name, source, ProjectSettings(_path(project["directory"], "project.directory", host), _bool(project["create_if_missing"], "project.create_if_missing")),
        ServerSettings(bind_address, _port(server["port"], "server.port"), advertised),
        BuildSettings(**{key: _argument(value, f"build.{key}") for key, value in build.items()}),
        ResourceSettings(memory, cpus, pids),
        StateSettings(_bool(state["share_host_provider_state"], "state.share_host_provider_state"),
                      _bool(state["share_host_t3_state"], "state.share_host_t3_state"),
                      *(_path(state[key], f"state.{key}", host) for key in ("t3_directory", "codex_directory", "claude_directory")),
                      _bool(state["share_host_gh_state"], "state.share_host_gh_state"),
                      *(_path(state[key], f"state.{key}", host) for key in ("gh_directory", "gitconfig_file"))),
        RuntimeSettings(None if runtime["env_file"] is None else _path(runtime["env_file"], "runtime.env_file", host),
                        _bool(runtime["automatic_healthcheck"], "runtime.automatic_healthcheck"), hostname),
        NetworkSettings(_bool(network["restricted"], "network.restricted"), normalize_allowlist(Allowlist(
            _list(allow["domains"], "network.allow.domains", _string),
            _list(allow["ips"], "network.allow.ips", _string),
            _list(allow["ports"], "network.allow.ports", _port)))))


def _read_profile(path: Path) -> bytes:
    with path.open("rb") as stream:
        return stream.read(MAX_PROFILE_BYTES + 1)


def _port_available(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        try:
            probe.bind(("0.0.0.0", port))
        except OSError:
            return False
    return True


def _allocate_port(profile_dir: Path) -> int:
    # Reserve the host T3 port and the default profile's port, even if a named
    # profile is initialized before default.
    used = {HOST_T3_PORT, DEFAULT_PROFILE_PORT}
    for path in profile_dir.glob("*.yaml"):
        # An invalid sibling profile must not block initializing another one.
        # Still reserve its port when that single field is readable.
        try:
            server = _read_yaml(_read_profile(path)).get("server")
        except (OSError, ValueError):
            continue
        port = server.get("port") if isinstance(server, dict) else None
        if type(port) is int:
            used.add(port)
    for port in range(DEFAULT_PROFILE_PORT + 1, MAX_MANAGEMENT_PORT + 1):
        if port not in used and _port_available(port):
            return port
    raise ValueError(f"No unused management port available from {DEFAULT_PROFILE_PORT + 1} to {MAX_MANAGEMENT_PORT}")


def initialize_profile(name: str, profile_dir: Path, host: HostContext) -> Path:
    validate_profile_name(name)
    target = profile_dir / f"{name}.yaml"
    profile_dir.mkdir(parents=True, exist_ok=True)
    # Allocation and publication share one short directory-wide lock. Runtime
    # mutations use a separate per-profile lock outside the removable snapshot.
    with (profile_dir / ".allocation.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if target.exists() or target.is_symlink():
            return target
        content = _TEMPLATE.read_text()
        if name != "default":
            content = content.replace("~/projects/t3-sandbox/default", f"~/projects/t3-sandbox/{name}")
            content = content.replace("share_host_t3_state: true", "share_host_t3_state: false")
            content = content.replace(f"  port: {DEFAULT_PROFILE_PORT}", f"  port: {_allocate_port(profile_dir)}")
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(dir=profile_dir, prefix=".profile-", delete=False) as stream:
                temporary = Path(stream.name)
                stream.write(content.encode("utf-8"))
                stream.flush()
                os.fsync(stream.fileno())
            try:
                # A hard link publishes the complete file only if target is
                # absent; rename/replace could clobber an intervening user edit.
                os.link(temporary, target)
            except FileExistsError:
                pass
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
    return target


def load_profile(name: str, profile_dir: Path, host: HostContext, *, initialize_default=True) -> Profile:
    validate_profile_name(name)
    source = profile_dir / f"{name}.yaml"
    if not source.exists() and name == "default" and initialize_default:
        initialize_profile(name, profile_dir, host)
    try:
        data = _read_profile(source)
    except FileNotFoundError as exc:
        raise ValueError(f"Profile {name!r} does not exist; run make init PROFILE={name}") from exc
    return decode_profile(data, name=name, source=source, host=host)
