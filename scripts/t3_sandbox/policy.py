"""Strict data-only policy compiler shared by host orchestration and gateway.

Squid restricts names; nft independently restricts actual destination addresses.
The policy digest identifies the allowlist, not topology or daemon identities.
Operational external subnets and resolvers are IPv4-only in this version. IPv6
allowlist parsing, host-address protection, and mapped-address denial remain
enabled; IPv6 egress requires a separately reviewed neighbor-discovery policy.
No DNS lookups, subprocesses, file writes, or firewall operations occur here.
"""
from dataclasses import asdict, dataclass, fields
import hashlib
import ipaddress
import json
import re

PROXY_PORT = 3128
T3_PORT = 3773
MAX_SNAPSHOT_BYTES = 1024 * 1024


@dataclass(frozen=True)
class Allowlist:
    domains: tuple[str, ...]
    ips: tuple[str, ...]
    ports: tuple[int, ...]


@dataclass(frozen=True)
class GatewayConfig:
    private_ip: str
    t3_ip: str
    private_cidr: str
    external_cidrs: tuple[str, ...]
    host_ips: tuple[str, ...]
    dns_servers: tuple[str, ...]
    bind_address: str
    host_port: int


@dataclass(frozen=True)
class CompiledPolicy:
    digest: str
    squid_conf: str
    nft_conf: str


# Explicit conservative special-use ranges, independent of Python's evolving
# is_global/is_private classifications. IPv6 allows only global unicast 2000::/3
# minus special-use space; transition/mapped forms never bypass IPv4 protection.
_PROTECTED_V4 = tuple(ipaddress.ip_network(value) for value in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
    "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16",
    "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4"))
_PROTECTED_V6 = tuple(ipaddress.ip_network(value) for value in (
    "::/3", "2001::/23", "2001:db8::/32", "2002::/16", "3fff::/20", "4000::/2", "8000::/1"))
_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", re.ASCII)


def _text(value, label):
    if not isinstance(value, str) or not value or not value.isascii() or any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError(f"{label} must be nonempty ASCII without whitespace or control characters")
    return value


def _address(value):
    value = _text(value, "IP address")
    if "%" in value:
        raise ValueError("Scoped IP addresses are not supported")
    try:
        return ipaddress.ip_address(value)
    except ValueError as exc:
        raise ValueError("Expected an IP address") from exc


def _network(value, *, strict):
    value = _text(value, "IP or CIDR")
    if "%" in value:
        raise ValueError("Scoped IP addresses are not supported")
    try:
        return ipaddress.ip_network(value, strict=strict)
    except ValueError as exc:
        raise ValueError("Expected an IP address or CIDR") from exc


def _port(value):
    if type(value) is not int or not 1 <= value <= 65535:
        raise ValueError("Port must be an integer from 1 to 65535")
    return value


def _tuple(value, label):
    if type(value) is not tuple:
        raise ValueError(f"{label} must be a tuple")
    return value


def _domain(value):
    value = _text(value, "Domain").lower()
    if value.endswith("."):
        value = value[:-1]
    host = value[2:] if value.startswith("*.") else value
    labels = host.split(".")
    # Numeric names include ambiguous legacy IP spellings; keep them out of DNS
    # grants. Explicit ASCII A-labels are accepted without implicit IDNA mapping.
    if len(host) > 253 or len(labels) < 2 or labels[-1].isdigit() or any(not _LABEL.fullmatch(label) for label in labels):
        raise ValueError("Expected an ASCII DNS name, optionally prefixed with *.")
    return value


def normalize_allowlist(value: Allowlist) -> Allowlist:
    """Validate and deduplicate entries, retaining first-occurrence user order."""
    if type(value) is not Allowlist:
        raise ValueError("Expected an Allowlist")
    return Allowlist(
        tuple(dict.fromkeys(_domain(item) for item in _tuple(value.domains, "domains"))),
        tuple(dict.fromkeys(str(_network(item, strict=False)) for item in _tuple(value.ips, "ips"))),
        tuple(dict.fromkeys(_port(item) for item in _tuple(value.ports, "ports"))))


def _gateway(value):
    if type(value) is not GatewayConfig:
        raise ValueError("Expected a GatewayConfig")
    private = _network(value.private_cidr, strict=True)
    proxy, t3 = _address(value.private_ip), _address(value.t3_ip)
    if private.version != 4 or proxy.version != 4 or t3.version != 4 or proxy == t3:
        raise ValueError("Private endpoints must be distinct IPv4 addresses")
    for endpoint in (proxy, t3):
        if endpoint not in private or endpoint in (private.network_address, private.broadcast_address) or endpoint.is_multicast or endpoint.is_unspecified or endpoint.is_loopback or endpoint.is_link_local:
            raise ValueError("Private endpoints must be usable addresses in the private subnet")
    external = tuple(_network(item, strict=True) for item in _tuple(value.external_cidrs, "external_cidrs"))
    if any(item.version != 4 for item in external):
        raise ValueError("Operational external_cidrs must contain only IPv4 subnets; IPv6 egress is unsupported")
    if not external or any(item.overlaps(private) for item in external):
        raise ValueError("External subnets must be present and separate from the private subnet")
    hosts = tuple(_address(item) for item in _tuple(value.host_ips, "host_ips"))
    dns = tuple(_address(item) for item in _tuple(value.dns_servers, "dns_servers"))
    if any(item.version != 4 for item in dns):
        raise ValueError("Operational dns_servers must contain only IPv4 addresses; IPv6 DNS is unsupported")
    if not dns or any(item.is_unspecified or item.is_multicast for item in dns):
        raise ValueError("DNS resolvers must be explicit unicast IP addresses")
    return GatewayConfig(str(proxy), str(t3), str(private), tuple(sorted(set(map(str, external)))),
        tuple(sorted(set(map(str, hosts)))), tuple(sorted(set(map(str, dns)))), str(_address(value.bind_address)), _port(value.host_port))


def _protected(gateway):
    networks = [*_PROTECTED_V4, *_PROTECTED_V6, _network(gateway.private_cidr, strict=True)]
    networks.extend(_network(item, strict=True) for item in gateway.external_cidrs)
    networks.extend(ipaddress.ip_network(_address(item)) for item in gateway.host_ips)
    return tuple(tuple(ipaddress.collapse_addresses(item for item in networks if item.version == version)) for version in (4, 6))


def is_protected_address(address: str, gateway: GatewayConfig) -> bool:
    """Return whether a literal is forbidden, even when expressly allowlisted."""
    parsed = _address(address)
    v4, v6 = _protected(_gateway(gateway))
    return any(parsed in network for network in (v4 if parsed.version == 4 else v6))


def _canonical_allow(value):
    return {key: sorted(items) for key, items in asdict(value).items()}


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def _digest(value):
    return hashlib.sha256(_json(_canonical_allow(value))).hexdigest()


def _squid(allow, gateway, protected):
    lines = [
        f"http_port {gateway.private_ip}:{PROXY_PORT}",
        "visible_hostname t3-egress", "cache deny all", "cache_store_log none",
        "logformat t3decision %ts.%03tu %Ss %err_code %{t3_reason}note %#.253>rd %>rP %#.32rm",
        "access_log stdio:/run/t3-proxy/decisions.fifo logformat=t3decision buffer-size=0KB on-error=die",
        "buffered_logs off", "logfile_rotate 0",
        "pid_filename /run/t3-proxy/squid/squid.pid", "cache_log /dev/null",
        "coredump_dir /run/t3-proxy/squid", "netdb_filename none", "pinger_enable off",
        "icp_port 0", "htcp_port 0", "forwarded_for delete", "follow_x_forwarded_for deny all",
        "dns_nameservers " + " ".join(gateway.dns_servers),
        f"acl t3_client src {gateway.t3_ip}/32", "acl CONNECT method CONNECT",
        "acl tag_protected annotate_transaction t3_reason=protected_address",
        "acl tag_port annotate_transaction t3_reason=forbidden_port",
        "acl tag_unlisted annotate_transaction t3_reason=unlisted_destination"]
    for network in (*protected[0], *protected[1]):
        lines.append(f"acl protected_dst dst {network}")
    if allow.ports:
        lines.append("acl allowed_ports port " + " ".join(map(str, sorted(allow.ports))))
    for domain in sorted(allow.domains):
        host = domain[2:] if domain.startswith("*.") else domain
        escaped = host.replace(".", r"\.")
        prefix = r"([a-z0-9-]+\.)+" if domain.startswith("*.") else ""
        lines.append(f"acl allowed_domains dstdom_regex -n -i ^{prefix}{escaped}$")
    for network in sorted(allow.ips):
        lines.append(f"acl allowed_ips dst {network}")
    # Every destination guard precedes every grant. -n prevents PTR lookups from
    # converting an IP-literal URL into an allowed domain name.
    lines += ["http_access deny protected_dst tag_protected"]
    if allow.ports:
        lines += ["http_access deny !allowed_ports tag_port", "http_access deny CONNECT !allowed_ports tag_port"]
        if allow.domains:
            lines.append("http_access allow t3_client allowed_domains")
        if allow.ips:
            lines.append("http_access allow t3_client allowed_ips")
    lines.append("http_access deny all tag_unlisted")
    return "\n".join(lines) + "\n"


def _nft(allow, gateway, protected, proxy_uid, relay_uid):
    lines = ["table inet t3_egress {"]
    for version, networks in zip((4, 6), protected):
        lines += [f"    set protected_v{version} {{", f"        type ipv{version}_addr; flags interval;",
                  "        elements = { " + ", ".join(map(str, networks)) + " }", "    }"]
    lines += ["    chain input {", "        type filter hook input priority 0; policy drop;",
              "        ct state invalid drop", "        ct state established,related accept",
              f"        ip saddr {gateway.t3_ip} ip daddr {gateway.private_ip} tcp dport {PROXY_PORT} accept",
              f"        ip saddr {gateway.private_cidr} drop",
              # The host's publication binds host_port/bind_address; gateway's
              # fixed relay listens on 3773. Never expose it to the T3 subnet.
              f"        tcp dport {T3_PORT} accept", "    }",
              "    chain forward {", "        type filter hook forward priority 0; policy drop;", "    }",
              "    chain output {", "        type filter hook output priority 0; policy drop;",
              "        ct state invalid drop", "        ct direction reply ct state established accept"]
    # Squid's internal resolver sends UDP. Do not allow TCP DNS: a protected
    # resolver TCP/53 exception could also carry client CONNECT requests.
    for resolver in gateway.dns_servers:
        family = "ip" if _address(resolver).version == 4 else "ip6"
        lines.append(f"        meta skuid {proxy_uid} {family} daddr {resolver} udp dport 53 accept")
    lines += [f"        meta skuid {relay_uid} ip daddr {gateway.t3_ip} tcp dport {T3_PORT} accept",
              "        ip daddr @protected_v4 drop", "        ip6 daddr @protected_v6 drop"]
    if allow.ports and (allow.domains or allow.ips):
        ports = "{ " + ", ".join(map(str, sorted(allow.ports))) + " }"
        lines.append(f"        meta skuid {proxy_uid} tcp dport {ports} accept")
    lines += ["    }", "}"]
    return "\n".join(lines) + "\n"


def compile_policy(value: Allowlist, gateway: GatewayConfig, *, proxy_uid: int, relay_uid: int) -> CompiledPolicy:
    """Generate standalone policy for IPv4 external topology and DNS resolvers.

    IPv6 operational topology is rejected until neighbor discovery has a reviewed
    policy; IPv6 allowlist syntax and protected-destination guards are retained.
    """
    allow, gateway = normalize_allowlist(value), _gateway(gateway)
    if any(type(uid) is not int or not 1 <= uid < 2**32 - 1 for uid in (proxy_uid, relay_uid)) or proxy_uid == relay_uid:
        raise ValueError("Proxy and relay UIDs must be distinct nonroot numeric identities")
    protected = _protected(gateway)
    return CompiledPolicy(_digest(allow), _squid(allow, gateway, protected), _nft(allow, gateway, protected, proxy_uid, relay_uid))


def encode_snapshot(value: Allowlist, gateway: GatewayConfig) -> bytes:
    """Encode a canonical bounded snapshot, containing no profile or secrets."""
    allow, gateway = normalize_allowlist(value), _gateway(gateway)
    data = _json({"version": 1, "allow": _canonical_allow(allow), "gateway": asdict(gateway), "digest": _digest(allow)}) + b"\n"
    if len(data) > MAX_SNAPSHOT_BYTES:
        raise ValueError("Policy snapshot exceeds 1 MiB")
    return data


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate snapshot key")
        result[key] = value
    return result


def _schema(value, keys):
    if type(value) is not dict or set(value) != set(keys):
        raise ValueError("Invalid snapshot fields")
    return value


def _array(value):
    if type(value) is not list:
        raise ValueError("Snapshot collection must be an array")
    return tuple(value)


def decode_snapshot(data: bytes) -> tuple[Allowlist, GatewayConfig]:
    """Revalidate all untrusted snapshot fields and verify the allowlist digest.

    The digest detects mismatched policy, not authenticity. Host mount ownership
    and gateway-only read-only snapshot mounts provide the trust boundary.
    """
    if type(data) is not bytes or len(data) > MAX_SNAPSHOT_BYTES:
        raise ValueError("Expected a snapshot of at most 1 MiB")
    try:
        raw = json.loads(data.decode("utf-8"), object_pairs_hook=_object,
                         parse_constant=lambda _: (_ for _ in ()).throw(ValueError("Invalid JSON constant")))
    except (UnicodeError, RecursionError, json.JSONDecodeError) as exc:
        raise ValueError("Invalid policy snapshot JSON") from exc
    _schema(raw, ("version", "allow", "gateway", "digest"))
    if type(raw["version"]) is not int or raw["version"] != 1:
        raise ValueError("Snapshot version must be integer 1")
    allow_raw = _schema(raw["allow"], ("domains", "ips", "ports"))
    allow = normalize_allowlist(Allowlist(**{key: _array(value) for key, value in allow_raw.items()}))
    gateway_raw = _schema(raw["gateway"], (field.name for field in fields(GatewayConfig)))
    gateway = _gateway(GatewayConfig(**{key: _array(value) if key in ("external_cidrs", "host_ips", "dns_servers") else value
                                       for key, value in gateway_raw.items()}))
    if type(raw["digest"]) is not str or raw["digest"] != _digest(allow):
        raise ValueError("Snapshot policy digest mismatch")
    return allow, gateway
