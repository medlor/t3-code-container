"""Fail-closed rootless Netavark topology and checks outside the workload."""
import ipaddress
import json
import re
import subprocess
import uuid

from .paths import HostContext, ProfileIdentity, ProfilePaths
from .podman import LABEL_PREFIX, Podman
from .policy import GatewayConfig, encode_snapshot, Allowlist
from .profiles import Profile, ServerSettings


class UnsupportedRuntime(ValueError):
    """The host cannot provide the required isolation controls."""


class IsolationError(ValueError):
    """An inspected resource violates a required security invariant."""


def labels(identity, role):
    return [part for key, value in dict(managed='true', uid=str(identity.uid),
            profile=identity.name, role=role).items() for part in ('--label', LABEL_PREFIX + key + '=' + value)]


def _json(result):
    try:
        return json.loads(result.stdout)
    except (ValueError, TypeError) as exc:
        raise IsolationError('Invalid runtime inspection JSON') from exc


def runtime_preflight(podman):
    info = _json(podman.run(['info', '--format', 'json']))
    host = info.get('host', {})
    if host.get('security', {}).get('rootless') is not True or host.get('networkBackend') != 'netavark' or host.get('serviceIsRemote') is not False:
        raise UnsupportedRuntime('Unsupported runtime: restricted mode requires local rootless Podman with Netavark')


def _resolvers(podman):
    result = []
    for line in podman.run(['unshare', 'cat', '/etc/resolv.conf']).stdout.splitlines():
        fields = line.split('#', 1)[0].split()
        if fields and fields[0] == 'nameserver':
            if len(fields) != 2:
                raise UnsupportedRuntime('Unsupported resolver settings')
            try:
                address = ipaddress.ip_address(fields[1])
            except ValueError as exc:
                raise UnsupportedRuntime('Unsupported resolver settings') from exc
            if address.version != 4:
                raise UnsupportedRuntime('Unsupported IPv6 resolver: select only IPv4 DNS resolvers')
            result.append(str(address))
    if not result:
        raise UnsupportedRuntime('No IPv4 DNS resolvers configured')
    return tuple(dict.fromkeys(result))


def _host_ips(podman, owned_interfaces):
    result = set()
    for prefix in (['unshare'], ['unshare', '--rootless-netns']):
        for link in _json(podman.run([*prefix, 'ip', '-j', 'addr'])):
            # Own bridge subnets are already protected. Their link-local IPv6
            # addresses disappear during hardening and must not affect reuse.
            if '--rootless-netns' in prefix and link.get('ifname') in owned_interfaces:
                continue
            for address in link.get('addr_info', []):
                parsed = ipaddress.ip_address(address['local'])
                # Dynamic veth link-local addresses are covered by the fixed
                # protected ranges, independent of host discovery.
                if not parsed.is_link_local:
                    result.add(str(parsed))
    return tuple(sorted(result))


def _network(podman, identity, name, internal):
    resource = podman.inspect_owned('network', name, identity)
    if resource is None:
        raise IsolationError('Required network is absent')
    if (resource.get('driver') != 'bridge' or resource.get('internal') is not internal or
            resource.get('dns_enabled') is not False or resource.get('ipv6_enabled') is not False):
        raise IsolationError('Network configuration changed; run make recreate')
    try:
        subnets = tuple(ipaddress.ip_network(item['subnet']) for item in resource['subnets'])
    except (KeyError, TypeError, ValueError) as exc:
        raise IsolationError('Invalid allocated network subnets') from exc
    if len(subnets) != 1 or any(item.version != 4 for item in subnets):
        raise UnsupportedRuntime('Unsupported network subnets: only one IPv4 subnet per network is supported; IPv6 egress is unsupported')
    if internal and any(item.get('gateway') for item in resource['subnets']):
        raise IsolationError('Private network must not have an IPv4 gateway')
    return resource, subnets[0]


def ensure_networks(podman: Podman, identity: ProfileIdentity, server: ServerSettings, *, create=True) -> GatewayConfig:
    """Called under the short host allocation lock; undo only our allocations."""
    runtime_preflight(podman)
    resolvers = _resolvers(podman)
    names = (identity.private_network, identity.external_network)
    existing = {name: podman.inspect_owned('network', name, identity) for name in names}
    if not create and any(value is None for value in existing.values()):
        raise IsolationError('Required network is absent; run make recreate')
    created = []
    try:
        for name, internal in zip(names, (True, False)):
            if existing[name] is None:
                podman.run(['network', 'create', '--disable-dns', *(['--internal'] if internal else []),
                            *labels(identity, 'private' if internal else 'external'), name])
                created.append(name)
        private, subnet = _network(podman, identity, names[0], True)
        external, external_subnet = _network(podman, identity, names[1], False)
        # The first host is reserved by convention even on an unaddressed bridge.
        if subnet.num_addresses < 8:
            raise IsolationError('Private subnet does not have enough deterministic endpoint addresses')
        gateway = GatewayConfig(str(subnet.network_address + 2), str(subnet.network_address + 3),
            str(subnet), (str(external_subnet),), _host_ips(podman, {private.get('network_interface'), external.get('network_interface')}),
            resolvers, server.bind_address, server.port)
        # Validate all shared policy contracts before any container can start.
        encode_snapshot(Allowlist((), (), ()), gateway)
        _members(podman, identity)
        return gateway
    except BaseException:
        for name in reversed(created):
            podman.run(['network', 'rm', name])
        raise


def _bridge(podman, identity):
    resource, _ = _network(podman, identity, identity.private_network, True)
    interface = resource.get('network_interface', '')
    if not re.fullmatch(r'[a-zA-Z0-9_-]{1,15}', interface):
        raise UnsupportedRuntime('Unsupported private bridge interface name')
    return interface


def _addresses(podman, interface):
    result = _json(podman.run(['unshare', '--rootless-netns', 'ip', '-j', 'addr', 'show', 'dev', interface]))
    if len(result) != 1 or not isinstance(result[0].get('addr_info'), list):
        raise IsolationError('Cannot inspect private bridge addresses')
    return result[0]['addr_info']


def harden_bridge(podman: Podman, identity: ProfileIdentity) -> None:
    interface = _bridge(podman, identity)
    try:
        if any(item.get('family') == 'inet' for item in _addresses(podman, interface)):
            raise IsolationError('IPv4-addressed private bridge is forbidden; refusing to remove its address')
        setting = f'net.ipv6.conf.{interface}.disable_ipv6'
        podman.run(['unshare', '--rootless-netns', 'sysctl', '-w', setting + '=1'])
        if podman.run(['unshare', '--rootless-netns', 'sysctl', '-n', setting]).stdout.strip() != '1':
            raise UnsupportedRuntime('Unsupported host: private bridge IPv6 hardening did not persist')
        if _addresses(podman, interface):
            raise IsolationError('Private bridge remains addressed after IPv6 hardening')
    except subprocess.SubprocessError as exc:
        raise UnsupportedRuntime('Unsupported host/runtime: cannot enforce private bridge IPv6 hardening') from exc


def _members(podman, identity):
    # Inspect every container, including unowned/stopped members. Label-filtered
    # discovery cannot prove that a private network has no unexpected members.
    for resource in podman.inspect_containers():
        networks = resource.get('NetworkSettings', {}).get('Networks', {})
        name = resource.get('Name', '').lstrip('/')
        if identity.private_network in networks and name not in (identity.container, identity.proxy):
            raise IsolationError('Unexpected private network member; refusing reuse')
        if identity.external_network in networks and name != identity.proxy:
            raise IsolationError('Unexpected external network member; refusing reuse')


# Read the live kernel route tables, using Python available in both images.
# Include route flags: the IPv6 unreachable ::/0 sentinel is not a usable route.
ROUTES = '''import json, socket, fcntl, struct
addresses={}
for _,name in socket.if_nameindex():
 try:
  with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:
   address=socket.inet_ntoa(fcntl.ioctl(s.fileno(),0x8915,struct.pack('256s',name.encode()))[20:24])
   addresses[address]=name
 except OSError: pass
v4=[]
for line in open('/proc/net/route').read().splitlines()[1:]:
 f=line.split()
 if int(f[3],16)&1: v4.append({'destination':f[1],'interface':f[0],'prefix':f[7]})
v6=[]
for line in open('/proc/net/ipv6_route'):
 f=line.split()
 if int(f[8],16)&1 and not int(f[8],16)&0x200: v6.append({'destination':f[0],'prefix':f[1],'interface':f[9]})
print(json.dumps({'ipv4':v4,'ipv6':v6,'interfaces':addresses}))'''


def check_routes(podman, name, *, external_ip=None):
    # Workload PATH, cwd and Python environment are writable/untrusted.
    # Use image-owned Python and exclude project/user imports and startup hooks.
    routes = _json(podman.run(['exec', name, '/usr/bin/python3', '-I', '-S', '-c', ROUTES]))
    try:
        defaults4 = [item for item in routes['ipv4'] if item['destination'] == '00000000']
        defaults6 = [item for item in routes['ipv6'] if item['destination'] == '0' * 32 and item.get('prefix') == '00']
    except (KeyError, TypeError) as exc:
        raise IsolationError('Cannot verify actual container routes') from exc
    if defaults6 or (external_ip is None and defaults4):
        raise IsolationError('Forbidden IPv4/IPv6 default route on private-only container')
    if external_ip is not None and (len(defaults4) != 1 or not routes.get('interfaces', {}).get(external_ip) or
            defaults4[0]['interface'] != routes['interfaces'][external_ip]):
        raise IsolationError('Gateway default route must use only its external interface')


GATEWAY_STATE = '''import json
from pathlib import Path
forwarding=[int(Path(p).read_text()) for p in ('/proc/sys/net/ipv4/ip_forward','/proc/sys/net/ipv6/conf/all/forwarding','/proc/sys/net/ipv6/conf/default/forwarding')]
s=dict(line.split(':',1) for line in Path('/proc/1/status').read_text().splitlines() if ':' in line)
print(json.dumps({'forwarding':forwarding,'capabilities':[int(s[k].strip(),16) for k in ('CapInh','CapPrm','CapEff','CapBnd','CapAmb')],'nnp':int(s['NoNewPrivs'])}))'''


def assert_isolated(podman: Podman, identity: ProfileIdentity, gateway: GatewayConfig) -> None:
    _members(podman, identity)
    interface = _bridge(podman, identity)
    if _addresses(podman, interface) or podman.run(['unshare', '--rootless-netns', 'sysctl', '-n',
            f'net.ipv6.conf.{interface}.disable_ipv6']).stdout.strip() != '1':
        raise IsolationError('Private bridge isolation changed')
    proxy = podman.inspect_owned('container', identity.proxy, identity)
    if not proxy or not proxy.get('State', {}).get('Running'):
        raise IsolationError('Gateway is not running')
    networks = proxy.get('NetworkSettings', {}).get('Networks', {})
    if set(networks) != {identity.private_network, identity.external_network} or networks[identity.private_network].get('IPAddress') != gateway.private_ip:
        raise IsolationError('Gateway actual network memberships or stable address changed; run make recreate')
    external = networks[identity.external_network].get('IPAddress')
    if not external:
        raise IsolationError('Gateway external IPv4 address is unavailable')
    check_routes(podman, identity.proxy, external_ip=external)
    if _json(podman.run(['exec', identity.proxy, 'python3', '-c', GATEWAY_STATE])) != {
            'forwarding': [0, 0, 0], 'capabilities': [0, 0, 0, 0, 0], 'nnp': 1}:
        raise IsolationError('Gateway forwarding, capability drop or no-new-privileges invariant failed')
    t3 = podman.inspect_owned('container', identity.container, identity)
    if t3:
        networks = t3.get('NetworkSettings', {}).get('Networks', {})
        if set(networks) != {identity.private_network}:
            raise IsolationError('T3 actual network memberships changed; run make recreate')
        if t3.get('State', {}).get('Running'):
            if networks[identity.private_network].get('IPAddress') != gateway.t3_ip:
                raise IsolationError('T3 actual stable address changed; run make recreate')
            check_routes(podman, identity.container)


def route_probe(podman, identity, image):
    name = identity.container + '-probe-' + uuid.uuid4().hex[:12]
    # Unique name, operation-local ID and exact labels; never remove by a filter.
    try:
        podman.run(['run', '--detach', '--pull=never', '--name', name, *labels(identity, 'proxy'),
            '--userns=keep-id:uid=2003,gid=2003', '--user=2003:2003', '--cap-drop=all',
            '--security-opt=no-new-privileges', '--pid=private', '--ipc=private', '--pids-limit=32',
            '--network=' + identity.private_network, '--dns=none', '--no-hosts',
            '--entrypoint=python3', image, '-c', 'import time; time.sleep(60)'])
        check_routes(podman, name)
    finally:
        resource = podman.inspect('container', name)
        if resource is not None:
            from .podman import assert_owned
            assert_owned(resource, identity)
            podman.run(['rm', '--force', '--time=1', name])


def start_restricted(profile: Profile, paths: ProfilePaths, *, podman: Podman, host: HostContext) -> None:
    # Caller holds the profile and shared-state locks. The launcher owns
    # lifecycle policy; networking helpers never own unrelated resources.
    from .launcher import Launcher
    launcher = Launcher(podman, host, paths.profile_file.parent)
    launcher._validate_start(profile, paths)
    launcher._start_restricted(profile, paths, ProfileIdentity(profile.name, host.uid))
