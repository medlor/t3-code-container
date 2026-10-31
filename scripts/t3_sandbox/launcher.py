"""Profile lifecycle policy; all external commands use argument arrays."""
from dataclasses import asdict, replace
from contextlib import ExitStack, closing
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import subprocess
import sys
import time
import tempfile
import uuid

from . import paths as storage
from .paths import HostContext, ProfileIdentity, ProfilePaths
from .podman import LABEL_PREFIX, Podman, published_bindings, resource_labels, assert_owned
from .profiles import Profile, initialize_profile, load_profile
from . import network
from .policy import encode_snapshot, decode_snapshot, MAX_SNAPSHOT_BYTES
from .denials import read_denials

ROOT = Path(__file__).resolve().parents[2]


def browser_cache_mount(host: HostContext) -> list[str]:
    return ['--tmpfs', f'/home/{host.user}/.t3/tools/chrome-headless-shell:rw,nosuid,nodev,exec,mode=1777,notmpcopyup']


def proxy_environment(proxy: str) -> dict[str, str]:
    values = {key: proxy for key in ('HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY',
                                    'http_proxy', 'https_proxy', 'all_proxy')}
    values.update(NO_PROXY='localhost,127.0.0.1,::1', no_proxy='localhost,127.0.0.1,::1',
                  NODE_USE_ENV_PROXY='1', T3_SANDBOX_BROWSER_PROXY=proxy)
    return values


def topology_digest(profile: Profile, paths: ProfilePaths) -> str:
    """Fingerprint settings that require container replacement, not image builds."""
    mounts = [('home', str(paths.home.resolve())), ('workspace', str(profile.project.directory.resolve()))]
    if profile.state.share_host_provider_state:
        mounts.extend((leaf, str(getattr(profile.state, leaf + '_directory').resolve())) for leaf in ('codex', 'claude'))
    if profile.state.share_host_gh_state:
        mounts.append(('gh', str(profile.state.gh_directory.resolve())))
        if profile.state.gitconfig_file.exists():
            mounts.append(('gitconfig', str(profile.state.gitconfig_file.resolve())))
    if profile.state.share_host_t3_state:
        mounts.append(('t3', str(profile.state.t3_directory.resolve())))
    value = {'browser_cache_contract': 1, 'proxy_environment_contract': 1, 'mounts': mounts, 'resources': asdict(profile.resources),
             'network': 'restricted' if profile.network.restricted else 'slirp4netns:allow_host_loopback=false',
             'server': asdict(profile.server), 'runtime': {
                 'env_file': str(profile.runtime.env_file) if profile.runtime.env_file else None,
                 'automatic_healthcheck': profile.runtime.automatic_healthcheck}}
    # Preserve existing fingerprints for profiles using the generated hostname.
    if profile.runtime.hostname is not None:
        value['runtime']['hostname'] = profile.runtime.hostname
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


class Launcher:
    def __init__(self, podman: Podman, host: HostContext, profile_dir: Path):
        self.podman, self.host, self.profile_dir = podman, host, profile_dir

    def _rootless(self):
        if self.host.uid == 0:
            raise ValueError('Run make as your Linux user, without sudo')
        if not re.fullmatch(r'[a-z_][a-z0-9_-]*', self.host.user):
            raise ValueError('Unsupported Linux username')
        if self.podman.run(['info', '--format', '{{.Host.Security.Rootless}}']).stdout.strip() != 'true':
            raise ValueError('A working local rootless Podman is required')

    def _owned(self, identity):
        return self.podman.inspect_owned('container', identity.container, identity, role='t3')

    def _labels(self, identity, role='t3'):
        return [part for key, value in {'managed': 'true', 'uid': str(identity.uid),
                'profile': identity.name, 'role': role}.items()
                for part in ('--label', LABEL_PREFIX + key + '=' + value)]

    def _endpoint(self, profile):
        if profile.server.advertised_url:
            return profile.server.advertised_url
        address = profile.server.bind_address
        address = {'0.0.0.0': '127.0.0.1', '::': '::1'}.get(address, address)
        if ':' in address:
            address = '[' + address + ']'
        return f'http://{address}:{profile.server.port}'

    def _host_t3_preflight(self, profile):
        if not profile.state.share_host_t3_state:
            return
        # T3 holds BEGIN EXCLUSIVE on this data-free SQLite database for its
        # lifetime (serverOwnership.ts). Namespace-local runtime PIDs cannot
        # identify host owners. Probe read-only, never create/unlink a lock, and
        # leave race arbitration to T3's own lifetime transaction at startup.
        lock = profile.state.t3_directory / 'userdata/server-owner.sqlite'
        try:
            with lock.open('rb') as stream:
                header = stream.read(20)
            # A read-only SQLite WAL connection may create shared-memory files.
            # Reject that unsupported format before opening a SQLite handle.
            if len(header) == 20 and (header[18] == 2 or header[19] == 2):
                raise ValueError('Unsupported T3 ownership lock journal mode; stop the host T3 server and inspect its state. Never delete its lock.')
        except FileNotFoundError:
            return
        except OSError as exc:
            raise ValueError('Cannot inspect the shared T3 ownership lock; check state permissions and integrity. Never delete its lock.') from exc
        try:
            with closing(sqlite3.connect(lock.resolve().as_uri() + '?mode=ro', uri=True, timeout=0)) as connection:
                mode = connection.execute('PRAGMA journal_mode').fetchone()[0]
                if mode != 'delete':
                    raise ValueError('Unsupported T3 ownership lock journal mode; stop the host T3 server and inspect its state. Never delete its lock.')
                connection.execute('SELECT name FROM sqlite_master').fetchall()
        except sqlite3.Error as exc:
            if getattr(exc, 'sqlite_errorcode', None) == sqlite3.SQLITE_BUSY:
                raise ValueError('The host T3 server is already running for the shared state directory; stop it or set state.share_host_t3_state: false. Never delete its lock.') from exc
            raise ValueError('Cannot inspect the shared T3 ownership lock; check state permissions and integrity. Never delete its lock.') from exc

    def _validate_start(self, profile, paths):
        storage.validate_storage(profile, paths, self.host, warn_skipped=False)
        for source, _ in storage._mounts(profile, paths, self.host):
            if ',' in str(source):
                raise ValueError(f'Mount path cannot contain commas: {source}')
            if source.exists() and not os.access(source, os.R_OK | os.W_OK | os.X_OK):
                raise ValueError(f'Storage is not readable and writable: {source}')
        for source, _ in storage.readonly_mounts(profile, self.host):
            if ',' in str(source):
                raise ValueError(f'Mount path cannot contain commas: {source}')
            if not os.access(source, os.R_OK):
                raise ValueError(f'Read-only mount is not readable: {source}')
        if profile.runtime.env_file and not profile.runtime.env_file.is_file():
            raise ValueError(f'Runtime env file not found: {profile.runtime.env_file}')
        storage.validate_t3_state_sharing(profile, paths, self.host, self.podman)

    def _build(self, profile, identity, fresh=False):
        args = ['build', '--format=docker', '--pull=always']
        if fresh:
            args.append('--no-cache')
        args += ['-f', str(ROOT / 'Dockerfile'), '-t', identity.image, *self._labels(identity)]
        selectors = {key.upper(): value for key, value in asdict(profile.build).items()}
        if fresh:
            selectors['T3_VERSION'] = 'latest'
        selectors.update(HOST_UID=str(self.host.uid), HOST_GID=str(self.host.gid), HOST_USER=self.host.user)
        for key, value in selectors.items():
            args += ['--build-arg', key + '=' + value]
        self.podman.run([*args, str(ROOT)], timeout=3600, capture=False)
        if profile.network.restricted:
            proxy = ['build', '--format=docker', '--pull=always']
            if fresh:
                proxy.append('--no-cache')
            self.podman.run([*proxy, '-f', str(ROOT / 'proxy/Dockerfile'), '-t', identity.proxy_image,
                            *self._labels(identity, role='proxy'), str(ROOT)], timeout=3600, capture=False)

    def _check_browser_runtime(self, profile, resource):
        specification = browser_cache_mount(self.host)[1]
        target, options = specification.split(':', 1)
        mounts = resource.get('HostConfig', {}).get('Tmpfs') or {}
        actual = set(mounts.get(target, '').split(','))
        required = set(options.split(',')) - {'notmpcopyup'}
        if set(mounts) != {target} or not required <= actual or actual - required - {'rprivate'}:
            raise ValueError('Actual browser tmpfs changed. Run make recreate.')
        env_items = resource.get('Config', {}).get('Env') or []
        env = dict(item.split('=', 1) for item in env_items if '=' in item)
        if len(env) != len(env_items):
            raise ValueError('Duplicate or malformed runtime environment. Run make recreate.')
        if profile.network.restricted:
            identity = ProfileIdentity(profile.name, self.host.uid)
            # Podman clears a stopped gateway's runtime IP. Derive the fixed
            # endpoint from the owned, validated network so crash recovery can
            # validate T3's environment before restarting that gateway.
            _, subnet = network._network(self.podman, identity, identity.private_network, True)
            gateway = self.podman.inspect_owned('container', identity.proxy, identity)
            address = str(subnet.network_address + 2)
            actual = (gateway or {}).get('NetworkSettings', {}).get('Networks', {}).get(identity.private_network, {}).get('IPAddress')
            if not gateway or (gateway.get('State', {}).get('Running') and actual != address):
                raise ValueError('Missing or changed browser proxy network. Run make recreate.')
            expected = proxy_environment(f'http://{address}:3128')
        else:
            expected = {'T3_SANDBOX_BROWSER_PROXY': ''}
        if any(env.get(key) != value for key, value in expected.items()):
            raise ValueError('Actual browser/proxy environment changed. Run make recreate.')

    def _check_existing(self, profile, paths, resource):
        self._check_browser_runtime(profile, resource)
        bindings = published_bindings(resource).get('3773/tcp', [])
        wanted = [{'HostIp': profile.server.bind_address, 'HostPort': str(profile.server.port)}]
        actual = {(m['Source'], m['Destination']) for m in resource.get('Mounts', []) if m.get('Type') == 'bind'}
        expected = {(str(source.resolve()), destination) for source, destination in
                    storage._mounts(profile, paths, self.host) + storage.readonly_mounts(profile, self.host)}
        identity = ProfileIdentity(profile.name, self.host.uid)
        image = self.podman.inspect_owned('image', identity.image, identity)
        if (image is None or resource.get('Image') != image['Id'] or bindings != wanted or actual != expected or
                resource_labels(resource).get(LABEL_PREFIX + 'topology') != topology_digest(profile, paths)):
            raise ValueError('Project, port, state mounts or runtime settings changed. Run make recreate to apply the new settings.')

    def _wait_ready(self, identity):
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            resource = self._owned(identity)
            if not resource or not resource.get('State', {}).get('Running'):
                code = resource.get('State', {}).get('ExitCode', 'unknown') if resource else 'unknown'
                raise ValueError(f'Container exited (code {code}). Run make logs. A shared .t3 requires the host T3 server to be stopped; use state.share_host_t3_state: false for private state.')
            ready = self.podman.run(['exec', identity.container, 'curl', '--fail', '--silent', '--noproxy', '*',
                '--connect-timeout', '1', '--max-time', '1', '--output', '/dev/null', 'http://127.0.0.1:3773/'], check=False)
            if ready.returncode == 0:
                return
            time.sleep(1)
        raise ValueError('Container is running, but T3 did not become ready within 30 seconds. Run make logs.')

    def _wait_published_ready(self, profile):
        # Probe the actual bind/port, independently of advertised pairing URLs
        # and ambient proxy variables. Rootless publication can lag listeners.
        address = {'0.0.0.0': '127.0.0.1', '::': '::1'}.get(profile.server.bind_address, profile.server.bind_address)
        if ':' in address:
            address = '[' + address + ']'
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            try:
                subprocess.run(['curl', '--fail', '--silent', '--show-error', '--noproxy', '*',
                    '--connect-timeout', '1', '--max-time', '2', '--output', '/dev/null',
                    f'http://{address}:{profile.server.port}/'], check=True, timeout=3,
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                return
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                time.sleep(0.1)
        raise ValueError('Published T3 management endpoint did not become ready within 30 seconds. Check the host port transport.')

    def _start(self, profile, paths, identity):
        self._validate_start(profile, paths)
        if profile.network.restricted:
            network.start_restricted(profile, paths, podman=self.podman, host=self.host)
            return
        resource = self._owned(identity)
        if resource:
            self._check_existing(profile, paths, resource)
            if not resource.get('State', {}).get('Running'):
                self._host_t3_preflight(profile)
                storage.prepare_home(profile, paths, self.host)
                self.podman.run(['start', identity.container], capture=False)
        else:
            self._host_t3_preflight(profile)
            image = self.podman.inspect_owned('image', identity.image, identity, role='t3')
            if image is None:
                raise ValueError('Build the image first: make build')
            labels = resource_labels(image)
            if any(labels.get(LABEL_PREFIX + key) != value for key, value in {
                    'uid': str(self.host.uid), 'gid': str(self.host.gid), 'user': self.host.user}.items()):
                raise ValueError('Image was built for another user. Run make build as the current user.')
            self._create_t3(profile, paths, identity, image,
                network_args=['--network=slirp4netns:allow_host_loopback=false'],
                publish_args=['--publish', f'{self._bind(profile)}:{profile.server.port}:3773'])
        self._wait_ready(identity)
        print('T3 endpoint: ' + self._endpoint(profile) + ' (ready)')

    def _bind(self, profile):
        address = profile.server.bind_address
        return '[' + address + ']' if ':' in address else address

    def _create_t3(self, profile, paths, identity, image, *, network_args, publish_args, browser_proxy=None):
        mounts = storage.prepare_home(profile, paths, self.host)
        home = '/home/' + self.host.user
        args = ['run', '--detach', '--name', identity.container, '--hostname', profile.runtime.hostname or identity.container,
            *self._labels(identity), '--label', LABEL_PREFIX + 'topology=' + topology_digest(profile, paths),
            '--label', LABEL_PREFIX + 'image-id=' + image['Id'],
            '--userns=keep-id', '--user', f'{self.host.uid}:{self.host.gid}', '--cap-drop=all',
            '--security-opt=no-new-privileges', *network_args,
            '--pid=private', '--ipc=private', '--pids-limit', str(profile.resources.pids_limit),
            '--init', '--shm-size=512m', '--stop-timeout=30', *publish_args,
            '--env', 'HOME=' + home, '--workdir', '/workspace']
        for source, destination in mounts:
            args += ['--mount', f'type=bind,src={source},dst={destination}']
        for source, destination in storage.readonly_mounts(profile, self.host):
            args += ['--mount', f'type=bind,src={source},dst={destination},ro']
        args += browser_cache_mount(self.host)
        if not profile.runtime.automatic_healthcheck:
            args.append('--no-healthcheck')
        for key in ('memory', 'cpus'):
            value = getattr(profile.resources, key)
            if value is not None:
                args += ['--' + key, str(value)]
        if profile.runtime.env_file:
            args += ['--env-file', str(profile.runtime.env_file)]
        if profile.network.restricted:
            if not browser_proxy:
                raise ValueError('Restricted browser proxy endpoint is required')
            for key, value in proxy_environment(browser_proxy).items():
                args += ['--env', key + '=' + value]
        else:
            # Our own control variable must not be injected by an env file.
            args += ['--env', 'T3_SANDBOX_BROWSER_PROXY=']
        # First keep-id start may copy/chown every image layer; 30s is far too short.
        self.podman.run([*args, identity.image], timeout=900, capture=False)

    def _atomic(self, path, data, mode):
        temporary = path.with_name(path.name + '.tmp')
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, mode)
        with os.fdopen(descriptor, 'wb') as stream:
            os.fchmod(stream.fileno(), mode)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)

    def _check_restricted_container(self, profile, paths, identity, resource, image, *, proxy):
        role = 'proxy' if proxy else 't3'
        if not proxy:
            self._check_browser_runtime(profile, resource)
        expected_mounts = {(str(source.resolve()), destination, not proxy or destination != '/run/t3-policy')
            for source, destination in ([(paths.runtime / 'policy', '/run/t3-policy'), (paths.logs, '/var/log/t3-proxy')]
                if proxy else storage._mounts(profile, paths, self.host))}
        if not proxy:
            expected_mounts |= {(str(source), destination, False)
                                for source, destination in storage.readonly_mounts(profile, self.host)}
        browser_target = None if proxy else browser_cache_mount(self.host)[1].split(':', 1)[0]
        actual_mounts = {(m.get('Source'), m.get('Destination'), m.get('RW'))
            for m in resource.get('Mounts', [])
            if not (not proxy and m.get('Type') == 'tmpfs' and m.get('Destination') == browser_target)}
        hc = resource.get('HostConfig', {})
        expected_ports = {'3773/tcp': [{'HostIp': profile.server.bind_address, 'HostPort': str(profile.server.port)}]} if proxy else {}
        caps = {'CAP_NET_ADMIN', 'CAP_SETUID', 'CAP_SETGID', 'CAP_SETPCAP', 'CAP_CHOWN'} if proxy else set()
        mappings = hc.get('IDMappings', {})
        mapped_uid, mapped_gid = (2003, 2003) if proxy else (self.host.uid, self.host.gid)
        keep_id = (hc.get('UsernsMode') == 'private' and
            f'{mapped_uid}:0:1' in (mappings.get('UidMap') or []) and
            f'{mapped_gid}:0:1' in (mappings.get('GidMap') or []))
        if (resource.get('Image') != image['Id'] or actual_mounts != expected_mounts or
                published_bindings(resource) != expected_ports or hc.get('Privileged') is not False or
                hc.get('PidMode') not in ('', 'private') or hc.get('IpcMode') != 'private' or
                set(resource.get('BoundingCaps') or []) != caps or
                not any(item in ('no-new-privileges', 'no-new-privileges=true') for item in hc.get('SecurityOpt') or []) or
                resource.get('Config', {}).get('User') != ('0:0' if proxy else f'{self.host.uid}:{self.host.gid}') or
                not keep_id or hc.get('ExtraHosts') or hc.get('Dns') or
                resource.get('ResolvConfPath') != '' or resource.get('HostsPath') != '' or
                (proxy and (hc.get('Init') or hc.get('Tmpfs')))):
            raise network.IsolationError(f'Actual {role} image, mounts, bind/ports or namespace controls changed. Run make recreate.')
        if resource_labels(resource).get(LABEL_PREFIX + 'topology') != topology_digest(profile, paths):
            raise ValueError('Project, port, state mounts or runtime settings changed. Run make recreate to apply the new settings.')

    def _wait_proxy(self, identity, digest):
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            resource = self.podman.inspect_owned('container', identity.proxy, identity)
            if not resource or not resource.get('State', {}).get('Running'):
                raise network.IsolationError('Gateway exited before matching policy readiness')
            result = self.podman.run(['exec', identity.proxy, 'cat', '/run/t3-proxy/ready.json'], check=False)
            try:
                ready = json.loads(result.stdout)
            except ValueError:
                ready = None
            if result.returncode == 0 and ready == {'digest': digest}:
                # The marker may survive a process exit between inspections.
                resource = self.podman.inspect_owned('container', identity.proxy, identity)
                if resource and resource.get('State', {}).get('Running'):
                    return
            time.sleep(0.1)
        raise network.IsolationError('Gateway did not publish matching policy readiness within 30 seconds')

    def _restricted_preflight(self, profile, paths, identity):
        """Validate reuse without changing running resources or bridge controls."""
        images = {role: self.podman.inspect_owned('image', name, identity, role=role) for role, name in (
            ('t3', identity.image), ('proxy', identity.proxy_image))}
        if any(image is None for image in images.values()):
            raise ValueError('Build both restricted-mode images first: make build')
        if any(resource_labels(images['t3']).get(LABEL_PREFIX + key) != value for key, value in {
                'uid': str(self.host.uid), 'gid': str(self.host.gid), 'user': self.host.user}.items()):
            raise ValueError('Image was built for another user. Run make build as the current user.')
        existing = {role: self.podman.inspect_owned('container', name, identity, role=role) for role, name in (
            ('t3', identity.container), ('proxy', identity.proxy))}
        # Check collisions for every deterministic resource before allocating any.
        initial_networks = {name: self.podman.inspect_owned('network', name, identity) for name in (
            identity.private_network, identity.external_network)}
        for role, resource in existing.items():
            if resource:
                self._check_restricted_container(profile, paths, identity, resource, images[role], proxy=role == 'proxy')
        if any(existing.values()):
            gateway = network.ensure_networks(self.podman, identity, profile.server, create=False)
            self._check_restricted_snapshot(profile, paths, gateway)
        if not existing['t3'] or not existing['t3'].get('State', {}).get('Running'):
            self._host_t3_preflight(profile)
        return images, existing, initial_networks

    def _check_restricted_snapshot(self, profile, paths, gateway):
        snapshot = json.loads(encode_snapshot(profile.network.allow, gateway))
        try:
            active = json.loads((paths.runtime / 'topology.json').read_bytes())
        except (OSError, ValueError) as exc:
            raise ValueError('Missing runtime topology. Run make recreate.') from exc
        if active.get('topology_digest') != topology_digest(profile, paths) or active.get('gateway') != snapshot['gateway']:
            raise ValueError('Network topology changed. Run make recreate.')
        if active.get('policy_digest') != snapshot['digest']:
            raise ValueError('Allowlist changed. Run make proxy-restart to apply the policy.')

    def _start_restricted(self, profile, paths, identity):
        images, existing, initial_networks = self._restricted_preflight(profile, paths, identity)
        created, started = [], []
        try:
            allocation = replace(paths, lock=paths.lock.parent.parent / '.allocation.lock')
            with storage.mutation_lock(allocation):
                gateway = network.ensure_networks(self.podman, identity, profile.server)
            snapshot = encode_snapshot(profile.network.allow, gateway)
            digest = json.loads(snapshot)['digest']
            topology_file = paths.runtime / 'topology.json'
            if any(existing.values()):
                self._check_restricted_snapshot(profile, paths, gateway)
            else:
                for path, mode in ((paths.runtime, 0o700), (paths.runtime / 'policy', 0o755), (paths.logs, 0o700)):
                    if path.is_symlink():
                        raise ValueError('Runtime and log directories must not be symlinks')
                    path.mkdir(mode=mode, parents=True, exist_ok=True)
                    if path.stat().st_uid != os.getuid():
                        raise ValueError('Runtime and logs must be owned by the host user')
                    path.chmod(mode)
                self._atomic(paths.runtime / 'policy/active.json', snapshot, 0o644)
            if existing['proxy']:
                if not existing['proxy'].get('State', {}).get('Running'):
                    started.append(identity.proxy)
                    self.podman.run(['start', identity.proxy])
            else:
                created.append(identity.proxy)
                self.podman.run(['run', '--detach', '--pull=never', '--name', identity.proxy,
                    *self._labels(identity, 'proxy'), '--label', LABEL_PREFIX + 'topology=' + topology_digest(profile, paths),
                    '--label', LABEL_PREFIX + 'image-id=' + images['proxy']['Id'],
                    '--userns=keep-id:uid=2003,gid=2003', '--user=0:0', '--cap-drop=all',
                    '--cap-add=NET_ADMIN,SETUID,SETGID,SETPCAP,CHOWN', '--security-opt=no-new-privileges',
                    '--pid=private', '--ipc=private', '--pids-limit=128', '--memory=512m', '--stop-timeout=10',
                    '--sysctl', 'net.ipv4.ip_forward=0', '--sysctl', 'net.ipv6.conf.all.forwarding=0',
                    '--sysctl', 'net.ipv6.conf.default.forwarding=0', '--dns=none', '--no-hosts',
                    '--network=' + identity.external_network,
                    '--network=' + identity.private_network + ':ip=' + gateway.private_ip,
                    '--mount', f'type=bind,src={paths.runtime / "policy"},dst=/run/t3-policy,ro',
                    '--mount', f'type=bind,src={paths.logs},dst=/var/log/t3-proxy',
                    '--publish', f'{self._bind(profile)}:{profile.server.port}:3773', identity.proxy_image])
            # Only the trusted gateway exists when the bridge is hardened.
            network.harden_bridge(self.podman, identity)
            self._wait_proxy(identity, digest)
            network.assert_isolated(self.podman, identity, gateway)
            network.route_probe(self.podman, identity, identity.proxy_image)
            network.assert_isolated(self.podman, identity, gateway)
            if existing['t3']:
                if not existing['t3'].get('State', {}).get('Running'):
                    storage.prepare_home(profile, paths, self.host)
                    started.append(identity.container)
                    self.podman.run(['start', identity.container])
            else:
                created.append(identity.container)
                self._create_t3(profile, paths, identity, images['t3'], network_args=[
                    '--network=' + identity.private_network + ':ip=' + gateway.t3_ip,
                    '--dns=none', '--no-hosts'], publish_args=[],
                    browser_proxy=f'http://{gateway.private_ip}:3128')
            network.assert_isolated(self.podman, identity, gateway)
            self._atomic(topology_file, json.dumps({'version': 1, 'topology_digest': topology_digest(profile, paths),
                'gateway': asdict(gateway), 'policy_digest': digest}, sort_keys=True).encode() + b'\n', 0o600)
            self._wait_ready(identity)
            self._wait_published_ready(profile)
            print('T3 endpoint: ' + self._endpoint(profile) + ' (ready; restricted)')
        except BaseException:
            # Bound rollback to exact resources created or started by this call.
            for name in (identity.container, identity.proxy):
                if name in created and self.podman.inspect_owned('container', name, identity):
                    self.podman.run(['rm', '--force', '--time=1', name])
                elif name in started and self.podman.inspect_owned('container', name, identity):
                    self.podman.run(['stop', name])
            for name, original in initial_networks.items():
                if original is None and self.podman.inspect_owned('network', name, identity):
                    self.podman.run(['network', 'rm', name])
            raise

    def _validate_candidate(self, identity, image, directory, digest):
        name = identity.proxy + '-validate-' + uuid.uuid4().hex[:12]
        try:
            validation = self.podman.run(['run', '--rm', '--pull=never', '--name', name,
                *self._labels(identity, 'proxy'), '--network=none', '--userns=keep-id:uid=2003,gid=2003',
                '--user=2003:2003', '--cap-drop=all', '--security-opt=no-new-privileges',
                '--pid=private', '--ipc=private', '--pids-limit=32', '--memory=512m',
                '--mount', f'type=bind,src={directory},dst=/run/t3-policy,ro',
                image['Id'], 'validate', '--snapshot', '/run/t3-policy/active.json'], timeout=30)
            try:
                valid = json.loads(validation.stdout) == {'digest': digest}
            except ValueError:
                valid = False
            if not valid:
                raise ValueError('Gateway software did not validate the candidate policy digest')
        finally:
            # --rm normally handles this; an interrupted/timed-out engine client
            # can leave its validator alive. Remove only this exact owned name.
            remaining = self.podman.inspect('container', name)
            if remaining is not None:
                assert_owned(remaining, identity)
                if resource_labels(remaining).get(LABEL_PREFIX + 'role') != 'proxy':
                    raise ValueError('Refusing validator cleanup with a changed role')
                self.podman.run(['rm', '--force', '--time=1', name])

    def proxy_restart(self, name: str) -> int:
        identity = ProfileIdentity(name, self.host.uid)
        paths = storage.profile_paths(identity, self.profile_dir, self.host)
        self._rootless()
        with storage.mutation_lock(paths):
            # One immutable candidate, including defaults, for this transaction.
            profile = load_profile(name, self.profile_dir, self.host)
            proxy = self.podman.inspect_owned('container', identity.proxy, identity, role='proxy')
            if not profile.network.restricted:
                if proxy:
                    raise ValueError('Network mode changed. Run make recreate.')
                print('Restricted mode is off; no gateway to restart.')
                return 0
            storage.validate_storage(profile, paths, self.host)
            t3 = self._owned(identity)
            if not proxy or not t3 or not t3.get('State', {}).get('Running'):
                raise ValueError('Start the restricted sandbox first: make start')
            # Pin validation to the existing software, even if its tag was rebuilt.
            images = {}
            for role, resource in (('proxy', proxy), ('t3', t3)):
                image = self.podman.inspect('image', resource['Image'])
                if image is None:
                    raise ValueError('Existing container image is unavailable; run make recreate')
                assert_owned(image, identity)
                if resource_labels(image).get(LABEL_PREFIX + 'role') != role:
                    raise ValueError('Existing image role changed; run make recreate')
                images[role] = image
            for role, resource in (('proxy', proxy), ('t3', t3)):
                self._check_restricted_container(profile, paths, identity, resource, images[role], proxy=role == 'proxy')
            gateway = network.ensure_networks(self.podman, identity, profile.server, create=False)
            topology_file = paths.runtime / 'topology.json'
            try:
                active = json.loads(topology_file.read_bytes())
            except (OSError, ValueError) as exc:
                raise ValueError('Missing runtime topology. Run make recreate.') from exc
            snapshot = encode_snapshot(profile.network.allow, gateway)
            candidate = json.loads(snapshot)
            if active.get('topology_digest') != topology_digest(profile, paths) or active.get('gateway') != candidate['gateway']:
                raise ValueError('Network topology changed. Run make recreate.')
            # A failed previous replacement can be retried without starting T3.
            network.harden_bridge(self.podman, identity)
            if proxy.get('State', {}).get('Running'):
                network.assert_isolated(self.podman, identity, gateway)
            with tempfile.TemporaryDirectory(prefix='candidate-', dir=paths.runtime) as temporary:
                directory = Path(temporary)
                directory.chmod(0o755)
                self._atomic(directory / 'active.json', snapshot, 0o644)
                self._validate_candidate(identity, images['proxy'], directory, candidate['digest'])
                # The existing directory mount observes this new inode atomically.
                os.replace(directory / 'active.json', paths.runtime / 'policy/active.json')
            try:
                if proxy.get('State', {}).get('Running'):
                    self.podman.run(['stop', identity.proxy])
                self.podman.run(['start', identity.proxy])
                self._wait_proxy(identity, candidate['digest'])
                current = self.podman.inspect_owned('container', identity.proxy, identity, role='proxy')
                self._check_restricted_container(profile, paths, identity, current, images['proxy'], proxy=True)
                network.harden_bridge(self.podman, identity)
                network.assert_isolated(self.podman, identity, gateway)
                self._wait_ready(identity)
                self._wait_published_ready(profile)
                self._atomic(topology_file, json.dumps({**active, 'policy_digest': candidate['digest']}, sort_keys=True).encode() + b'\n', 0o600)
            except BaseException:
                # Never restore a broader previous policy or touch the workload.
                current = self.podman.inspect_owned('container', identity.proxy, identity, role='proxy')
                if current and current.get('State', {}).get('Running'):
                    self.podman.run(['stop', identity.proxy])
                raise
            print('Proxy policy restarted; T3 remains running. Active streams must reconnect.')
            return 0

    def _firewall_logs(self, identity, paths, *, tail, follow):
        proxy = self.podman.inspect_owned('container', identity.proxy, identity, role='proxy')
        if proxy is None:
            raise ValueError('No owned restricted-mode gateway exists for this profile')
        mounts = [m for m in proxy.get('Mounts', []) if m.get('Destination') == '/var/log/t3-proxy']
        if (len(mounts) != 1 or mounts[0].get('Type') != 'bind' or
                mounts[0].get('Source') != str(paths.logs.resolve()) or paths.logs.is_symlink() or
                not paths.logs.is_dir() or paths.logs.stat().st_uid != os.getuid() or paths.logs.stat().st_mode & 0o077):
            raise ValueError('Gateway log directory is not the owned private profile directory')
        try:
            for record in read_denials(paths.logs, tail=tail, follow=follow):
                print(record.json_line(), end='', flush=True)
        except KeyboardInterrupt:
            return 130
        return 0

    def _policy_status(self, identity, paths, proxy):
        digest = None
        if proxy and proxy.get('State', {}).get('Running'):
            ready = self.podman.run(['exec', identity.proxy, 'cat', '/run/t3-proxy/ready.json'], check=False)
            try:
                value = json.loads(ready.stdout)
                current = self.podman.inspect_owned('container', identity.proxy, identity, role='proxy')
                if (ready.returncode == 0 and isinstance(value, dict) and set(value) == {'digest'} and
                        isinstance(value['digest'], str) and re.fullmatch('[0-9a-f]{64}', value['digest']) and
                        current and current.get('State', {}).get('Running')):
                    digest = value['digest']
            except ValueError:
                pass
        print('active policy: ' + (digest or 'unavailable'))
        try:
            if not paths.profile_file.is_file():
                raise ValueError('Missing profile')
            profile = load_profile(identity.name, self.profile_dir, self.host)
            if not profile.network.restricted:
                saved = 'off'
            else:
                with (paths.runtime / 'policy/active.json').open('rb') as stream:
                    _, gateway = decode_snapshot(stream.read(MAX_SNAPSHOT_BYTES + 1))
                saved = json.loads(encode_snapshot(profile.network.allow, gateway))['digest']
        except (OSError, ValueError):
            saved = 'invalid or missing'
        print('saved policy: ' + saved)

    def _stop(self, identity):
        # Deterministic owned discovery is independent of broken/missing YAML.
        for name, role in ((identity.container, 't3'), (identity.proxy, 'proxy')):
            resource = self.podman.inspect_owned('container', name, identity, role=role)
            if resource and resource.get('State', {}).get('Running'):
                self.podman.run(['stop', name], capture=False)

    def _remove(self, identity):
        self._stop(identity)
        for name, role in ((identity.container, 't3'), (identity.proxy, 'proxy')):
            if self.podman.inspect_owned('container', name, identity, role=role):
                self.podman.run(['rm', name], capture=False)
        for name, role in ((identity.private_network, 'private'), (identity.external_network, 'external')):
            if self.podman.inspect_owned('network', name, identity, role=role):
                self.podman.run(['network', 'rm', name], capture=False)

    def _require_running(self, identity):
        resource = self._owned(identity)
        if not resource or not resource.get('State', {}).get('Running'):
            raise ValueError('Start the sandbox first: make start')

    def dispatch(self, command: str, name: str, *, cmd: str | None = None, follow=True, tail=100) -> int:
        if command == 'proxy-restart':
            return self.proxy_restart(name)
        identity = ProfileIdentity(name, self.host.uid)
        paths = storage.profile_paths(identity, self.profile_dir, self.host)
        if command == 'init':
            print('Profile: ' + str(initialize_profile(name, self.profile_dir, self.host)))
            return 0
        recovery = command in ('stop', 'remove', 'status', 'logs', 'firewall-logs')
        profile = None if recovery else load_profile(name, self.profile_dir, self.host)
        if command == 'config':
            print(json.dumps({'profile': str(profile.source), 'container': identity.container, 'image': identity.image,
                'home': str(paths.home), 'settings': asdict(profile)}, default=str, indent=2))
            return 0
        self._rootless()
        if command in ('build', 'rebuild', 'start', 'restart', 'recreate', 'stop', 'remove'):
            # Validate boundaries before creating even the mutation lock directory.
            if profile is not None and command in ('start', 'restart', 'recreate'):
                storage.validate_storage(profile, paths, self.host)
            with ExitStack() as locks:
                locks.enter_context(storage.mutation_lock(paths))
                if profile is not None and command in ('start', 'restart', 'recreate'):
                    source = (profile.state.t3_directory if profile.state.share_host_t3_state else paths.home / '.t3').resolve()
                    state_key = hashlib.sha256(str(source).encode()).hexdigest()
                    # Only profiles using this same canonical state source wait.
                    locks.enter_context(storage.mutation_lock(replace(paths,
                        lock=paths.lock.parent.parent / ('.state-' + state_key + '.lock'))))
                if command in ('build', 'rebuild'):
                    self._build(profile, identity, command == 'rebuild')
                elif command in ('stop', 'remove'):
                    (self._remove if command == 'remove' else self._stop)(identity)
                else:
                    self._validate_start(profile, paths)
                    if command == 'restart':
                        resource = self._owned(identity)
                        if profile.network.restricted:
                            self._restricted_preflight(profile, paths, identity)
                        elif resource:
                            self._check_existing(profile, paths, resource)
                        self._stop(identity)
                    if command == 'recreate':
                        self._remove(identity)
                    self._start(profile, paths, identity)
            return 0
        if command == 'firewall-logs':
            return self._firewall_logs(identity, paths, tail=tail, follow=follow)
        if command == 'status':
            for resource_name, role in ((identity.container, 't3'), (identity.proxy, 'proxy')):
                resource = self.podman.inspect_owned('container', resource_name, identity, role=role)
                print(resource_name + ': ' + ('running' if resource.get('State', {}).get('Running') else 'stopped') if resource else resource_name + ': absent')
                if resource:
                    print(json.dumps(resource.get('HostConfig', {}).get('PortBindings', {})))
                if role == 'proxy' and resource:
                    self._policy_status(identity, paths, resource)
        elif command == 'logs':
            if not self._owned(identity):
                raise ValueError('No owned container exists for this profile')
            args = ['logs', '--tail', str(tail)]
            if follow:
                args.append('--follow')
            self.podman.run([*args, identity.container], timeout=None, capture=False)
        elif command == 'doctor':
            for executable in ('slirp4netns', 'newuidmap', 'newgidmap'):
                if not shutil.which(executable):
                    raise ValueError('Install host prerequisite: ' + executable)
            for file in ('/etc/subuid', '/etc/subgid'):
                entries = [line.split(':') for line in Path(file).read_text().splitlines()]
                if not any(len(row) == 3 and row[0] in (self.host.user, str(self.host.uid)) and int(row[2]) >= 65536 for row in entries):
                    raise ValueError(f'Assign {self.host.user} a nonoverlapping subordinate ID range of at least 65536 in {file}')
            storage.validate_storage(profile, paths, self.host)
            print('Host prerequisites passed.')
        elif command in ('shell', 'exec', 'pair', 'smoke'):
            self._require_running(identity)
            if command in ('shell', 'exec'):
                if command == 'exec' and not cmd:
                    raise ValueError('Usage: make exec CMD="codex login --device-auth"')
                tty = ['-i'] + (['-t'] if sys.stdin.isatty() and sys.stdout.isatty() else [])
                # The session's exit status is the user's, not a Podman failure (e.g. 130 after Ctrl-C).
                # Podman's own failures use 125-127 and still surface as errors.
                result = self.podman.run(['exec', *tty, identity.container, *(['bash'] if command == 'shell' else ['bash', '-c', cmd])], check=False, timeout=None, capture=False)
                if result.returncode in (125, 126, 127):
                    result.check_returncode()
                return result.returncode
            elif command == 'pair':
                result = self.podman.run(['exec', identity.container, 't3', 'pair'])
                subprocess.run([sys.executable, str(ROOT / 'scripts/pair-url.py'), self._endpoint(profile)], input=result.stdout, text=True, check=True)
            else:
                self._smoke(profile, identity)
        else:
            raise ValueError('Unknown command. Run make help.')
        return 0

    def _smoke(self, profile, identity):
        if profile.network.restricted:
            network_probe = (
                'status=$(curl --silent --show-error --connect-timeout 5 --max-time 20 '
                '--output /dev/null --write-out "%{http_code}" https://api.openai.com/v1/models); '
                'case "$status" in 200|401|403) ;; *) echo "Provider HTTPS transport failed: $status" >&2; exit 1;; esac; ')
        else:
            network_probe = ('curl --fail --silent --show-error --connect-timeout 5 --max-time 20 '
                             '--output /dev/null https://registry.npmjs.org/; ')
        self.podman.run(['exec', identity.container, 'bash', '-ec',
            'test "$(id -u)" != 0; id; node --version; npm --version; codex --version; claude --version; t3 --version; '
            'python3 --version; uv --version; go version; rustc --version; javac -version; ' +
            network_probe + 'curl --fail --silent --show-error --noproxy \"*\" --connect-timeout 2 --max-time 5 '
            '--output /dev/null http://127.0.0.1:3773/'], capture=False)
        probe = self.podman.run(['exec', identity.container, 'mktemp', '/workspace/.t3-permission-check.XXXXXXXX']).stdout.strip()
        if not re.fullmatch(r'/workspace/\.t3-permission-check\.[A-Za-z0-9]+', probe):
            raise ValueError('Unexpected ownership probe path')
        target = profile.project.directory / Path(probe).name
        try:
            stat = target.stat()
            if (stat.st_uid, stat.st_gid) != (self.host.uid, self.host.gid):
                raise ValueError('Host file ownership does not match')
        finally:
            target.unlink(missing_ok=True)
        address = {'0.0.0.0': '127.0.0.1', '::': '::1'}.get(profile.server.bind_address, profile.server.bind_address)
        if ':' in address:
            address = '[' + address + ']'
        subprocess.run(['curl', '--fail', '--silent', '--show-error', '--noproxy', '*',
                        '--connect-timeout', '2', '--max-time', '5', '--output', '/dev/null',
                        f'http://{address}:{profile.server.port}'], check=True, timeout=10)
        print('Tools, outbound HTTPS, T3 HTTP, and host UID/GID ownership passed.')
