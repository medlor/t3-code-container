"""Profile lifecycle policy; all external commands use argument arrays."""
from dataclasses import asdict, replace
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time

from . import paths as storage
from .paths import HostContext, ProfileIdentity, ProfilePaths
from .podman import LABEL_PREFIX, Podman, published_bindings, resource_labels
from .profiles import Profile, initialize_profile, load_profile
from . import network
from .policy import encode_snapshot

ROOT = Path(__file__).resolve().parents[2]


def topology_digest(profile: Profile, paths: ProfilePaths) -> str:
    """Fingerprint settings that require container replacement, not image builds."""
    mounts = [('home', str(paths.home.resolve())), ('workspace', str(profile.project.directory.resolve()))]
    if profile.state.share_host_provider_state:
        mounts.extend((leaf, str(getattr(profile.state, leaf + '_directory').resolve())) for leaf in ('codex', 'claude'))
    if profile.state.share_host_t3_state:
        mounts.append(('t3', str(profile.state.t3_directory.resolve())))
    value = {'mounts': mounts, 'resources': asdict(profile.resources),
             'network': 'restricted' if profile.network.restricted else 'slirp4netns:allow_host_loopback=false',
             'server': asdict(profile.server), 'runtime': {
                 'env_file': str(profile.runtime.env_file) if profile.runtime.env_file else None,
                 'automatic_healthcheck': profile.runtime.automatic_healthcheck}}
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
        # Follow T3's persisted runtime discovery. This is only a preflight;
        # T3's own lifetime lock arbitrates races. Never clear its runtime record.
        record = profile.state.t3_directory / 'userdata/server-runtime.json'
        try:
            state = json.loads(record.read_text())
        except (FileNotFoundError, ValueError):
            return
        if not isinstance(state, dict) or state.get('version') != 1 or type(state.get('pid')) is not int or state['pid'] <= 0:
            return
        try:
            os.kill(state['pid'], 0)
        except ProcessLookupError:
            return
        except PermissionError:
            pass
        raise ValueError('The host T3 server is already running for the shared state directory; stop it or set state.share_host_t3_state: false. Never delete its lock.')

    def _validate_start(self, profile, paths):
        storage.validate_storage(profile, paths, self.host)
        for source, _ in storage._mounts(profile, paths, self.host):
            if ',' in str(source):
                raise ValueError(f'Mount path cannot contain commas: {source}')
            if source.exists() and not os.access(source, os.R_OK | os.W_OK | os.X_OK):
                raise ValueError(f'Storage is not readable and writable: {source}')
        if profile.runtime.env_file and not profile.runtime.env_file.is_file():
            raise ValueError(f'Runtime env file not found: {profile.runtime.env_file}')
        storage.validate_t3_state_sharing(profile, paths, self.host, self.podman)

    def _build(self, profile, identity, fresh=False):
        args = ['build', '--format=docker', '--pull=always']
        if fresh:
            args.append('--no-cache')
        args += ['-f', str(ROOT / 'Dockerfile'), '-t', identity.image, *self._labels(identity)]
        selectors = {key.upper(): value for key, value in asdict(profile.build).items()}
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

    def _check_existing(self, profile, paths, resource):
        bindings = published_bindings(resource).get('3773/tcp', [])
        wanted = [{'HostIp': profile.server.bind_address, 'HostPort': str(profile.server.port)}]
        actual = {(m['Source'], m['Destination']) for m in resource.get('Mounts', []) if m.get('Type') == 'bind'}
        expected = {(str(source.resolve()), destination) for source, destination in storage._mounts(profile, paths, self.host)}
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

    def _create_t3(self, profile, paths, identity, image, *, network_args, publish_args):
        mounts = storage.prepare_home(profile, paths, self.host)
        home = '/home/' + self.host.user
        args = ['run', '--detach', '--name', identity.container, '--hostname', identity.container,
            *self._labels(identity), '--label', LABEL_PREFIX + 'topology=' + topology_digest(profile, paths),
            '--label', LABEL_PREFIX + 'image-id=' + image['Id'],
            '--userns=keep-id', '--user', f'{self.host.uid}:{self.host.gid}', '--cap-drop=all',
            '--security-opt=no-new-privileges', *network_args,
            '--pid=private', '--ipc=private', '--pids-limit', str(profile.resources.pids_limit),
            '--init', '--shm-size=512m', '--stop-timeout=30', *publish_args,
            '--env', 'HOME=' + home, '--workdir', '/workspace']
        for source, destination in mounts:
            args += ['--mount', f'type=bind,src={source},dst={destination}']
        if not profile.runtime.automatic_healthcheck:
            args.append('--no-healthcheck')
        for key in ('memory', 'cpus'):
            value = getattr(profile.resources, key)
            if value is not None:
                args += ['--' + key, str(value)]
        if profile.runtime.env_file:
            args += ['--env-file', str(profile.runtime.env_file)]
        self.podman.run([*args, identity.image], capture=False)

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
        expected_mounts = {(str(source.resolve()), destination, not proxy or destination != '/run/t3-policy')
            for source, destination in ([(paths.runtime / 'policy', '/run/t3-policy'), (paths.logs, '/var/log/t3-proxy')]
                if proxy else storage._mounts(profile, paths, self.host))}
        actual_mounts = {(m.get('Source'), m.get('Destination'), m.get('RW')) for m in resource.get('Mounts', [])}
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
                (proxy and hc.get('Init'))):
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

    def _start_restricted(self, profile, paths, identity):
        # All sharing/storage preflights precede resource and runtime mutations.
        self._host_t3_preflight(profile)
        images = {role: self.podman.inspect_owned('image', name, identity) for role, name in (
            ('t3', identity.image), ('proxy', identity.proxy_image))}
        if any(image is None for image in images.values()):
            raise ValueError('Build both restricted-mode images first: make build')
        if any(resource_labels(images['t3']).get(LABEL_PREFIX + key) != value for key, value in {
                'uid': str(self.host.uid), 'gid': str(self.host.gid), 'user': self.host.user}.items()):
            raise ValueError('Image was built for another user. Run make build as the current user.')
        existing = {role: self.podman.inspect_owned('container', name, identity) for role, name in (
            ('t3', identity.container), ('proxy', identity.proxy))}
        # Check collisions for every deterministic resource before allocating any.
        initial_networks = {name: self.podman.inspect_owned('network', name, identity) for name in (
            identity.private_network, identity.external_network)}
        for role, resource in existing.items():
            if resource:
                self._check_restricted_container(profile, paths, identity, resource, images[role], proxy=role == 'proxy')
        created, started = [], []
        try:
            allocation = replace(paths, lock=paths.lock.parent.parent / '.allocation.lock')
            with storage.mutation_lock(allocation):
                gateway = network.ensure_networks(self.podman, identity, profile.server)
            snapshot = encode_snapshot(profile.network.allow, gateway)
            digest = json.loads(snapshot)['digest']
            topology_file = paths.runtime / 'topology.json'
            if any(existing.values()):
                try:
                    active = json.loads(topology_file.read_bytes())
                except (OSError, ValueError) as exc:
                    raise ValueError('Missing runtime topology. Run make recreate.') from exc
                if active.get('topology_digest') != topology_digest(profile, paths) or active.get('gateway') != json.loads(snapshot)['gateway']:
                    raise ValueError('Network topology changed. Run make recreate.')
                if active.get('policy_digest') != digest:
                    raise ValueError('Allowlist changed. Run make proxy-restart to apply the policy.')
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
                    '--dns=none', '--no-hosts', '--env', f'HTTP_PROXY=http://{gateway.private_ip}:3128',
                    '--env', f'HTTPS_PROXY=http://{gateway.private_ip}:3128',
                    '--env', f'http_proxy=http://{gateway.private_ip}:3128',
                    '--env', f'https_proxy=http://{gateway.private_ip}:3128'], publish_args=[])
            network.assert_isolated(self.podman, identity, gateway)
            self._atomic(topology_file, json.dumps({'version': 1, 'topology_digest': topology_digest(profile, paths),
                'gateway': asdict(gateway), 'policy_digest': digest}, sort_keys=True).encode() + b'\n', 0o600)
            self._wait_ready(identity)
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
        identity = ProfileIdentity(name, self.host.uid)
        paths = storage.profile_paths(identity, self.profile_dir, self.host)
        if command == 'init':
            print('Profile: ' + str(initialize_profile(name, self.profile_dir, self.host)))
            return 0
        recovery = command in ('stop', 'remove', 'status', 'logs')
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
                        if resource and not profile.network.restricted:
                            self._check_existing(profile, paths, resource)
                        self._stop(identity)
                    if command == 'recreate':
                        self._remove(identity)
                    self._start(profile, paths, identity)
            return 0
        if command == 'status':
            for resource_name, role in ((identity.container, 't3'), (identity.proxy, 'proxy')):
                resource = self.podman.inspect_owned('container', resource_name, identity, role=role)
                print(resource_name + ': ' + ('running' if resource.get('State', {}).get('Running') else 'stopped') if resource else resource_name + ': absent')
                if resource:
                    print(json.dumps(resource.get('HostConfig', {}).get('PortBindings', {})))
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
                self.podman.run(['exec', *tty, identity.container, *(['bash'] if command == 'shell' else ['bash', '-c', cmd])], timeout=None, capture=False)
            elif command == 'pair':
                result = self.podman.run(['exec', identity.container, 't3', 'pair'])
                subprocess.run([sys.executable, str(ROOT / 'scripts/pair-url.py'), self._endpoint(profile)], input=result.stdout, text=True, check=True)
            else:
                self._smoke(profile, identity)
        else:
            raise ValueError('Unknown command. Run make help.')
        return 0

    def _smoke(self, profile, identity):
        self.podman.run(['exec', identity.container, 'bash', '-ec',
            'test "$(id -u)" != 0; id; node --version; npm --version; codex --version; claude --version; t3 --version; '
            'python3 --version; uv --version; go version; rustc --version; javac -version; '
            'curl --fail --silent --show-error --output /dev/null https://registry.npmjs.org/'], capture=False)
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
