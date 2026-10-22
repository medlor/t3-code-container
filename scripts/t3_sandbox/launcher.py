"""Profile lifecycle policy; all external commands use argument arrays."""
from dataclasses import asdict
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
from .podman import LABEL_PREFIX, Podman, resource_labels
from .profiles import Profile, initialize_profile, load_profile

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
        if profile.network.restricted:
            raise ValueError('Restricted startup is not implemented until Task 6; no unrestricted fallback is available')
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

    def _check_existing(self, profile, paths, resource):
        bindings = resource.get('HostConfig', {}).get('PortBindings', {}).get('3773/tcp', [])
        wanted = [{'HostIp': profile.server.bind_address, 'HostPort': str(profile.server.port)}]
        actual = {(m['Source'], m['Destination']) for m in resource.get('Mounts', []) if m.get('Type') == 'bind'}
        expected = {(str(source.resolve()), destination) for source, destination in storage._mounts(profile, paths, self.host)}
        if bindings != wanted or actual != expected or resource_labels(resource).get(LABEL_PREFIX + 'topology') != topology_digest(profile, paths):
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
            mounts = storage.prepare_home(profile, paths, self.host)
            home = '/home/' + self.host.user
            address = profile.server.bind_address
            if ':' in address:
                address = '[' + address + ']'
            args = ['run', '--detach', '--name', identity.container, '--hostname', identity.container,
                *self._labels(identity), '--label', LABEL_PREFIX + 'topology=' + topology_digest(profile, paths),
                '--label', LABEL_PREFIX + 'image-id=' + image['Id'],
                '--userns=keep-id', '--user', f'{self.host.uid}:{self.host.gid}', '--cap-drop=all',
                '--security-opt=no-new-privileges', '--network=slirp4netns:allow_host_loopback=false',
                '--pid=private', '--ipc=private', '--pids-limit', str(profile.resources.pids_limit),
                '--init', '--shm-size=512m', '--stop-timeout=30', '--publish', f'{address}:{profile.server.port}:3773',
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
        self._wait_ready(identity)
        print('T3 endpoint: ' + self._endpoint(profile) + ' (ready)')

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
            with storage.mutation_lock(paths):
                if command in ('build', 'rebuild'):
                    self._build(profile, identity, command == 'rebuild')
                elif command in ('stop', 'remove'):
                    (self._remove if command == 'remove' else self._stop)(identity)
                else:
                    self._validate_start(profile, paths)
                    if command == 'restart':
                        resource = self._owned(identity)
                        if resource:
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
