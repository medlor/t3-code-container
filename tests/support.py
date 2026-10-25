"""Temporary host/profile fixtures; never use real user state."""
from copy import deepcopy
from pathlib import Path
import json
import os
import tempfile
from unittest.mock import patch

import yaml


class ProfileFixture:
    def __enter__(self):
        from t3_sandbox.paths import HostContext
        self.temp = tempfile.TemporaryDirectory(prefix="t3-profile-test-")
        self.root = Path(self.temp.name)
        self.host = HostContext(self.root / "host", 1234, 2345, "testuser")
        self.host.home.mkdir()
        self.profile_dir = self.root / "profiles"
        return self

    def __exit__(self, *args):
        self.temp.cleanup()

    def write(self, name, overrides):
        def merge(base, updates):
            for key, value in updates.items():
                if isinstance(value, dict) and isinstance(base.get(key), dict):
                    merge(base[key], value)
                else:
                    base[key] = deepcopy(value)
            return base
        path = self.profile_dir / f"{name}.yaml"
        self.profile_dir.mkdir(parents=True, exist_ok=True)
        base = yaml.safe_load(path.read_text()) if path.exists() else {"version": 1}
        path.write_text(yaml.safe_dump(merge(base, overrides), sort_keys=False))
        return path

    def load(self, name, overrides=None):
        from t3_sandbox.profiles import load_profile
        if overrides is not None:
            self.write(name, overrides)
        return load_profile(name, self.profile_dir, self.host)


# A JSON-backed extension of the launcher command recorder. All resources and
# mutations are confined to the fixture; it never contacts a Podman service.
FAKE_JSON_PODMAN = '''#!/usr/bin/python3
import json, os, sys, time
a = sys.argv[1:]
with open(os.environ['CALL_LOG'], 'a') as stream:
    stream.write(json.dumps(a) + '\\n')
state = json.load(open(os.environ['PODMAN_STATE']))
if 'sleep' in state: time.sleep(state['sleep'])
if 'failure' in state:
    print(state['failure'], file=sys.stderr)
    sys.exit(125)
if len(a) >= 2 and a[1] == 'exists':
    sys.exit(0 if a[-1] in state.get(a[0], {}) else 1)
if len(a) >= 2 and a[1] == 'inspect':
    value = state.get(a[0], {}).get(a[-1])
    if value is None:
        print('no such resource', file=sys.stderr)
        sys.exit(125)
    print(state.get('inspect_output', json.dumps([value])))
elif a[0] == 'ps':
    print(json.dumps([{'Id': value['Id']} for value in state.get('container', {}).values()]))
elif a[0] == 'info':
    print('true')
elif a[0] == 'build':
    name = a[a.index('-t') + 1]
    labels = dict(item.split('=', 1) for i, item in enumerate(a) if i and a[i-1] == '--label')
    args = dict(item.split('=', 1) for i, item in enumerate(a) if i and a[i-1] == '--build-arg')
    if labels.get('io.t3-sandbox.role') == 't3':
        labels.update({'io.t3-sandbox.' + key: args['HOST_' + key.upper()] for key in ('uid', 'gid', 'user')})
    state.setdefault('image', {})[name] = {'Id': 'sha256:test-image', 'Config': {'Labels': labels}}
    json.dump(state, open(os.environ['PODMAN_STATE'], 'w'))
elif a[0] == 'run':
    name = a[a.index('--name') + 1]
    labels = dict(item.split('=', 1) for i, item in enumerate(a) if i and a[i-1] == '--label')
    mounts = []
    for i, item in enumerate(a):
        if i and a[i-1] == '--mount':
            fields = dict(pair.split('=', 1) for pair in item.split(','))
            mounts.append({'Type': 'bind', 'Source': fields['src'], 'Destination': fields['dst']})
    publish = a[a.index('--publish') + 1].rsplit(':', 2)
    state.setdefault('container', {})[name] = {'Id': name, 'Name': name, 'Image': 'sha256:test-image',
        'Config': {'Labels': labels, 'Env': [a[i+1] for i,v in enumerate(a) if v == '--env']}, 'Mounts': mounts,
        'HostConfig': {'Tmpfs': dict(a[i+1].replace(',notmpcopyup', '').split(':', 1) for i,v in enumerate(a) if v == '--tmpfs'), 'PortBindings': {'3773/tcp': [{'HostIp': publish[0], 'HostPort': publish[1]}]}},
        'State': {'Running': not state.get('exit_on_start', False), 'ExitCode': 78}}
    json.dump(state, open(os.environ['PODMAN_STATE'], 'w'))
    print(name)
elif a[0] in ('start', 'stop'):
    state['container'][a[-1]]['State']['Running'] = a[0] == 'start' and not state.get('exit_on_start', False)
    state['container'][a[-1]]['State']['ExitCode'] = 78
    json.dump(state, open(os.environ['PODMAN_STATE'], 'w'))
elif a[0] == 'exec':
    if 'pair' in a: print('Pairing URL: http://10.0.2.100:3773/#token=secret-token')
    if 'mktemp' in a:
        name = a[a.index('exec') + 1]
        source = next(m['Source'] for m in state['container'][name]['Mounts'] if m['Destination'] == '/workspace')
        probe = '.t3-permission-check.abcdefgh'
        open(os.path.join(source, probe), 'w').close()
        print('/workspace/' + probe)
elif a[0] in ('logs', 'port'): pass
elif a[0] == 'rm':
    state.get('container', {}).pop(a[-1], None)
    json.dump(state, open(os.environ['PODMAN_STATE'], 'w'))
else:
    print(json.dumps(a))
'''


class FakePodman:
    def __init__(self, root):
        self.root = root / 'fake-podman'
        self.root.mkdir()
        self.log = self.root / 'calls'
        self.state_file = self.root / 'state.json'
        self.state = {}

    def __enter__(self):
        executable = self.root / 'podman'
        executable.write_text(FAKE_JSON_PODMAN)
        executable.chmod(0o755)
        self.save()
        self.environment = patch.dict(os.environ, PATH=str(self.root) + ':' + os.environ.get('PATH', '/usr/bin:/bin'),
                                      CALL_LOG=str(self.log), PODMAN_STATE=str(self.state_file))
        self.environment.start()
        return self

    def __exit__(self, *args):
        self.environment.stop()

    def save(self):
        self.state_file.write_text(json.dumps(self.state))

    def calls(self):
        return [json.loads(line) for line in self.log.read_text().splitlines()] if self.log.exists() else []

    def add_container(self, name, *, uid='1234', profile='work', role='t3', managed='true', mounts=(), running=True):
        value = {'Id': name, 'Name': name, 'Config': {'Labels': {
            'io.t3-sandbox.managed': managed, 'io.t3-sandbox.uid': uid,
            'io.t3-sandbox.profile': profile, 'io.t3-sandbox.role': role}},
            'Mounts': list(mounts), 'State': {'Running': running}}
        self.state.setdefault('container', {})[name] = value
        self.save()
        return value

    def reload(self):
        self.state = json.loads(self.state_file.read_text())

    def last_t3_run(self):
        return next(call for call in reversed(self.calls()) if call[0] == 'run' and '--name' in call)

    def created_proxy_resources(self):
        return [call for call in self.calls() if call[:2] == ['network', 'create'] or (call[0] == 'run' and call[call.index('--name') + 1].endswith('-proxy')) or (call[0] == 'build' and 'code-proxy:' in call[call.index('-t') + 1])]
