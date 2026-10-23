"""Restricted startup: real lifecycle/policy/filesystem with only engine I/O faked."""
from copy import deepcopy
import json
import os
from pathlib import Path
import subprocess
import threading
import time
import unittest
from unittest.mock import patch

from support import ProfileFixture
from t3_sandbox.network import IsolationError, check_routes
from t3_sandbox.launcher import Launcher
from t3_sandbox.paths import ProfileIdentity, profile_paths
from t3_sandbox.podman import Podman, LABEL_PREFIX


def labels(identity, role):
    return {LABEL_PREFIX + k: v for k, v in dict(managed='true', uid=str(identity.uid),
            profile=identity.name, role=role).items()}


class NetworkEngine(Podman):
    def __init__(self, identity, host):
        self.identity, self.host = identity, host
        self.calls, self.containers, self.networks = [], {}, {}
        self.images = {identity.image: {'Id': 'sha256:t3', 'Config': {'Labels': {
            **labels(identity, 't3'), LABEL_PREFIX + 'gid': str(host.gid), LABEL_PREFIX + 'user': host.user}}},
            identity.proxy_image: {'Id': 'sha256:proxy', 'Config': {'Labels': labels(identity, 'proxy')}}}
        self.bridge_addresses = [{'family': 'inet6', 'local': 'fe80::1234', 'prefixlen': 64}]
        self.hardening_fails = self.route_default = self.bad_ready = self.external_ipv6 = False
        self.backend, self.resolvers = 'netavark', 'nameserver 9.9.9.9\n'

    def run(self, args, *, check=True, timeout=30, capture=True):
        a = list(args)
        self.calls.append(a)
        output, code = '', 0
        stores = {'container': self.containers, 'network': self.networks, 'image': self.images}
        if len(a) > 1 and a[1] == 'exists':
            code = 0 if a[-1] in stores[a[0]] else 1
        elif len(a) > 1 and a[1] == 'inspect':
            output = json.dumps([stores[a[0]][a[-1]]])
        elif a[0] == 'info':
            output = 'true' if a[-1] == '{{.Host.Security.Rootless}}' else json.dumps({
                'host': {'security': {'rootless': True}, 'networkBackend': self.backend, 'serviceIsRemote': False}})
        elif a[0] == 'ps':
            output = json.dumps([{'Id': name} for name in self.containers])
        elif a[:2] == ['network', 'create']:
            name, internal = a[-1], '--internal' in a
            self.networks[name] = {'name': name, 'id': name, 'driver': 'bridge',
                'network_interface': 'podman91' if internal else 'podman92', 'internal': internal,
                'dns_enabled': False, 'ipv6_enabled': False,
                'subnets': [{'subnet': '10.230.1.0/24' if internal else '10.230.2.0/24',
                             **({} if internal else {'gateway': '10.230.2.1'})}],
                'labels': dict(item.split('=', 1) for i, item in enumerate(a) if i and a[i-1] == '--label')}
            if not internal and self.external_ipv6:
                self.networks[name]['subnets'].append({'subnet': 'fd00::/64'})
        elif a[:2] == ['network', 'rm']:
            del self.networks[a[-1]]
        elif a[0] == 'unshare':
            if 'sysctl' in a:
                if '-w' in a:
                    if self.hardening_fails:
                        code = 1
                    else:
                        self.bridge_addresses = []
                output = '1'
            elif 'cat' in a:
                output = self.resolvers
            elif 'ip' in a:
                output = json.dumps([{'addr_info': self.bridge_addresses}]) if 'dev' in a else json.dumps([
                    {'addr_info': [{'family': 'inet', 'local': '192.168.1.22'},
                                   {'family': 'inet6', 'local': '2001:db8::22'}]}])
        elif a[0] == 'run' and 'validate' in a:
            source = next(field[4:] for field in a[a.index('--mount') + 1].split(',') if field.startswith('src='))
            output = json.dumps({'digest': json.loads((Path(source) / 'active.json').read_bytes())['digest']})
        elif a[0] == 'run':
            name, nets = a[a.index('--name') + 1], {}
            for i, item in enumerate(a):
                net = item.split('=', 1)[1] if item.startswith('--network=') else (a[i+1] if item == '--network' else None)
                if net:
                    fields = net.split(':', 1)
                    netname = fields[0]
                    addr = '10.230.2.2' if netname.endswith('-external') else '10.230.1.4'
                    if len(fields) > 1:
                        addr = fields[1].split('ip=')[-1].split(',')[0]
                    if '--ip' in a:
                        addr = a[a.index('--ip')+1]
                    nets[netname] = {'IPAddress': addr, 'GlobalIPv6Address': '', 'Aliases': None,
                                     'InterfaceName': 'eth' + str(len(nets))}
            mounts = []
            for i, item in enumerate(a):
                if item == '--mount':
                    fields = a[i+1].split(',')
                    values = dict(field.split('=', 1) for field in fields if '=' in field)
                    mounts.append({'Type': 'bind', 'Source': values['src'], 'Destination': values['dst'], 'RW': 'ro' not in fields})
            bindings = {}
            if '--publish' in a:
                bind, port, dest = a[a.index('--publish')+1].rsplit(':', 2)
                bindings[dest + '/tcp'] = [{'HostIp': bind, 'HostPort': port}]
            image = next((item for item in a if item in self.images), None)
            self.containers[name] = {'Id': name, 'Name': name, 'Image': self.images[image]['Id'],
                'Config': {'Labels': dict(item.split('=', 1) for i, item in enumerate(a) if i and a[i-1] == '--label'),
                           'Env': [a[i+1] for i,v in enumerate(a) if v == '--env'],
                           'User': '0:0' if name.endswith('-proxy') else f'{self.host.uid}:{self.host.gid}'},
                'HostConfig': {'Tmpfs': dict(a[i+1].replace(',notmpcopyup', '').split(':', 1) for i,v in enumerate(a) if v == '--tmpfs'), 'PortBindings': bindings, 'NetworkMode': next(iter(nets)), 'PidMode': 'private',
                    'IpcMode': 'private', 'Privileged': False, 'SecurityOpt': ['no-new-privileges'],
                    'CapAdd': ['CAP_NET_ADMIN','CAP_SETUID','CAP_SETGID','CAP_SETPCAP','CAP_CHOWN'] if name.endswith('-proxy') else [],
                    'CapDrop': [], 'Dns': [], 'ExtraHosts': [],
                    'UsernsMode': 'private', 'IDMappings': {
                        'UidMap': [f'{2003 if name.endswith("-proxy") else self.host.uid}:0:1'],
                        'GidMap': [f'{2003 if name.endswith("-proxy") else self.host.gid}:0:1']}},
                'BoundingCaps': ['CAP_NET_ADMIN','CAP_SETUID','CAP_SETGID','CAP_SETPCAP','CAP_CHOWN'] if name.endswith('-proxy') else [],
                'ResolvConfPath': '', 'HostsPath': '',
                'NetworkSettings': {'Networks': nets}, 'Mounts': mounts, 'State': {'Running': True, 'Pid': 123}}
            output = name
        elif a[0] in ('start', 'stop'):
            self.containers[a[-1]]['State']['Running'] = a[0] == 'start'
            if a[-1] == self.identity.container:
                for net in self.containers[a[-1]]['NetworkSettings']['Networks'].values():
                    net['IPAddress'] = '10.230.1.3' if a[0] == 'start' else ''
        elif a[0] == 'rm':
            del self.containers[a[-1]]
        elif a[0] == 'exec':
            if '/run/t3-proxy/ready.json' in a:
                if self.bad_ready:
                    output = '{}'
                    self.containers[a[1]]['State']['Running'] = False
                else:
                    source = next(m['Source'] for m in self.containers[a[1]]['Mounts'] if m['Destination'] == '/run/t3-policy')
                    output = json.dumps({'digest': json.loads((Path(source) / 'active.json').read_bytes())['digest']})
            elif any(arg in ('python3', '/usr/bin/python3') for arg in a):
                if 'forwarding' in a[-1]:
                    output = json.dumps({'forwarding': [0, 0, 0], 'capabilities': [0, 0, 0, 0, 0], 'nnp': 1})
                else:
                    output = json.dumps({'ipv4': [{'destination': '00000000', 'interface': 'eth0'}] if a[1].endswith('-proxy') else ([{'destination': '00000000', 'interface': 'eth0'}] if self.route_default else []), 'ipv6': [], 'interfaces': {'10.230.2.2': 'eth0'}})
        result = subprocess.CompletedProcess(a, code, output, 'simulated unsupported host/runtime' if code else '')
        if check:
            result.check_returncode()
        return result


class LocalRouteExec(Podman):
    """Execute the real probe command; fake only the container and kernel data.

    A real subprocess preserves interpreter selection, import order, working
    directory and environment behavior. The trusted fixture prefix replaces
    only reads of the two kernel route tables with a forbidden default route.
    """
    ROUTE_TABLE = """import builtins, io
original_open = builtins.open
def fixture_open(path, *args, **kwargs):
 if path == '/proc/net/route':
  return io.StringIO('Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\\neth0 00000000 0100000A 0003 0 0 0 00000000 0 0 0\\n')
 if path == '/proc/net/ipv6_route':
  return io.StringIO('')
 return original_open(path, *args, **kwargs)
builtins.open = fixture_open
"""

    def __init__(self, cwd, environment):
        self.cwd, self.environment = cwd, environment

    def run(self, args, *, check=True, timeout=30, capture=True):
        command = list(args[2:])  # Replace only the external podman exec boundary.
        script_index = command.index('-c') + 1
        command[script_index] = self.ROUTE_TABLE + command[script_index]
        return subprocess.run(command, cwd=self.cwd, env=self.environment,
                              check=check, timeout=timeout, capture_output=capture, text=True)


class RouteInspectionTrustTests(unittest.TestCase):
    def setUp(self):
        self.f = self.enterContext(ProfileFixture())
        self.project = self.f.root / 'project'
        self.project.mkdir()
        self.environment = dict(os.environ, PATH='/usr/bin:/bin')
        self.environment.pop('PYTHONPATH', None)
        self.environment.pop('PYTHONHOME', None)
        self.marker = self.f.root / 'untrusted-code-ran'

    def assert_real_default_is_rejected(self):
        with self.assertRaisesRegex(IsolationError, 'default route'):
            check_routes(LocalRouteExec(self.project, self.environment), 'workload')
        self.assertFalse(self.marker.exists(), 'Writable code ran during trusted route inspection')

    def malicious_module(self, directory, name):
        # If imported, lie about the routes and terminate successfully before
        # the actual probe reads /proc. The host must reject the real default.
        forged = '{"ipv4":[],"ipv6":[],"interfaces":{}}'
        (directory / (name + '.py')).write_text(
            'import os\n'
            f'open({str(self.marker)!r}, "w").write("untrusted import")\n'
            f'print({forged!r}, flush=True)\n'
            'os._exit(0)\n')

    def test_route_check_ignores_writable_path_python_wrapper(self):
        binary = self.f.root / 'home-bin'
        binary.mkdir()
        wrapper = binary / 'python3'
        wrapper.write_text('#!/bin/sh\nprintf wrapper > "' + str(self.marker) + '"\n'
                           "printf '%s\\n' '{\"ipv4\":[],\"ipv6\":[],\"interfaces\":{}}'\n")
        wrapper.chmod(0o755)
        self.environment['PATH'] = str(binary) + ':/usr/bin:/bin'
        self.assert_real_default_is_rejected()

    def test_route_check_ignores_project_json_and_socket_modules(self):
        for module in ('json', 'socket'):
            with self.subTest(module=module):
                self.malicious_module(self.project, module)
                try:
                    self.assert_real_default_is_rejected()
                finally:
                    (self.project / (module + '.py')).unlink()
                    self.marker.unlink(missing_ok=True)

    def test_route_check_ignores_pythonpath_startup_hooks(self):
        imports = self.f.root / 'pythonpath'
        imports.mkdir()
        self.malicious_module(imports, 'sitecustomize')
        self.environment['PYTHONPATH'] = str(imports)
        self.assert_real_default_is_rejected()

    def test_route_check_ignores_spoofed_pythonhome_and_pythonpath(self):
        self.environment['PYTHONHOME'] = str(self.f.root / 'fake-python-home')
        self.environment['PYTHONPATH'] = str(self.project)
        self.malicious_module(self.project, 'json')
        self.assert_real_default_is_rejected()


class RestrictedNetworkTests(unittest.TestCase):
    def setUp(self):
        self.f = self.enterContext(ProfileFixture())
        self.f.load('work', {'server': {'port': 3774}, 'network': {'restricted': True}})
        self.identity = ProfileIdentity('work', self.f.host.uid)
        self.paths = profile_paths(self.identity, self.f.profile_dir, self.f.host)
        self.fake = NetworkEngine(self.identity, self.f.host)
        self.launcher = Launcher(self.fake, self.f.host, self.f.profile_dir)

    def start(self):
        return self.launcher.dispatch('start', 'work')

    def mutations(self):
        return [a for a in self.fake.calls if a[0] in ('run', 'start') or a[:2] == ['network', 'create']]

    def test_bridge_hardened_before_only_private_t3_launch(self):
        self.start()
        runs = [a for a in self.fake.calls if a[0] == 'run']
        t3 = next(a for a in runs if a[a.index('--name')+1] == self.identity.container)
        gateway = next(a for a in runs if a[a.index('--name')+1] == self.identity.proxy)
        self.assertEqual(set(self.fake.containers[self.identity.container]['NetworkSettings']['Networks']), {self.identity.private_network})
        self.assertIn('0.0.0.0:3774:3773', gateway)
        self.assertNotIn('--publish', t3)
        self.assertFalse(any(':3128' in value for value in gateway))
        disable = next(i for i, a in enumerate(self.fake.calls) if 'sysctl' in a and '-w' in a)
        self.assertLess(disable, self.fake.calls.index(t3))
        self.assertEqual(self.fake.bridge_addresses, [])
        self.assertTrue(any(a[0] == 'exec' and a[1] == self.identity.container and '/usr/bin/python3' in a for a in self.fake.calls))

    def test_gateway_has_only_policy_and_logs_and_drops_initial_caps(self):
        self.start()
        gateway = self.fake.containers[self.identity.proxy]
        self.assertEqual({m['Destination'] for m in gateway['Mounts']}, {'/run/t3-policy', '/var/log/t3-proxy'})
        self.assertFalse(next(m for m in gateway['Mounts'] if m['Destination'] == '/run/t3-policy')['RW'])
        run = next(a for a in self.fake.calls if a[0] == 'run' and a[a.index('--name')+1] == self.identity.proxy)
        self.assertNotIn('--init', run)
        self.assertIn('--userns=keep-id:uid=2003,gid=2003', run)
        self.assertIn('--cap-add=NET_ADMIN,SETUID,SETGID,SETPCAP,CHOWN', run)
        for path, mode in ((self.paths.logs, 0o700), (self.paths.runtime / 'policy', 0o755), (self.paths.runtime / 'policy/active.json', 0o644)):
            self.assertEqual(path.stat().st_mode & 0o777, mode)
        topology = json.loads((self.paths.runtime / 'topology.json').read_text())
        self.assertEqual(topology['policy_digest'], json.loads((self.paths.runtime / 'policy/active.json').read_text())['digest'])

    def test_ipv4_addressed_bridge_is_rejected_before_t3_start(self):
        self.fake.bridge_addresses.append({'family': 'inet', 'local': '10.230.1.1'})
        with self.assertRaisesRegex(ValueError, 'IPv4|addressed'):
            self.start()
        self.assertNotIn(self.identity.container, self.fake.containers)
        self.assertFalse(self.fake.networks)

    def test_bridge_hardening_failure_never_falls_back(self):
        self.fake.hardening_fails = True
        with self.assertRaisesRegex(ValueError, 'Unsupported|unsupported|hardening'):
            self.start()
        self.assertFalse(self.fake.containers)
        self.assertFalse(self.fake.networks)

    def test_unowned_name_collision_is_rejected_before_mutations(self):
        self.fake.networks[self.identity.external_network] = {'labels': {}}
        with self.assertRaisesRegex(ValueError, 'unowned'):
            self.start()
        self.assertEqual(self.mutations(), [])

    def test_unexpected_network_member_prevents_reuse(self):
        self.start()
        self.fake.containers['unrelated'] = deepcopy(self.fake.containers[self.identity.container])
        self.fake.containers['unrelated']['Id'] = 'unrelated'
        self.fake.containers['unrelated']['Name'] = 'unrelated'
        with self.assertRaisesRegex(ValueError, 'member'):
            self.start()
        self.assertIn('unrelated', self.fake.containers)

    def test_proxy_precedes_t3_and_cleanup_is_owned_only(self):
        self.fake.route_default = True
        with self.assertRaisesRegex(ValueError, 'default route'):
            self.start()
        self.assertFalse(self.fake.containers)
        self.assertFalse(self.fake.networks)
        self.assertFalse(any(a[0] == 'run' and a[a.index('--name')+1] == self.identity.container for a in self.fake.calls))
        self.assertFalse(any('prune' in a for a in self.fake.calls))

    def test_new_workload_route_mismatch_removes_it_without_touching_existing_gateway(self):
        self.start()
        del self.fake.containers[self.identity.container]
        run = self.fake.run
        def workload_default(args, **kwargs):
            result = run(args, **kwargs)
            if args[0] == 'exec' and args[1] == self.identity.container and '/usr/bin/python3' in args:
                result.stdout = json.dumps({'ipv4': [{'destination': '00000000', 'interface': 'eth0'}], 'ipv6': []})
            return result
        self.fake.run = workload_default
        with self.assertRaisesRegex(ValueError, 'default route'):
            self.start()
        self.assertNotIn(self.identity.container, self.fake.containers)
        self.assertTrue(self.fake.containers[self.identity.proxy]['State']['Running'])
        self.assertEqual(len(self.fake.networks), 2)

    def test_failure_removes_new_workload_before_stopping_restarted_gateway(self):
        self.start()
        del self.fake.containers[self.identity.container]
        self.fake.containers[self.identity.proxy]['State']['Running'] = False
        run = self.fake.run
        def workload_default(args, **kwargs):
            result = run(args, **kwargs)
            if args[0] == 'exec' and args[1] == self.identity.container and '/usr/bin/python3' in args:
                result.stdout = json.dumps({'ipv4': [{'destination': '00000000', 'interface': 'eth0'}], 'ipv6': []})
            return result
        self.fake.run = workload_default
        self.fake.calls.clear()
        with self.assertRaisesRegex(ValueError, 'default route'):
            self.start()
        cleanup = [a for a in self.fake.calls if a[0] in ('rm', 'stop') and a[-1] in (self.identity.container, self.identity.proxy)]
        self.assertEqual([a[-1] for a in cleanup], [self.identity.container, self.identity.proxy])
        self.assertFalse(self.fake.containers[self.identity.proxy]['State']['Running'])
        self.assertNotIn(self.identity.container, self.fake.containers)

    def test_restart_rechecks_recreated_bridge(self):
        self.start()
        count = sum('sysctl' in a and '-w' in a for a in self.fake.calls)
        self.fake.bridge_addresses = [{'family': 'inet6', 'local': 'fe80::5678'}]
        self.launcher.dispatch('restart', 'work')
        self.assertGreater(sum('sysctl' in a and '-w' in a for a in self.fake.calls), count)
        self.assertEqual(self.fake.bridge_addresses, [])

    def test_policy_change_and_topology_change_report_different_actions(self):
        self.start()
        self.f.write('work', {'network': {'allow': {'domains': ['example.com']}}})
        with self.assertRaisesRegex(ValueError, 'proxy-restart'):
            self.start()
        self.f.write('work', {'server': {'port': 3775}})
        with self.assertRaisesRegex(ValueError, 'recreate'):
            self.start()

    def test_invalid_readiness_never_starts_t3(self):
        self.fake.bad_ready = True
        with self.assertRaisesRegex(ValueError, 'readiness|ready|exited'):
            self.start()
        self.assertFalse(self.fake.containers)

    def test_unsupported_runtime_and_ipv6_topology_fail_closed(self):
        self.fake.backend = 'cni'
        with self.assertRaisesRegex(ValueError, 'Unsupported|unsupported|Netavark'):
            self.start()
        self.assertEqual(self.mutations(), [])
        self.fake.backend = 'netavark'
        self.fake.external_ipv6 = True
        with self.assertRaisesRegex(ValueError, 'IPv4|IPv6'):
            self.start()
        self.assertFalse(self.fake.containers)
        self.assertFalse(self.fake.networks)

    def test_ipv6_resolver_rejected_before_mutations(self):
        self.fake.resolvers = 'nameserver 2001:4860:4860::8888\n'
        with self.assertRaisesRegex(ValueError, 'IPv4|IPv6'):
            self.start()
        self.assertEqual(self.mutations(), [])

    def test_reuse_accepts_podman_empty_ipv4_wildcard_binding(self):
        self.start()
        self.fake.containers[self.identity.proxy]['HostConfig']['PortBindings']['3773/tcp'][0]['HostIp'] = ''
        self.start()

    def test_reuse_checks_actual_image_mounts_ports_and_memberships(self):
        self.start()
        for mutate in (
                lambda c: c.update(Image='sha256:wrong'),
                lambda c: c.update(BoundingCaps=['CAP_SYS_ADMIN']),
                lambda c: c['HostConfig']['IDMappings'].update(UidMap=['0:0:65536']),
                lambda c: c['Mounts'].append({'Type': 'bind', 'Source': '/tmp', 'Destination': '/oops', 'RW': True}),
                lambda c: c['HostConfig'].update(PortBindings={'3128/tcp': [{'HostIp': '0.0.0.0', 'HostPort': '3128'}]}),
                lambda c: c['NetworkSettings']['Networks'].update(unexpected={'IPAddress': '10.1.1.2'})):
            original = deepcopy(self.fake.containers[self.identity.proxy])
            mutate(self.fake.containers[self.identity.proxy])
            with self.assertRaises(ValueError):
                self.start()
            self.fake.containers[self.identity.proxy] = original

    def test_network_membership_inspection_rejects_malformed_container_listing(self):
        run = self.fake.run
        def malformed(args, **kwargs):
            if args[0] == 'ps' and '--filter' not in args:
                return subprocess.CompletedProcess(args, 0, '[{}]', '')
            return run(args, **kwargs)
        self.fake.run = malformed
        with self.assertRaisesRegex(ValueError, 'listing'):
            self.start()
        self.assertFalse(self.fake.containers)

    def test_new_owned_bridge_addresses_do_not_invalidate_topology_on_reuse(self):
        run = self.fake.run
        def with_materialized_bridge(args, **kwargs):
            result = run(args, **kwargs)
            if args[:2] == ['unshare', '--rootless-netns'] and args[-3:] == ['ip', '-j', 'addr'] and self.identity.proxy in self.fake.containers:
                result.stdout = json.dumps(json.loads(result.stdout) + [{'ifname': 'podman92',
                    'addr_info': [{'family': 'inet', 'local': '10.230.2.1'}, {'family': 'inet6', 'local': 'fe80::99'}]}, {'ifname': 'veth123', 'addr_info': [{'family': 'inet6', 'local': 'fe80::abcd'}]}])
            return result
        self.fake.run = with_materialized_bridge
        self.start()
        self.start()

    def test_other_profile_private_addresses_do_not_invalidate_proxy_restart(self):
        self.fake.images.update({resource['Id']: resource for resource in self.fake.images.copy().values()})
        run = self.fake.run
        addresses = []
        def with_other_profile(args, **kwargs):
            result = run(args, **kwargs)
            if args[:2] == ['unshare', '--rootless-netns'] and args[-3:] == ['ip', '-j', 'addr']:
                result.stdout = json.dumps(json.loads(result.stdout) + [{'ifname': 'podman999',
                    'addr_info': [{'local': address} for address in addresses]}])
            return result
        self.fake.run = with_other_profile
        self.start()
        with patch('t3_sandbox.launcher.subprocess.run', return_value=subprocess.CompletedProcess([], 0)):
            addresses.extend(['10.231.12.1', 'fd00::1234', '::ffff:10.231.12.1'])
            self.launcher.proxy_restart('work')
            addresses.clear()
            self.launcher.proxy_restart('work')

    def test_new_public_host_addresses_still_reject_proxy_restart_before_stop(self):
        self.fake.images.update({resource['Id']: resource for resource in self.fake.images.copy().values()})
        run = self.fake.run
        addresses = []
        def with_public_host(args, **kwargs):
            result = run(args, **kwargs)
            if args[:2] == ['unshare', '--rootless-netns'] and args[-3:] == ['ip', '-j', 'addr']:
                result.stdout = json.dumps(json.loads(result.stdout) + [{'ifname': 'public0',
                    'addr_info': [{'local': address} for address in addresses]}])
            return result
        self.fake.run = with_public_host
        self.start()
        for address in ('93.184.216.34', '2606:4700:4700::1111'):
            addresses[:] = [address]
            self.fake.calls.clear()
            with self.subTest(address=address), self.assertRaisesRegex(ValueError, 'topology changed'):
                self.launcher.proxy_restart('work')
            self.assertFalse(any(call[0] == 'stop' for call in self.fake.calls))

    def test_two_profiles_cannot_reuse_one_shared_t3_state(self):
        self.f.write('work', {'state': {'share_host_t3_state': True}})
        self.start()
        other = ProfileIdentity('other', self.f.host.uid)
        self.f.write('other', {'server': {'port': 3775}, 'network': {'restricted': True},
                               'state': {'share_host_t3_state': True}})
        with self.assertRaisesRegex(ValueError, 'already in use'):
            self.launcher.dispatch('start', 'other')
        self.assertNotIn(other.container, self.fake.containers)

    def test_gateway_routes_use_live_address_mapping_without_inspect_interface_names(self):
        run = self.fake.run
        def without_names(args, **kwargs):
            result = run(args, **kwargs)
            if list(args)[:2] == ['container', 'inspect']:
                values = json.loads(result.stdout)
                for net in values[0].get('NetworkSettings', {}).get('Networks', {}).values():
                    net.pop('InterfaceName', None)
                result.stdout = json.dumps(values)
            return result
        self.fake.run = without_names
        self.start()
        self.assertTrue(self.fake.containers[self.identity.container]['State']['Running'])

    def test_profile_mutations_are_serialized(self):
        entered, release, finished = threading.Event(), threading.Event(), threading.Event()
        run = self.fake.run
        errors = []
        def blocked(args, **kwargs):
            if args[0] == 'run' and args[args.index('--name')+1] == self.identity.proxy:
                entered.set()
                release.wait(3)
            return run(args, **kwargs)
        self.fake.run = blocked
        def start(done=None):
            try:
                self.start()
            except Exception as exc:
                errors.append(exc)
            finally:
                if done: done.set()
        first = threading.Thread(target=start)
        second = threading.Thread(target=start, args=(finished,))
        first.start()
        self.assertTrue(entered.wait(3))
        second.start()
        try:
            self.assertFalse(finished.wait(0.15))
        finally:
            release.set()
            first.join(5)
            second.join(5)
        self.assertEqual(errors, [])

    def test_shared_state_startups_hold_a_cross_profile_state_lock(self):
        self.f.write('work', {'state': {'share_host_t3_state': True}})
        self.f.write('other', {'server': {'port': 3775}, 'network': {'restricted': True},
                               'state': {'share_host_t3_state': True}})
        other = ProfileIdentity('other', self.f.host.uid)
        for name, role in ((other.image, 't3'), (other.proxy_image, 'proxy')):
            self.fake.images[name] = deepcopy(self.fake.images[self.identity.image if role == 't3' else self.identity.proxy_image])
            self.fake.images[name]['Config']['Labels'].update(labels(other, role))
        entered, release, finished = threading.Event(), threading.Event(), threading.Event()
        run, errors = self.fake.run, []
        def blocked(args, **kwargs):
            if args[0] == 'run' and args[args.index('--name')+1] == self.identity.proxy:
                entered.set()
                release.wait(3)
            return run(args, **kwargs)
        self.fake.run = blocked
        def start(name, done=None):
            try:
                self.launcher.dispatch('start', name)
            except Exception as exc:
                errors.append(exc)
            finally:
                if done: done.set()
        first = threading.Thread(target=start, args=('work',))
        second = threading.Thread(target=start, args=('other', finished))
        first.start()
        self.assertTrue(entered.wait(3))
        second.start()
        try:
            self.assertFalse(finished.wait(0.15), 'Second profile passed sharing preflight while first was starting')
        finally:
            release.set()
            first.join(5)
            second.join(5)
        self.assertEqual(len(errors), 1)
        self.assertIn('already in use', str(errors[0]))
        self.assertNotIn(other.container, self.fake.containers)

    def test_stop_remove_order_preserves_host_state(self):
        self.start()
        marker = self.paths.home / 'keep'
        marker.write_text('persist')
        self.fake.calls.clear()
        self.launcher.dispatch('remove', 'work')
        self.assertEqual([a[-1] for a in self.fake.calls if a[0] == 'stop'], [self.identity.container, self.identity.proxy])
        self.assertEqual(marker.read_text(), 'persist')
        self.assertTrue(self.paths.logs.exists())
        self.assertFalse(self.fake.containers)
        self.assertFalse(self.fake.networks)

    def test_reuse_rejects_gateway_tmpfs_shadowing_trusted_runtime(self):
        self.start()
        for representation in ('mounts', 'host_config', 'both'):
            with self.subTest(representation=representation):
                original = deepcopy(self.fake.containers[self.identity.proxy])
                gateway = self.fake.containers[self.identity.proxy]
                if representation in ('mounts', 'both'):
                    gateway['Mounts'].append({'Type': 'tmpfs', 'Source': 'tmpfs',
                                              'Destination': '/usr/local/lib/t3-proxy', 'RW': True})
                if representation in ('host_config', 'both'):
                    gateway['HostConfig']['Tmpfs'] = {'/usr/local/lib/t3-proxy': 'rw,exec'}
                try:
                    with self.assertRaisesRegex(ValueError, 'recreate|mount'):
                        self.start()
                finally:
                    self.fake.containers[self.identity.proxy] = original

    def test_reuse_rejects_t3_tmpfs_outside_validated_browser_cache(self):
        self.start()
        for representation in ('mounts', 'host_config', 'both'):
            with self.subTest(representation=representation):
                original = deepcopy(self.fake.containers[self.identity.container])
                workload = self.fake.containers[self.identity.container]
                if representation in ('mounts', 'both'):
                    workload['Mounts'].append({'Type': 'tmpfs', 'Source': 'tmpfs',
                                               'Destination': '/opt/t3-runtime', 'RW': True})
                if representation in ('host_config', 'both'):
                    workload['HostConfig']['Tmpfs']['/opt/t3-runtime'] = 'rw,exec'
                try:
                    with self.assertRaisesRegex(ValueError, 'recreate|mount|browser'):
                        self.start()
                finally:
                    self.fake.containers[self.identity.container] = original

    def test_browser_environment_validation_allows_owned_stopped_gateway(self):
        self.start()
        proxy = self.fake.containers[self.identity.proxy]
        proxy['State']['Running'] = False
        proxy['NetworkSettings']['Networks'][self.identity.private_network]['IPAddress'] = ''
        try:
            self.launcher._check_browser_runtime(self.f.load('work'), self.fake.containers[self.identity.container])
        except ValueError as exc:
            self.fail('Owned stopped gateway must permit proxy recovery: ' + str(exc))
        # A stopped gateway still cannot make its own environment authoritative.
        self.fake.containers[self.identity.container]['Config']['Env'] = ['HTTP_PROXY=http://wrong:3128']
        with self.assertRaisesRegex(ValueError, 'proxy|browser'):
            self.launcher._check_browser_runtime(self.f.load('work'), self.fake.containers[self.identity.container])

    def test_reuse_rejects_missing_browser_tmpfs_and_changed_proxy_environment(self):
        self.start()
        for mutate in (
                lambda c: c['HostConfig'].update(Tmpfs={}),
                lambda c: c['HostConfig'].update(Tmpfs={'/home/testuser/.t3/tools/chrome-headless-shell': 'rw,nosuid,nodev,noexec,mode=1777'}),
                lambda c: c['Config'].update(Env=['HTTP_PROXY=http://wrong:3128']),
                lambda c: c['Config']['Env'].append('NO_PROXY=*')):
            original = deepcopy(self.fake.containers[self.identity.container])
            mutate(self.fake.containers[self.identity.container])
            with self.assertRaisesRegex(ValueError, 'recreate|proxy|browser'):
                self.start()
            self.fake.containers[self.identity.container] = original


if __name__ == '__main__':
    unittest.main()
