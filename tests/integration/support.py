"""Disposable real-Podman acceptance fixtures, never the user's host state.

Every lifecycle transition is a production Launcher call. Extra engine calls
are bounded observations or explicitly owned adversarial test services.
"""
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import pwd
import signal
import select
import socket
import subprocess
import tempfile
import time
import uuid
from unittest.mock import patch
import urllib.request

import yaml

from t3_sandbox.launcher import Launcher, ROOT
from t3_sandbox.paths import HostContext, ProfileIdentity, profile_paths
from t3_sandbox.podman import Podman, assert_owned
from t3_sandbox.profiles import load_profile
from t3_sandbox import network

ENABLED = os.environ.get('T3_SANDBOX_INTEGRATION') == '1'
PROXY_KEYS = ('HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'NO_PROXY', 'http_proxy', 'https_proxy', 'all_proxy', 'no_proxy', 'NODE_USE_ENV_PROXY', 'T3_SANDBOX_BROWSER_PROXY')


@dataclass(frozen=True)
class ProxyResponse:
    status: int | None
    connect_status: int | None
    diagnostic: str = ''


@dataclass(frozen=True)
class CounterJob:
    path: str
    initial_count: int


def unused_port():
    with socket.socket() as sock:
        sock.bind(('0.0.0.0', 0))
        return sock.getsockname()[1]


def host_ipv4():
    result = subprocess.run(['ip', '-j', '-4', 'addr'], check=True, capture_output=True, text=True)
    return next(a['local'] for i in json.loads(result.stdout) for a in i['addr_info'] if a['scope'] == 'global')


class SandboxLab:
    def __init__(self, *, restricted=True, bridge_control=False, share_t3=False, share_providers=False):
        self.restricted, self.bridge_control = restricted, bridge_control
        self.share_t3, self.share_providers = share_t3, share_providers
        self.stack = ExitStack()
        self.processes = []
        self.extra_containers = []
        self.bridge_positive_control = None
        self.bridge_url = None

    def __enter__(self):
        if not ENABLED:
            raise RuntimeError('Real Podman tests require explicit T3_SANDBOX_INTEGRATION=1')
        self.temporary = tempfile.TemporaryDirectory(prefix='t3-integration-')
        self.root = Path(self.temporary.name)
        self.host = HostContext(self.root / 'host', os.getuid(), os.getgid(), pwd.getpwuid(os.getuid()).pw_name)
        self.host.home.mkdir()
        self.identity = ProfileIdentity('it-' + uuid.uuid4().hex[:12], self.host.uid)
        self.profile_dir = self.root / 'profiles'
        self.profile_dir.mkdir()
        self.file = self.profile_dir / (self.identity.name + '.yaml')
        self.port = unused_port()
        self.host_ipv4 = host_ipv4()
        self.podman = Podman()
        self.launcher = Launcher(self.podman, self.host, self.profile_dir)
        self.paths = profile_paths(self.identity, self.profile_dir, self.host)
        for leaf in ('.t3', '.codex', '.claude'):
            (self.host.home / leaf).mkdir()
            (self.host.home / leaf / 'fixture-marker').write_text(leaf)
        self.settings = {'version': 1, 'project': {'directory': str(self.root / 'project')},
            'server': {'bind_address': '0.0.0.0', 'port': self.port},
            'state': {'share_host_provider_state': self.share_providers, 'share_host_t3_state': self.share_t3},
            'network': {'restricted': self.restricted, 'allow': {'domains': ['example.com', 'api.openai.com'],
                'ips': ['127.0.0.1', '10.0.2.2', '192.168.1.1', '::1', 'fc00::1', 'fe80::1', '::ffff:127.0.0.1'], 'ports': [443]}}}
        self.update({})
        try:
            self.launcher.dispatch('build', self.identity.name)
            self.start_host_service()
            if self.bridge_control:
                original = network.harden_bridge
                def harden(engine, identity):
                    if identity == self.identity and self.bridge_url is None:
                        self.before_bridge_hardening()
                    return original(engine, identity)
                with patch.object(network, 'harden_bridge', harden):
                    self.launcher.dispatch('start', self.identity.name)
            else:
                self.launcher.dispatch('start', self.identity.name)
            if self.restricted:
                self.gateway = json.loads((self.paths.runtime / 'topology.json').read_text())['gateway']
            print('INTEGRATION fixture ' + self.identity.name + ' ready', flush=True)
            return self
        except BaseException:
            self.__exit__(None, None, None)
            raise

    def __exit__(self, *args):
        errors = []
        for proc in reversed(self.processes):
            try:
                os.killpg(proc.pid, signal.SIGTERM)
                proc.communicate(timeout=5)
            except ProcessLookupError:
                pass
            except subprocess.TimeoutExpired:
                os.killpg(proc.pid, signal.SIGKILL)
                proc.communicate(timeout=5)
        for name in reversed(self.extra_containers):
            resource = self.podman.inspect('container', name)
            if resource:
                assert_owned(resource, self.identity)
                self.podman.run(['rm', '--force', '--time=1', name])
        try:
            self.launcher.dispatch('remove', self.identity.name)
            for kind, names in [('container', (self.identity.container, self.identity.proxy)),
                                ('network', (self.identity.private_network, self.identity.external_network))]:
                for name in names:
                    if self.podman.inspect(kind, name) is not None:
                        errors.append(kind + ' ' + name)
            print('INTEGRATION cleanup ' + self.identity.name + ': ' + ('EMPTY' if not errors else repr(errors)), flush=True)
        finally:
            # Homes contain the actual host UID because the workload uses keep-id.
            # Only this freshly allocated, exact temporary root is eligible.
            # Podman may have created root-mapped mountpoint ancestors.
            if self.root.parent != Path(tempfile.gettempdir()) or not self.root.name.startswith('t3-integration-'):
                raise AssertionError('Refusing nonfixture cleanup')
            self.podman.run(['unshare', 'rm', '-rf', '--', str(self.root)])
            self.temporary.cleanup()
        if errors:
            raise AssertionError('Owned test resources remain: ' + ', '.join(errors))

    def update(self, values):
        def merge(base, incoming):
            for key, value in incoming.items():
                if isinstance(value, dict) and isinstance(base.get(key), dict):
                    merge(base[key], value)
                else:
                    base[key] = value
        merge(self.settings, values)
        self.file.write_text(yaml.safe_dump(self.settings))

    @property
    def profile(self):
        return load_profile(self.identity.name, self.profile_dir, self.host)

    def exec(self, args, *, check=True, clear_proxy=False, user=None, gateway=False):
        command = ['exec']
        if user:
            command += ['--user=' + user]
        command += [self.identity.proxy if gateway else self.identity.container]
        if clear_proxy:
            command += ['env', *('-u' + key for key in PROXY_KEYS)]
        return self.podman.run([*command, *args], check=check, timeout=30)

    def python(self, code, **kwargs):
        return self.exec(['/usr/bin/python3', '-I', '-S', '-c', code], **kwargs)

    def direct(self, url):
        return self.exec(['curl', '--noproxy', '*', '--connect-timeout', '1', '--max-time', '3', '-gsS', url], check=False, clear_proxy=True)

    def https_via_proxy(self, url):
        response = self.exec(['curl', '--noproxy', '', '--proxy', f"http://{self.gateway['private_ip']}:3128", '--connect-timeout', '12', '--max-time', '20', '-gsS', '-o', '/dev/null', '-w', '%{http_code} %{http_connect}', url], check=False)
        code, connect = response.stdout.strip().split()[-2:]
        return ProxyResponse(int(code) if code != '000' else None, int(connect) if connect != '000' else None, response.stderr)

    def socket_connect(self, host, port, *, gateway_user=None):
        result = self.python('import socket;socket.create_connection(' + repr((host, port)) + ',1).close()',
            user=gateway_user, gateway=gateway_user is not None, check=False, clear_proxy=True)
        return result.returncode == 0

    def t3_identity_and_start_time(self):
        resource = self.podman.inspect_owned('container', self.identity.container, self.identity)
        return resource['Id'], resource['State']['StartedAt']

    def start_local_counter_job(self):
        path = '/tmp/it-counter-' + uuid.uuid4().hex
        code = "import time\nfrom pathlib import Path\np=Path(" + repr(path) + ")\ni=0\nwhile True:\n i+=1;p.write_text(str(i));time.sleep(.1)"
        self.podman.run(['exec', '--detach', self.identity.container, '/usr/bin/python3', '-I', '-S', '-c', code])
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            result = self.exec(['cat', path], check=False)
            if result.returncode == 0:
                return CounterJob(path, int(result.stdout))
            time.sleep(.1)
        raise AssertionError('Counter job did not start')

    def counter(self, job):
        return int(self.exec(['cat', job.path]).stdout)

    def allow(self, domain):
        domains = self.settings['network']['allow']['domains']
        if domain not in domains:
            domains.append(domain)
        self.update({})

    def proxy_restart(self):
        return self.launcher.proxy_restart(self.identity.name)

    def start_process(self, args):
        proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
        self.processes.append(proc)
        return proc

    def read_port(self, proc):
        if not select.select([proc.stdout], [], [], 10)[0]:
            raise AssertionError('Owned service did not publish its port within ten seconds')
        value = proc.stdout.readline()
        if not value.strip().isdigit():
            raise AssertionError('Owned service exited before publishing a port: ' + proc.stderr.read()[-2000:])
        return int(value)

    def start_host_service(self):
        code = "from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer\nclass H(BaseHTTPRequestHandler):\n def do_GET(self):\n  self.send_response(200);self.end_headers();self.wfile.write(b'integration-host-service')\n def log_message(self,*a):pass\ns=ThreadingHTTPServer(('0.0.0.0',0),H);print(s.server_port,flush=True);s.serve_forever()"
        proc = self.start_process(['/usr/bin/python3', '-u', '-c', code])
        self.host_service_port = self.read_port(proc)

    def before_bridge_hardening(self):
        """Positive control and reversible owned fault: new bridge not hardened yet.

        Assert the eventual negative test fails here, while a trusted disposable
        client can still reach a host bridge IPv6 HTTP service. Then remove the
        client and let the original production hardener close this path.
        """
        code = "import socket\nfrom http.server import BaseHTTPRequestHandler,ThreadingHTTPServer\nclass H(BaseHTTPRequestHandler):\n def do_GET(self):\n  self.send_response(200);self.end_headers();self.wfile.write(b'integration-host-service')\n def log_message(self,*a):pass\nclass S(ThreadingHTTPServer):address_family=socket.AF_INET6\ns=S(('::',0),H);print(s.server_port,flush=True);s.serve_forever()"
        proc = self.start_process(['podman', 'unshare', '--rootless-netns', '/usr/bin/python3', '-u', '-c', code])
        port = self.read_port(proc)
        name = self.identity.container + '-bridge-control'
        self.extra_containers.append(name)
        self.podman.run(['run', '--detach', '--pull=never', '--name', name, *network.labels(self.identity, 'proxy'),
            '--userns=keep-id', '--user', f'{self.host.uid}:{self.host.gid}', '--cap-drop=all', '--security-opt=no-new-privileges',
            '--pid=private', '--ipc=private', '--no-healthcheck', '--network=' + self.identity.private_network,
            '--dns=none', '--no-hosts', '--entrypoint=/usr/bin/python3', self.identity.image, '-I', '-S', '-c', 'import time;time.sleep(90)'])
        for _ in range(30):
            info = self.bridge_info()
            candidates = [a['local'] for a in info['addr_info'] if a['family'] == 'inet6']
            if candidates:
                self.bridge_url = f'http://[{candidates[0]}%eth0]:{port}'
                result = self.podman.run(['exec', name, 'curl', '--noproxy', '*', '--connect-timeout', '1', '--max-time', '2', '-gsS', self.bridge_url], check=False)
                if result.returncode == 0:
                    self.bridge_positive_control = result.stdout
                    # This is the same boundary assertion used by the negative
                    # case; it MUST fail before production bridge hardening.
                    try:
                        assert result.returncode != 0, 'bridge IPv6 was reachable before hardening'
                    except AssertionError as expected:
                        print('INTEGRATION RED observed: ' + str(expected), flush=True)
                    else:
                        raise AssertionError('Owned fault was not detected')
                    break
            time.sleep(.2)
        if self.bridge_positive_control != 'integration-host-service':
            raise AssertionError('IPv6 pre-hardening positive control did not work')
        self.podman.run(['rm', '--force', '--time=1', name])

    def bridge_info(self):
        info = self.podman.inspect_owned('network', self.identity.private_network, self.identity)
        return json.loads(self.podman.run(['unshare', '--rootless-netns', 'ip', '-j', 'addr', 'show', 'dev', info['network_interface']]).stdout)[0]

    def bridge_ipv6_disabled(self):
        info = self.podman.inspect_owned('network', self.identity.private_network, self.identity)
        return self.podman.run(['unshare', '--rootless-netns', 'cat', '/proc/sys/net/ipv6/conf/' + info['network_interface'] + '/disable_ipv6']).stdout.strip()

    def gateway_listener(self):
        code = "import socket,time;s=socket.socket();s.bind(('0.0.0.0',0));s.listen();print(s.getsockname()[1],flush=True);time.sleep(90)"
        proc = self.start_process(['podman', 'exec', '--user=2003:2003', self.identity.proxy, '/usr/bin/python3', '-I', '-S', '-u', '-c', code])
        return self.read_port(proc)

    @contextmanager
    def controlled_dns(self, answer):
        """Own resolver seam; protected TCP rules are unchanged.

        Only Squid UDP to fixture loopback:53 and its paired input are added.
        Full production restart removes these rules/configuration in finally.
        """
        script = r"""import json,socket,struct,sys
from pathlib import Path
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('127.0.0.1',53));print(s.getsockname()[1],flush=True)
while True:
 data,peer=s.recvfrom(4096)
 end=12
 while data[end]:end+=data[end]+1
 end+=1
 typ,cls=struct.unpack('!HH',data[end:end+4]);question=data[12:end+4]
 answer=Path(sys.argv[1]).read_text().strip()
 result=(b'\xc0\x0c'+struct.pack('!HHIH',1,1,0,4)+socket.inet_aton(answer)) if typ==1 else b''
 s.sendto(data[:2]+struct.pack('!HHHHH',0x8180,1,int(bool(result)),0,0)+question+result,peer)
 with open(sys.argv[2],'a') as log:log.write(answer+'\n')
"""
        self.dns_answer_path = self.root / 'dns-answer'
        self.dns_observed_path = self.root / 'dns-observed'
        self.dns_answer(answer)
        gateway = self.podman.inspect_owned('container', self.identity.proxy, self.identity)
        # Trusted fixture service enters only the exact owned network namespace.
        # Production gateway processes/capabilities and mount namespace stay intact.
        proc = self.start_process(['podman', 'unshare', 'nsenter',
            '--net=/proc/' + str(gateway['State']['Pid']) + '/ns/net',
            '/usr/bin/python3', '-I', '-S', '-u', '-c', script,
            str(self.dns_answer_path), str(self.dns_observed_path)])
        self.read_port(proc)
        try:
            original_rules = self.exec(['nft', 'list', 'ruleset'], gateway=True, user='0:0').stdout.splitlines()
            self.exec(['nft', 'insert', 'rule', 'inet', 't3_egress', 'output', 'meta', 'skuid', '2001', 'ip', 'daddr', '127.0.0.1', 'udp', 'dport', '53', 'accept'], gateway=True, user='0:0')
            self.exec(['nft', 'insert', 'rule', 'inet', 't3_egress', 'input', 'iifname', 'lo', 'ip', 'daddr', '127.0.0.1', 'udp', 'dport', '53', 'accept'], gateway=True, user='0:0')
            fixture_rules = self.exec(['nft', 'list', 'ruleset'], gateway=True, user='0:0').stdout.splitlines()
            exceptions = {'meta skuid 2001 ip daddr 127.0.0.1 udp dport 53 accept',
                          'iifname "lo" ip daddr 127.0.0.1 udp dport 53 accept'}
            if ([line for line in fixture_rules if line.strip() not in exceptions] != original_rules
                    or sum(line.strip() in exceptions for line in fixture_rules) != 2):
                raise AssertionError('Fixture must preserve all original guards and add only two UDP53 rules')
            self.python("from pathlib import Path;p=Path('/run/t3-proxy/squid.conf');p.write_text(chr(10).join('dns_nameservers 127.0.0.1' if l.startswith('dns_nameservers ') else l for l in p.read_text().splitlines())+chr(10)+'positive_dns_ttl 1 seconds'+chr(10))", gateway=True, user='0:0')
            self.exec(['squid', '-k', 'reconfigure', '-f', '/run/t3-proxy/squid.conf'], gateway=True, user='2001:2001')
            time.sleep(.3)
            yield
        finally:
            try:
                try:
                    os.killpg(proc.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                try:
                    proc.communicate(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(proc.pid, signal.SIGKILL)
                    proc.communicate(timeout=5)
            finally:
                self.proxy_restart()

    def dns_answer(self, answer):
        self.dns_answer_path.write_text(answer)

    def wait_denial(self, destination):
        from t3_sandbox.denials import read_denials
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if any(r.destination == destination for r in read_denials(self.paths.logs, tail=100, follow=False)):
                return
            time.sleep(.1)
        raise AssertionError('Expected denial not recorded: ' + destination)

    def management_websocket_reconnects(self):
        # Issue ephemeral disposable fixture auth through production T3. Never
        # print it or read the user's real auth state.
        token = self.exec(['t3', 'auth', 'session', 'issue', '--subject', 'integration-client', '--ttl', '20m', '--token-only']).stdout.strip()
        protocol = 2
        address = self.host_ipv4
        connection = socket.create_connection((address, self.port), timeout=5)
        try:
            key = base64.b64encode(os.urandom(16)).decode()
            connection.sendall((f'GET /ws?orchestrationProtocol={protocol} HTTP/1.1\r\nHost: {address}:{self.port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\nAuthorization: Bearer {token}\r\n\r\n').encode())
            header = bytearray()
            while not header.endswith(b'\r\n\r\n') and len(header) < 16384:
                chunk = connection.recv(1)
                if not chunk:break
                header.extend(chunk)
            return header.startswith(b'HTTP/1.1 101 ')
        finally:
            connection.close()

    def assert_security(self, case):
        t3 = self.podman.inspect('container', self.identity.container)
        proxy = self.podman.inspect('container', self.identity.proxy)
        case.assertEqual(set(t3['NetworkSettings']['Networks']), {self.identity.private_network})
        case.assertFalse(self.podman.inspect('network', self.identity.private_network)['dns_enabled'])
        routes = self.python("import json;print(json.dumps({'v4':open('/proc/net/route').read(),'v6':open('/proc/net/ipv6_route').read()}))").stdout
        case.assertNotIn('00000000\t00000000', json.loads(routes)['v4'])
        for resource in (t3, proxy):
            case.assertTrue(resource['HostConfig']['SecurityOpt'])
            if resource is t3:
                case.assertFalse(resource['EffectiveCaps'])
        status = self.exec(['cat', '/proc/1/status']).stdout
        case.assertIn('NoNewPrivs:\t1', status)
        case.assertIn('CapEff:\t0000000000000000', status)
        gateway_status = self.exec(['cat', '/proc/1/status'], gateway=True).stdout
        case.assertIn('NoNewPrivs:\t1', gateway_status)
        case.assertIn('CapEff:\t0000000000000000', gateway_status)
        case.assertIn('Uid:\t2003\t2003\t2003\t2003', gateway_status)
        for leaf in ('net/ipv4/ip_forward', 'net/ipv6/conf/all/forwarding', 'net/ipv6/conf/default/forwarding'):
            case.assertEqual(self.exec(['cat', '/proc/sys/' + leaf], gateway=True).stdout.strip(), '0')
        case.assertNotEqual(self.exec(['nft', 'list', 'ruleset'], check=False).returncode, 0)
        # Fresh root exec is only an observation of the installed gateway rules;
        # workload/Squid have no privilege to inspect or mutate these controls.
        rules = self.exec(['nft', 'list', 'ruleset'], gateway=True, user='0:0').stdout
        case.assertIn('policy drop', rules)
        case.assertIn('skuid 2001', rules)
        snapshot = self.paths.runtime / 'policy/active.json'
        case.assertEqual(snapshot.stat().st_mode & 0o777, 0o644)
        case.assertEqual(snapshot.parent.stat().st_mode & 0o777, 0o755)
        case.assertEqual(self.paths.logs.stat().st_mode & 0o777, 0o700)
        case.assertEqual({m['Destination'] for m in proxy['Mounts']}, {'/run/t3-policy', '/var/log/t3-proxy'})
        case.assertNotIn('3128/tcp', proxy['HostConfig']['PortBindings'])
