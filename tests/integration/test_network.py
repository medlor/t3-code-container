"""Real, opt-in checks of the production restricted boundary."""
import json
import os
import subprocess
import time
import unittest

from support import SandboxLab, ENABLED


@unittest.skipUnless(ENABLED, 'set T3_SANDBOX_INTEGRATION=1 for disposable real Podman tests')
class RestrictedNetworkTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.lab = SandboxLab(restricted=True, bridge_control=True)
        cls.lab.__enter__()
        cls.addClassCleanup(cls.lab.__exit__, None, None, None)

    def test_bridge_ipv6_positive_control_then_denial(self):
        self.assertEqual(self.lab.bridge_positive_control, 'integration-host-service')
        self.assertNotEqual(self.lab.direct(self.lab.bridge_url).returncode, 0)
        info = self.lab.bridge_info()
        self.assertEqual(info['addr_info'], [])
        self.assertEqual(self.lab.bridge_ipv6_disabled(), '1')

    def browser(self, url):
        code = "import os,pathlib,subprocess,json;manifest=json.load(open('/opt/t3-browser/manifest.json'));p=pathlib.Path(os.environ['HOME'])/'.t3/tools/chrome-headless-shell'/manifest['executable'];r=subprocess.run([str(p),'--headless','--dump-dom','--timeout=12000'," + repr(url) + "],capture_output=True,text=True,timeout=22);print(json.dumps({'code':r.returncode,'body':r.stdout,'error':r.stderr}))"
        result = json.loads(self.lab.python(code).stdout)
        if result['code'] != 0 and any(marker in result['error'] for marker in ('No usable sandbox', 'Failed to move to new namespace', 'Operation not permitted', 'apparmor')):
            self.skipTest('Host browser sandbox prerequisite: ' + result['error'][-1200:])
        if result['code'] == -5 and 'Zygote process exited prematurely' in result['error']:
            probe = self.lab.exec(['unshare', '--user', '--map-root-user', 'chroot', '/', '/usr/bin/true'], check=False)
            if probe.returncode != 0 and 'Operation not permitted' in probe.stderr:
                self.skipTest('Production sandbox blocks nested chroot: ' + probe.stderr.strip() + '; Chromium: ' + result['error'].strip())
        self.assertEqual(result['code'], 0, result['error'])
        return result['body']

    def test_browser_renders_local_html_with_installed_assets(self):
        self.assertIn('integration-rendered', self.browser('data:text/html,<p id="proof">integration-rendered</p>'))
        self.assertIn('<html', self.browser('http://127.0.0.1:3773/').lower())
        self.assertNotEqual(self.lab.exec(['test', '-d', '/home/' + self.lab.host.user + '/.t3/runtime'], check=False).returncode, 0)

    def test_browser_https_allowed_and_unlisted_blocked(self):
        self.assertIn('Example Domain', self.browser('https://example.com'))
        self.assertNotIn('Wikipedia', self.browser('https://www.wikipedia.org'))
        self.lab.wait_denial('www.wikipedia.org')

    def test_provider_unauthenticated_tls_and_node_transport(self):
        response = self.lab.https_via_proxy('https://api.openai.com/v1/models')
        self.assertEqual(response.connect_status, 200)
        self.assertIn(response.status, (401, 403))
        result = self.lab.exec(['node', '-e', "fetch('https://api.openai.com/v1/models').then(r=>console.log(r.status)).catch(e=>{console.error(e);process.exit(1)})"])
        self.assertIn(int(result.stdout.strip()), (401, 403))
        result = self.lab.exec(['bun', '-e', "fetch('https://api.openai.com/v1/models').then(r=>console.log(r.status)).catch(e=>{console.error(e);process.exit(1)})"])
        self.assertIn(int(result.stdout.strip()), (401, 403))
        self.assertIn('codex-cli ', self.lab.exec(['codex', '--version']).stdout)
        # Authentication is never imported from the real host. No model request
        # is claimed by this unauthenticated transport assertion.
        self.assertNotEqual(self.lab.exec(['test', '-e', '/home/' + self.lab.host.user + '/.codex/auth.json'], check=False).returncode, 0)
        self.lab.launcher.dispatch('smoke', self.lab.identity.name)

    def test_t3_preview_uses_local_authenticated_production_interface(self):
        # Reuse the installed build helper's stdlib MCP/WS handshake; this calls
        # installed T3, and cannot download a browser because the wrapper/cache
        # was seeded from immutable image assets before the server started.
        # Check the actual browser prerequisite before invoking T3's preview.
        self.browser('data:text/html,<p>preview-prerequisite</p>')
        code = """import importlib.util,subprocess,socket,json,sys
sys.path.insert(0,'/usr/local/lib/t3-sandbox')
spec=importlib.util.spec_from_file_location('installer','/usr/local/lib/t3-sandbox/install-t3-browser.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
def issue(subject):
 return subprocess.run(['t3','auth','session','issue','--subject',subject,'--ttl','20m','--token-only'],check=True,capture_output=True,text=True).stdout.strip()
connection=m.trigger_preview(3773,issue)
if connection:
 data=b''
 for i in range(10):
  try:data+=connection.recv(65536)
  except socket.timeout:continue
  if b'Failure' in data or b'Defect' in data or b'Success' in data:break
 connection.close()
 print(data.decode('utf-8','replace'))
"""
        result = self.lab.python(code, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        if any(marker in result.stdout for marker in ('No usable sandbox', 'Failed to move to new namespace', 'Operation not permitted', 'apparmor')):
            self.skipTest('T3 browser launch requires host sandbox prerequisite: ' + result.stdout[-1400:])
        self.assertNotIn('Failure', result.stdout)
        self.assertNotIn('Defect', result.stdout)
        self.assertIn('Success', result.stdout)

    def test_allowed_dns_private_answer_and_deterministic_rebinding_denied(self):
        import socket
        self.lab.allow('rebind.fixture.test')
        self.lab.allow('private.fixture.test')
        self.lab.proxy_restart()
        with self.lab.controlled_dns('127.0.0.1'):
            self.assertEqual(self.lab.https_via_proxy('https://private.fixture.test').connect_status, 403)
            public = socket.gethostbyname('example.com')
            self.lab.dns_answer(public)
            self.assertEqual(self.lab.https_via_proxy('https://rebind.fixture.test').connect_status, 200)
            self.lab.dns_answer('127.0.0.1')
            time.sleep(2)
            self.assertEqual(self.lab.https_via_proxy('https://rebind.fixture.test').connect_status, 403)
            observed = self.lab.dns_observed_path.read_text().splitlines()
            self.assertIn(public, observed)
            self.assertEqual(observed[-1], '127.0.0.1')
            print('INTEGRATION DNS: same allowed hostname CONNECT 200 with public answer, then 403 with fresh private answer', flush=True)
            self.assertFalse(self.lab.socket_connect('127.0.0.1', 3773, gateway_user='2001:2001'))
        self.assertEqual(self.lab.https_via_proxy('https://example.com').status, 200)
        self.lab.assert_security(self)

    def test_wildcard_and_allowed_ip_through_real_squid(self):
        original = list(self.lab.settings['network']['allow']['domains'])
        ips = list(self.lab.settings['network']['allow']['ips'])
        self.lab.update({'network': {'allow': {'domains': ['*.example.com'], 'ips': ips + ['1.1.1.1']}}})
        try:
            self.lab.proxy_restart()
            self.assertEqual(self.lab.https_via_proxy('https://www.example.com').status, 200)
            self.assertEqual(self.lab.https_via_proxy('https://example.com').connect_status, 403)
            self.assertEqual(self.lab.https_via_proxy('https://1.1.1.1').connect_status, 200)
        finally:
            self.lab.update({'network': {'allow': {'domains': original, 'ips': ips}}})
            self.lab.proxy_restart()

    def test_upstream_http_403_is_excluded_from_denial_log(self):
        from t3_sandbox.denials import read_denials
        self.lab.allow('httpbin.org')
        self.lab.proxy_restart()
        response = self.lab.https_via_proxy('https://httpbin.org/status/403')
        self.assertEqual((response.connect_status, response.status), (200, 403), repr(response))
        time.sleep(.2)
        self.assertNotIn('httpbin.org', [r.destination for r in read_denials(self.lab.paths.logs, tail=100, follow=False)])

    def test_direct_ipv4_internet_denied_with_all_proxy_variables_cleared(self):
        self.assertNotEqual(self.lab.direct('https://1.1.1.1').returncode, 0)

    def test_direct_ipv6_internet_denied_with_all_proxy_variables_cleared(self):
        self.assertNotEqual(self.lab.direct('https://[2606:4700:4700::1111]').returncode, 0)

    def test_direct_udp_and_tcp_dns_denied(self):
        result = self.lab.python("import socket,json\nr=[]\nfor kind in (socket.SOCK_DGRAM,socket.SOCK_STREAM):\n s=socket.socket(socket.AF_INET,kind);s.settimeout(1)\n try:\n  s.connect(('1.1.1.1',53));s.send(b'\\x12\\x34'+b'\\x00'*20);s.recv(32);r.append(True)\n except OSError:r.append(False)\nprint(json.dumps(r))", clear_proxy=True)
        self.assertEqual(json.loads(result.stdout), [False, False])
        self.assertNotEqual(self.lab.exec(['timeout', '3', 'getent', 'ahostsv4', 'example.com'], clear_proxy=True, check=False).returncode, 0)

    def test_proxy_only_endpoint_and_direct_host_lan_denial(self):
        self.assertEqual(self.lab.https_via_proxy('https://example.com').status, 200)
        gateway = self.lab.gateway
        for host, port in [(gateway['private_ip'], 3773), (gateway['private_ip'], 22), ('10.0.2.2', 80), ('192.168.1.1', 80), (self.lab.host_ipv4, self.lab.host_service_port)]:
            with self.subTest(host=host, port=port):
                self.assertFalse(self.lab.socket_connect(host, port))
        self.assertTrue(self.lab.socket_connect(gateway['private_ip'], 3128))

    def test_protected_literals_and_mapped_addresses_denied_even_if_listed(self):
        for authority in ['127.0.0.1', '10.0.2.2', '192.168.1.1', '[::1]', '[fc00::1]', '[fe80::1]', '[::ffff:127.0.0.1]', self.lab.gateway['private_ip']]:
            with self.subTest(authority=authority):
                response = self.lab.https_via_proxy('https://' + authority)
                if authority == '[::1]':
                    # Squid's IPv4-only operational listener may time out on its
                    # IPv6 localhost special case before emitting an ACL status.
                    self.assertNotEqual(response.connect_status, 200, repr(response))
                    self.assertIsNone(response.status, repr(response))
                else:
                    self.assertEqual(response.connect_status, 403, repr(response))

    def test_proxy_uid_cannot_bypass_application_acl_to_protected_sockets(self):
        for address in [self.lab.gateway['private_ip'], '127.0.0.1', self.lab.gateway['t3_ip'], self.lab.host_ipv4, '192.168.1.1']:
            with self.subTest(address=address):
                self.assertFalse(self.lab.socket_connect(address, 3773, gateway_user='2001:2001'))

    def test_supervisor_exception_does_not_allow_wrong_port(self):
        port = self.lab.gateway_listener()
        address = self.lab.gateway['private_ip']
        self.assertTrue(self.lab.socket_connect(address, 3773, gateway_user='2003:2003'))
        self.assertFalse(self.lab.socket_connect(address, port, gateway_user='2003:2003'))

    def test_fixed_relay_is_not_an_arbitrary_http_connect_proxy(self):
        response = self.lab.exec(['curl', '--silent', '--show-error', '--connect-timeout', '2', '--max-time', '4', '--noproxy', '', '--proxy', f"http://{self.lab.gateway['private_ip']}:3773", 'https://example.com'], check=False)
        self.assertNotEqual(response.returncode, 0)
        self.assertNotIn('200 Connection established', response.stdout)
        # Exercise the published relay too: private-source denial above alone
        # cannot establish what the relay does with an actual CONNECT request.
        response = subprocess.run(['curl', '--silent', '--show-error', '--connect-timeout', '2',
            '--max-time', '4', '--noproxy', '', '--proxy',
            f'http://{self.lab.host_ipv4}:{self.lab.port}', 'https://example.com'],
            capture_output=True, text=True, timeout=6)
        self.assertNotEqual(response.returncode, 0)
        self.assertNotIn('Example Domain', response.stdout)

    def test_actual_routes_namespaces_privileges_and_outside_firewall(self):
        self.lab.assert_security(self)

    def test_proxy_restart_preserves_t3_counter_and_management_reconnects(self):
        before = self.lab.t3_identity_and_start_time()
        job = self.lab.start_local_counter_job()
        self.assertTrue(self.lab.management_websocket_reconnects())
        self.lab.allow('example.com')
        self.lab.proxy_restart()
        self.assertEqual(self.lab.t3_identity_and_start_time(), before)
        self.assertGreater(self.lab.counter(job), job.initial_count)
        self.assertEqual(self.lab.https_via_proxy('https://example.com').status, 200)
        self.assertEqual(self.lab.https_via_proxy('https://unlisted.example').connect_status, 403)
        self.assertTrue(self.lab.management_websocket_reconnects())

    def test_proxy_crash_preserves_t3_and_direct_isolation(self):
        before = self.lab.t3_identity_and_start_time()
        self.lab.podman.run(['kill', '--signal=KILL', self.lab.identity.proxy])
        try:
            self.assertEqual(self.lab.t3_identity_and_start_time(), before)
            self.assertNotEqual(self.lab.direct('https://1.1.1.1').returncode, 0)
            self.assertIsNone(self.lab.https_via_proxy('https://example.com').status)
        finally:
            self.lab.proxy_restart()
        self.assertEqual(self.lab.t3_identity_and_start_time(), before)

    def test_structural_change_rejected_before_stopping_anything(self):
        before = (self.lab.t3_identity_and_start_time(), self.lab.podman.inspect('container', self.lab.identity.proxy)['State']['StartedAt'])
        self.lab.update({'resources': {'pids_limit': 2047}})
        try:
            with self.assertRaisesRegex(ValueError, 'recreate'):
                self.lab.proxy_restart()
            self.assertEqual((self.lab.t3_identity_and_start_time(), self.lab.podman.inspect('container', self.lab.identity.proxy)['State']['StartedAt']), before)
        finally:
            self.lab.update({'resources': {'pids_limit': 2048}})

    def test_denials_persist_across_rotation_and_gateway_restart(self):
        from t3_sandbox.denials import read_denials, MAX_LOG_BYTES
        self.lab.https_via_proxy('https://rotation-before.example')
        self.lab.wait_denial('rotation-before.example')
        path = self.lab.paths.logs / 'denials.jsonl'
        with path.open('ab') as stream:
            stream.write(b'\n' * MAX_LOG_BYTES)
        self.lab.https_via_proxy('https://rotation-after.example')
        self.lab.wait_denial('rotation-after.example')
        self.assertTrue(path.with_name(path.name + '.1').is_file())
        self.lab.proxy_restart()
        destinations = [r.destination for r in read_denials(self.lab.paths.logs, tail=100, follow=False)]
        self.assertIn('rotation-before.example', destinations)
        self.assertIn('rotation-after.example', destinations)
