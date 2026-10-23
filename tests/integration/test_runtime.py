"""Real production T3, offline browser assets, and persistent state acceptance."""
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import subprocess
import time
import unittest
import urllib.request

from support import ENABLED, SandboxLab


@unittest.skipUnless(ENABLED, 'set T3_SANDBOX_INTEGRATION=1 for disposable real Podman tests')
class RuntimeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.lab = SandboxLab(restricted=False)
        cls.lab.__enter__()
        cls.addClassCleanup(cls.lab.__exit__, None, None, None)

    def test_unrestricted_works_without_any_proxy_resource(self):
        lab = self.lab
        for kind, name in [('image', lab.identity.proxy_image), ('container', lab.identity.proxy), ('network', lab.identity.private_network), ('network', lab.identity.external_network)]:
            self.assertIsNone(lab.podman.inspect(kind, name))
        self.assertEqual(lab.exec(['curl', '--fail', '--silent', '--connect-timeout', '5', '--max-time', '20', '-o', '/dev/null', 'https://example.com']).returncode, 0)
        self.assertEqual(lab.exec(['id', '-u']).stdout.strip(), str(os.getuid()))
        lab.launcher.dispatch('smoke', lab.identity.name)

    def test_nonloopback_http_pairing_and_authenticated_websocket(self):
        lab = self.lab
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(f'http://{lab.host_ipv4}:{lab.port}/', timeout=5) as response:
            self.assertEqual(response.status, 200)
            self.assertIn(b'<html', response.read().lower())
        pairing = lab.exec(['t3', 'pair']).stdout
        # Assert token presence without writing any fixture auth into test logs.
        self.assertIn('token=', pairing)
        self.assertTrue(lab.management_websocket_reconnects())

    def test_persistent_home_survives_production_build_recreate_and_remove(self):
        lab = self.lab
        lab.exec(['bash', '-ec', 'printf private-home > "$HOME/it-marker"; printf private-t3 > "$HOME/.t3/it-marker"; printf private-provider > "$HOME/.codex/it-marker"'])
        home = lab.paths.home
        before = lab.t3_identity_and_start_time()
        lab.launcher.dispatch('build', lab.identity.name)
        self.assertEqual(lab.t3_identity_and_start_time(), before)
        lab.launcher.dispatch('recreate', lab.identity.name)
        self.assertNotEqual(lab.t3_identity_and_start_time()[0], before[0])
        self.assertEqual(lab.exec(['cat', '/home/' + lab.host.user + '/it-marker']).stdout, 'private-home')
        self.assertEqual((home / '.t3/it-marker').read_text(), 'private-t3')
        self.assertEqual((home / '.codex/it-marker').read_text(), 'private-provider')
        lab.launcher.dispatch('remove', lab.identity.name)
        self.assertEqual((home / 'it-marker').read_text(), 'private-home')
        self.assertEqual((lab.host.home / '.t3/fixture-marker').read_text(), '.t3')
        lab.launcher.dispatch('start', lab.identity.name)

    def test_independent_state_sharing_flags_use_only_fake_host_directories(self):
        lab = self.lab
        cache = lab.host.home / '.t3/tools/chrome-headless-shell'
        cache.mkdir(parents=True)
        (cache / 'host-sentinel').write_text('preserve host browser cache')
        try:
            for t3, providers in [(True, False), (False, True), (True, True), (False, False)]:
                with self.subTest(t3=t3, providers=providers):
                    lab.update({'state': {'share_host_t3_state': t3, 'share_host_provider_state': providers}})
                    lab.launcher.dispatch('recreate', lab.identity.name)
                    mounts = {m['Destination']: m['Source'] for m in lab.podman.inspect('container', lab.identity.container)['Mounts'] if m['Type'] == 'bind'}
                    self.assertEqual('/home/' + lab.host.user + '/.t3' in mounts, t3)
                    self.assertEqual('/home/' + lab.host.user + '/.codex' in mounts, providers)
                    self.assertEqual('/home/' + lab.host.user + '/.claude' in mounts, providers)
                    if t3:
                        self.assertEqual(lab.exec(['cat', '/home/' + lab.host.user + '/.t3/fixture-marker']).stdout, '.t3')
                    if providers:
                        self.assertEqual(lab.exec(['cat', '/home/' + lab.host.user + '/.codex/fixture-marker']).stdout, '.codex')
                    self.assertEqual((cache / 'host-sentinel').read_text(), 'preserve host browser cache')
                    self.assertEqual(list(cache.iterdir()), [cache / 'host-sentinel'])
        finally:
            lab.update({'state': {'share_host_t3_state': False, 'share_host_provider_state': False}})
            lab.launcher.dispatch('recreate', lab.identity.name)

    def test_recovery_after_invalid_yaml_and_same_profile_concurrency(self):
        lab = self.lab
        lab.file.write_text('version: [malformed\n')
        try:
            lab.launcher.dispatch('status', lab.identity.name)
            lab.launcher.dispatch('logs', lab.identity.name, follow=False, tail=1)
            lab.launcher.dispatch('stop', lab.identity.name)
            lab.launcher.dispatch('remove', lab.identity.name)
        finally:
            lab.update({})
        with ThreadPoolExecutor(max_workers=2) as workers:
            futures = [workers.submit(lab.launcher.dispatch, 'start', lab.identity.name) for _ in range(2)]
            for future in futures:
                self.assertEqual(future.result(timeout=90), 0)
        self.assertTrue(lab.podman.inspect('container', lab.identity.container)['State']['Running'])

    def test_missing_default_initialization_is_offline_and_reserves_default_port(self):
        # This creates YAML only, never a real default engine identity.
        from t3_sandbox.profiles import load_profile, initialize_profile
        default = load_profile('default', self.lab.profile_dir, self.lab.host)
        self.assertEqual(default.server.port, 3773)
        self.assertTrue(default.state.share_host_t3_state)
        path = initialize_profile('it-initialization', self.lab.profile_dir, self.lab.host)
        self.assertNotEqual(load_profile('it-initialization', self.lab.profile_dir, self.lab.host).server.port, 3773)


@unittest.skipUnless(ENABLED, 'set T3_SANDBOX_INTEGRATION=1 for disposable real Podman tests')
class ConcurrentProfileTests(unittest.TestCase):
    def test_two_restricted_profiles_stay_separate(self):
        with SandboxLab(restricted=True) as first, SandboxLab(restricted=True) as second:
            self.assertNotEqual(first.port, second.port)
            self.assertNotEqual(first.gateway['private_cidr'], second.gateway['private_cidr'])
            self.assertFalse(first.socket_connect(second.gateway['t3_ip'], 3773))
            self.assertFalse(second.socket_connect(first.gateway['t3_ip'], 3773))
            first.exec(['bash', '-ec', 'printf first > "$HOME/only-first"'])
            self.assertNotEqual(second.exec(['test', '-e', '/home/' + second.host.user + '/only-first'], check=False).returncode, 0)
            self.assertTrue(first.management_websocket_reconnects())
            self.assertTrue(second.management_websocket_reconnects())
            before = first.t3_identity_and_start_time()
            first.proxy_restart()
            self.assertEqual(first.t3_identity_and_start_time(), before)
            self.assertEqual(first.https_via_proxy('https://example.com').status, 200)
            self.assertTrue(second.management_websocket_reconnects())
