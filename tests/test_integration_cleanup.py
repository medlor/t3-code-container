"""Failure-path fixture cleanup checks; no real Podman or fixture startup."""
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

from t3_sandbox.paths import ProfileIdentity
from t3_sandbox.podman import LABEL_PREFIX

_SPEC = importlib.util.spec_from_file_location('integration_cleanup_support', Path(__file__).parent / 'integration/support.py')
_FIXTURES = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = _FIXTURES
_SPEC.loader.exec_module(_FIXTURES)


class CleanupEngine:
    def __init__(self, identity, extra):
        labels = {LABEL_PREFIX + key: str(value) for key, value in
                  dict(managed='true', uid=identity.uid, profile=identity.name).items()}
        self.resources = {(kind, name): {'Labels': {**labels, LABEL_PREFIX + 'role': role}}
            for kind, name, role in [('container', extra, 'proxy'),
                ('container', identity.container, 't3'), ('container', identity.proxy, 'proxy'),
                ('network', identity.private_network, 'private'), ('network', identity.external_network, 'external')]}
        self.calls = []
        self.fail_remove = set()

    def inspect(self, kind, name):
        return self.resources.get((kind, name))

    def run(self, args, *, timeout=30):
        args = list(args)
        self.calls.append((args, timeout))
        if args[0] == 'unshare':
            shutil.rmtree(args[-1])
        else:
            kind = 'network' if args[0] == 'network' else 'container'
            if args[-1] in self.fail_remove:
                raise subprocess.TimeoutExpired(args, timeout)
            self.resources.pop((kind, args[-1]), None)
        return subprocess.CompletedProcess(args, 0)


class IntegrationCleanupTests(unittest.TestCase):
    def setUp(self):
        self.lab = _FIXTURES.SandboxLab()
        self.lab.identity = ProfileIdentity('it-cleanup-fault', os.getuid())
        self.lab.root = Path(tempfile.mkdtemp(prefix='t3-integration-'))
        self.addCleanup(shutil.rmtree, self.lab.root, True)
        self.extra = self.lab.identity.container + '-control'
        self.lab.extra_containers = [self.extra]
        self.lab.podman = CleanupEngine(self.lab.identity, self.extra)

    def assert_primary_cleanup_attempted(self):
        names = [args[-1] for args, _ in self.lab.podman.calls]
        for name in (self.lab.identity.container, self.lab.identity.proxy,
                     self.lab.identity.private_network, self.lab.identity.external_network):
            self.assertIn(name, names)
            self.assertNotIn(('container' if name in (self.lab.identity.container, self.lab.identity.proxy) else 'network', name), self.lab.podman.resources)
        self.assertTrue(all(timeout == 30 for _, timeout in self.lab.podman.calls))

    def test_helper_shutdown_failure_still_cleans_all_owned_resources(self):
        helper = Mock(pid=12345)
        helper.communicate.side_effect = subprocess.TimeoutExpired(['helper'], 5)
        other = Mock(pid=12346)
        self.lab.processes = [other, helper]
        def signal(pid, sig):
            if pid == helper.pid:
                raise PermissionError('injected helper shutdown failure')
        with patch.object(_FIXTURES.os, 'killpg', side_effect=signal):
            with self.assertRaises(AssertionError):
                self.lab.__exit__(None, None, None)
        other.communicate.assert_called_once_with(timeout=5)
        self.assertEqual(helper.communicate.call_count, 2)
        self.assert_primary_cleanup_attempted()
        self.assertNotIn(('container', self.extra), self.lab.podman.resources)
        self.assertTrue(self.lab.root.exists(), 'Unconfirmed helper must retain its backing files')

    def test_extra_removal_failure_does_not_skip_other_resources_or_delete_backing_root(self):
        self.lab.podman.fail_remove.add(self.extra)
        with self.assertRaises(AssertionError):
            self.lab.__exit__(None, None, None)
        self.assert_primary_cleanup_attempted()
        self.assertIn(('container', self.extra), self.lab.podman.resources)
        self.assertTrue(self.lab.root.exists())
        self.assertFalse(any(args[0] == 'unshare' for args, _ in self.lab.podman.calls))

    def test_ownership_failure_refuses_container_and_continues_other_cleanup(self):
        self.lab.podman.resources['container', self.extra]['Labels'][LABEL_PREFIX + 'profile'] = 'somebody-else'
        with self.assertRaises(AssertionError):
            self.lab.__exit__(None, None, None)
        self.assert_primary_cleanup_attempted()
        self.assertFalse(any(args[-1] == self.extra for args, _ in self.lab.podman.calls))
        self.assertTrue(self.lab.root.exists())

    def test_success_deletes_only_exact_fixture_root_after_resources_are_absent(self):
        self.lab.__exit__(None, None, None)
        self.assertFalse(self.lab.podman.resources)
        self.assertFalse(self.lab.root.exists())
        self.assertEqual(self.lab.podman.calls[-1], (['unshare', 'rm', '-rf', '--', str(self.lab.root)], 30))

    def test_unknown_container_state_retains_root_and_continues_other_cleanup(self):
        inspect = self.lab.podman.inspect
        def unavailable(kind, name):
            if name == self.extra:
                raise RuntimeError('injected inspection failure')
            return inspect(kind, name)
        with patch.object(self.lab.podman, 'inspect', side_effect=unavailable):
            with self.assertRaisesRegex(AssertionError, 'verify container'):
                self.lab.__exit__(None, None, None)
        self.assert_primary_cleanup_attempted()
        self.assertTrue(self.lab.root.exists())

    def test_cleanup_failure_keeps_original_test_exception_as_cause(self):
        original = RuntimeError('original test failure')
        self.lab.podman.fail_remove.add(self.extra)
        with self.assertRaises(AssertionError) as raised:
            self.lab.__exit__(type(original), original, original.__traceback__)
        self.assertIs(raised.exception.__cause__, original)
