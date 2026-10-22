"""Trusted gateway behavior; real packaged-daemon checks recorded in task report."""
from dataclasses import asdict
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from t3_sandbox import policy

ROOT = Path(__file__).resolve().parents[1]


def runtime_module():
    spec = importlib.util.spec_from_file_location('proxy_runtime', ROOT / 'proxy/runtime.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def snapshot(path):
    topology = policy.GatewayConfig('10.89.1.2', '10.89.1.3', '10.89.1.0/24',
        ('10.89.2.0/24',), ('192.168.1.1',), ('1.1.1.1',), '0.0.0.0', 3773)
    path.write_bytes(policy.encode_snapshot(policy.Allowlist(('example.com',), (), (80, 443)), topology))
    return path


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.runtime = runtime_module()
        self.directory = self.enterContext(tempfile.TemporaryDirectory())
        self.root = Path(self.directory)
        self.snapshot = snapshot(self.root / 'active.json')

    def test_validate_starts_no_daemons(self):
        with patch.object(self.runtime.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0)), \
             patch.object(self.runtime.subprocess, 'Popen', side_effect=AssertionError('started listener')):
            compiled = self.runtime.validate_snapshot(self.snapshot)
        self.assertEqual(len(compiled.digest), 64)
        self.assertFalse((self.root / 'ready.json').exists())

    def test_missing_malformed_and_oversized_snapshot_fail(self):
        for data in (b'{}', b'[]', b'\xff', b'x' * (1024 * 1024 + 1)):
            self.snapshot.write_bytes(data)
            with self.subTest(data=data[:10]), self.assertRaises(ValueError):
                self.runtime.validate_snapshot(self.snapshot)
        with self.assertRaises(OSError):
            self.runtime.validate_snapshot(self.root / 'missing')

    def test_validation_failure_clears_stale_readiness(self):
        ready = self.root / 'ready.json'
        ready.write_text('{"digest":"old"}')
        with patch.object(self.runtime.os, 'getpid', return_value=1), \
             patch.object(self.runtime, 'READY', ready), \
             patch.object(self.runtime, 'validate_snapshot', side_effect=ValueError('bad snapshot')):
            self.assertEqual(self.runtime.serve(self.snapshot, self.root / 'logs'), 1)
        self.assertFalse(ready.exists())

    def test_firewall_failure_prevents_listener_start(self):
        with patch.object(self.runtime.os, 'getpid', return_value=1), \
             patch.object(self.runtime, 'validate_snapshot', return_value=policy.compile_policy(
                 *policy.decode_snapshot(self.snapshot.read_bytes()), proxy_uid=2001, relay_uid=2002)), \
             patch.object(self.runtime, 'initialize', side_effect=RuntimeError('nft failed')), \
             patch.object(self.runtime.subprocess, 'Popen', side_effect=AssertionError('started listener')):
            self.assertNotEqual(self.runtime.serve(self.snapshot, self.root / 'logs'), 0)
        self.assertFalse((self.root / 'ready.json').exists())

    def test_proxy_and_relay_drop_capabilities_and_use_distinct_uids(self):
        # Privilege transitions cannot run in the unittest host namespace. Actual
        # /proc status evidence for all three processes is captured in the report.
        with patch.object(self.runtime.os, 'setgroups') as groups, \
             patch.object(self.runtime.os, 'setresgid') as gids, \
             patch.object(self.runtime.os, 'setresuid') as uids, \
             patch.object(self.runtime, 'prctl') as prctl, \
             patch.object(self.runtime, 'clear_capabilities') as caps:
            self.runtime.drop_privileges(2001)
            self.runtime.drop_privileges(2002)
        self.assertEqual([call.args for call in uids.call_args_list], [(2001, 2001, 2001), (2002, 2002, 2002)])
        self.assertEqual([call.args for call in gids.call_args_list], [(2001, 2001, 2001), (2002, 2002, 2002)])
        self.assertEqual(groups.call_count, 2)
        self.assertEqual(caps.call_count, 2)
        self.assertIn(unittest.mock.call(38, 1), prctl.call_args_list)  # PR_SET_NO_NEW_PRIVS

    def test_child_failure_terminates_gateway(self):
        # Real processes exercise death detection. The serving CLI must be PID1;
        # namespace exit, rather than cross-UID signals, kills every descendant.
        child = subprocess.Popen(['/bin/sh', '-c', 'exit 7'])
        child.wait()
        self.assertEqual(self.runtime.supervise([child], ready=lambda: True,
            reader=None, log_path=self.root / 'denials.jsonl', digest='a' * 64,
            ready_path=self.root / 'ready.json'), 1)
        self.assertFalse((self.root / 'ready.json').exists())

    def test_serving_requires_namespace_pid_one(self):
        with patch.object(self.runtime.os, 'getpid', return_value=123):
            self.assertEqual(self.runtime.serve(self.snapshot, self.root / 'logs'), 1)

    def test_readiness_is_passive_and_checks_exact_listener(self):
        rows = ('  sl  local_address rem_address st\n'
                '  0: 0201590A:0C38 00000000:0000 0A 0 0 0 2001\n'
                '  1: 00000000:0EBD 00000000:0000 0A 0 0 0 2002\n')
        self.assertTrue(self.runtime.listener_present('10.89.1.2', 3128, 2001, rows))
        self.assertFalse(self.runtime.listener_present('10.89.1.3', 3128, 2001, rows))
        self.assertFalse(self.runtime.listener_present('10.89.1.2', 3128, 2002, rows))

    def test_log_backpressure_has_bounded_memory(self):
        decoder = self.runtime.DecisionBuffer()
        for _ in range(100):
            self.assertEqual(decoder.feed(b'x' * 65536), [])
            self.assertLessEqual(len(decoder.pending), 4096)
        self.assertEqual(decoder.feed(b'\n'), [])


class DenialTests(unittest.TestCase):
    def setUp(self):
        from t3_sandbox import denials
        self.denials = denials

    def test_denial_writer_rotation_is_bounded(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'denials.jsonl'
            record = self.denials.DenialRecord('2026-10-22T10:00:00.000Z', 'blocked.example',
                443, 'CONNECT', 'unlisted_destination', 'a' * 64)
            with patch.object(self.denials, 'MAX_LOG_BYTES', 700):
                for _ in range(100):
                    self.denials.append_denial(path, record)
            self.assertEqual(len(list(Path(directory).iterdir())), 4)
            for file in Path(directory).iterdir():
                self.assertLessEqual(file.stat().st_size, 700)
                for line in file.read_text().splitlines():
                    self.assertEqual(json.loads(line)['destination'], 'blocked.example')

    def test_upstream_403_is_not_a_policy_denial(self):
        # This fixture is populated from the installed Squid emitted-record check.
        line = (ROOT / 'tests/fixtures/squid-upstream-403.log').read_text().strip()
        self.assertIsNone(self.denials.parse_denial(line, policy_digest='a' * 64))

    def test_policy_denial_is_sanitized_and_has_fixed_reason(self):
        line = (ROOT / 'tests/fixtures/squid-policy-denied.log').read_text().strip()
        denied = self.denials.parse_denial(line, policy_digest='a' * 64)
        self.assertEqual((denied.destination, denied.port, denied.reason),
            ('blocked.example', 443, 'unlisted_destination'))
        self.assertNotIn('token=secret', json.dumps(asdict(denied)))

    def test_other_emitted_denial_reasons_and_ipv6_are_normalized(self):
        for fixture, destination, port, reason in (
            ('squid-forbidden-port.log', 'blocked.example', 25, 'forbidden_port'),
            ('squid-protected-address.log', '192.168.1.1', 443, 'protected_address')):
            record = self.denials.parse_denial((ROOT / 'tests/fixtures' / fixture).read_text(), policy_digest='a' * 64)
            self.assertEqual((record.destination, record.port, record.reason), (destination, port, reason))
        record = self.denials.parse_denial((ROOT / 'tests/fixtures/squid-ipv6-denied.log').read_text(), policy_digest='a' * 64)
        self.assertEqual(record.destination, '::1')

    def test_gateway_normalizes_protected_literal_reason_without_upstream_false_positive(self):
        topology = policy.GatewayConfig('10.89.1.2', '10.89.1.3', '10.89.1.0/24',
            ('10.89.2.0/24',), ('93.184.216.34',), ('1.1.1.1',), '0.0.0.0', 3773)
        record = self.denials.parse_denial((ROOT / 'tests/fixtures/squid-ipv6-denied.log').read_text(),
            policy_digest='a' * 64, gateway=topology)
        self.assertEqual((record.destination, record.reason), ('::1', 'protected_address'))
        for fixture in ('squid-mapped-private.log', 'squid-protected-address.log'):
            record = self.denials.parse_denial((ROOT / 'tests/fixtures' / fixture).read_text(),
                policy_digest='a' * 64, gateway=topology)
            self.assertEqual((record.destination, record.reason), ('192.168.1.1', 'protected_address'))
        upstream = (ROOT / 'tests/fixtures/squid-upstream-403.log').read_text()
        self.assertIsNone(self.denials.parse_denial(upstream, policy_digest='a' * 64, gateway=topology))

    def test_malformed_and_unsafe_records_are_rejected(self):
        for line in ('', 'x' * 10000, '1700000000.000 TCP_DENIED ERR_ACCESS_DENIED unlisted_destination user@host/path?token=secret 443 GET',
                     '1700000000.000 TCP_DENIED ERR_ACCESS_DENIED unlisted_destination evil%0Ahost 443 GET',
                     '1700000000.000 TCP_DENIED ERR_ACCESS_DENIED protected_address fe80::1%25eth0%3Ftoken%3Dsecret 443 CONNECT',
                     '1700000000.000 TCP_DENIED ERR_ACCESS_DENIED protected_address %5Bfe80::1%25eth0%2Fsecret%5D 443 CONNECT',
                     '1700000000.000 TCP_DENIED ERR_ACCESS_DENIED arbitrary blocked.example 443 GET',
                     '1700000000.000 TCP_DENIED ERR_ACCESS_DENIED forbidden_port blocked.example 0 GET'):
            with self.subTest(line=line[:70]):
                self.assertIsNone(self.denials.parse_denial(line, policy_digest='a' * 64))
