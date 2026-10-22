"""Denial viewing uses real retained files and selected owned profile identity."""
from contextlib import redirect_stdout
import fcntl
import io
import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch

from support import ProfileFixture
from t3_sandbox import denials
from t3_sandbox.denials import DenialRecord
from t3_sandbox.launcher import Launcher
from t3_sandbox.paths import ProfileIdentity, profile_paths
from test_network import NetworkEngine


def record(number):
    return DenialRecord(f'2026-10-22T12:00:{number:02}.000Z', 'blocked.example', 443,
                        'CONNECT', 'unlisted_destination', 'a' * 64)


class DenialReaderTests(unittest.TestCase):
    def setUp(self):
        self.f = self.enterContext(ProfileFixture())
        self.directory = self.f.root / 'logs'
        self.directory.mkdir()

    def write(self, suffix, numbers):
        path = self.directory / ('denials.jsonl' + suffix)
        path.write_text(''.join(record(n).json_line() for n in numbers))
        return path

    def read(self, **kwargs):
        reader = getattr(denials, 'read_denials', None)
        self.assertIsNotNone(reader, 'rotation-aware denial reader is missing')
        return reader(self.directory, **kwargs)

    def test_finite_tail_is_chronological_across_retained_files(self):
        self.write('.3', [1, 2])
        self.write('.2', [3, 4])
        self.write('.1', [5, 6])
        self.write('', [7, 8])
        self.assertEqual(list(self.read(tail=3, follow=False)), [record(6), record(7), record(8)])
        self.assertEqual(list(self.read(tail=0, follow=False)), [])

    def test_firewall_logs_follow_rotation_and_restart(self):
        active = self.write('', [1])
        reader = self.read(tail=1, follow=True)
        self.addCleanup(reader.close)
        self.assertEqual(next(reader), record(1))
        active.rename(self.directory / 'denials.jsonl.1')
        self.write('', [2])
        self.assertEqual(next(reader), record(2))
        with active.open('a') as stream:
            stream.write(record(3).json_line())
        self.assertEqual(next(reader), record(3))
        # Restart may temporarily leave no active file, then create a fresh inode.
        active.rename(self.directory / 'denials.jsonl.2')
        def restart(_):
            self.write('', [4])
        with patch.object(denials.time, 'sleep', restart):
            self.assertEqual(next(reader), record(4))

    def test_incomplete_and_oversized_records_do_not_leak_or_repeat(self):
        active = self.write('', [1])
        reader = self.read(tail=1)
        self.addCleanup(reader.close)
        self.assertEqual(next(reader), record(1))
        line = record(2).json_line()
        with active.open('a') as stream:
            stream.write('x' * 20000 + '\n' + line[:20])
        def finish(_):
            with active.open('a') as stream:
                stream.write(line[20:])
        with patch.object(denials.time, 'sleep', finish):
            self.assertEqual(next(reader), record(2))

    def test_unrelated_and_malformed_files_are_excluded(self):
        self.write('', [1])
        (self.directory / 'other.jsonl').write_text(record(9).json_line())
        with (self.directory / 'denials.jsonl').open('a') as stream:
            stream.write('{"token":"must-not-print"}\n')
            malformed = json.loads(record(1).json_line())
            malformed['destination'] = 123
            stream.write(json.dumps(malformed) + '\n')
        self.assertEqual(list(self.read(follow=False)), [record(1)])

    def test_reader_rejects_symlinked_log_file(self):
        target = self.f.root / 'secret'
        target.write_text(record(1).json_line())
        (self.directory / 'denials.jsonl').symlink_to(target)
        with self.assertRaises(OSError):
            list(self.read(follow=False))


class FirewallCommandTests(unittest.TestCase):
    def setUp(self):
        self.f = self.enterContext(ProfileFixture())
        self.f.load('work', {'network': {'restricted': True}})
        self.identity = ProfileIdentity('work', self.f.host.uid)
        self.paths = profile_paths(self.identity, self.f.profile_dir, self.f.host)
        self.fake = NetworkEngine(self.identity, self.f.host)
        self.launcher = Launcher(self.fake, self.f.host, self.f.profile_dir)
        self.launcher.dispatch('start', 'work')
        self.fake.calls.clear()
        (self.paths.logs / 'denials.jsonl').write_text(record(1).json_line())

    def test_firewall_logs_work_with_invalid_or_missing_yaml(self):
        for missing in (False, True):
            if missing:
                self.paths.profile_file.unlink()
            else:
                self.paths.profile_file.write_text('network: [invalid')
            out = io.StringIO()
            with redirect_stdout(out):
                self.assertEqual(self.launcher.dispatch('firewall-logs', 'work', follow=False), 0)
            self.assertEqual(out.getvalue(), record(1).json_line())

    def test_log_stdout_has_only_selected_profile_denials(self):
        other = self.paths.logs.parent.parent / 'other/logs'
        other.mkdir(parents=True)
        (other / 'denials.jsonl').write_text(record(9).json_line())
        out = io.StringIO()
        with redirect_stdout(out):
            self.assertEqual(self.launcher.dispatch('firewall-logs', 'work', follow=False, tail=1), 0)
        self.assertEqual([json.loads(line)['timestamp'] for line in out.getvalue().splitlines()], ['2026-10-22T12:00:01.000Z'])

    def test_log_follow_does_not_hold_mutation_lock_and_ctrl_c_keeps_containers(self):
        def interrupted(_):
            with self.paths.lock.open('a') as lock:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                fcntl.flock(lock, fcntl.LOCK_UN)
            raise KeyboardInterrupt
        reader = getattr(denials, 'read_denials', None)
        self.assertIsNotNone(reader, 'rotation-aware denial reader is missing')
        with redirect_stdout(io.StringIO()), patch.object(denials.time, 'sleep', interrupted):
            self.assertEqual(self.launcher.dispatch('firewall-logs', 'work'), 130)
        self.assertTrue(all(c['State']['Running'] for c in self.fake.containers.values()))
        self.assertFalse(any(a[0] in ('stop', 'start', 'rm', 'run') for a in self.fake.calls))

    def test_off_mode_does_not_create_logs_or_proxy(self):
        self.f.load('off', {})
        out = io.StringIO()
        with redirect_stdout(out), self.assertRaisesRegex(ValueError, 'gateway|restricted'):
            self.launcher.dispatch('firewall-logs', 'off', follow=False)
        self.assertEqual(out.getvalue(), '')
        self.assertFalse((self.paths.logs.parent.parent / 'off/logs').exists())

    def test_unowned_proxy_is_rejected(self):
        self.fake.containers[self.identity.proxy]['Config']['Labels']['io.t3-sandbox.uid'] = '99999'
        with self.assertRaises(ValueError), redirect_stdout(io.StringIO()):
            self.launcher.dispatch('firewall-logs', 'work', follow=False)
