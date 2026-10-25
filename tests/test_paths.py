"""Persistent storage, protected host paths, and owned resource discovery."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from contextlib import redirect_stderr
import io
from pathlib import Path
import subprocess
import sqlite3
import os
import json
from unittest.mock import patch
import threading
import unittest

from support import FakePodman, ProfileFixture
from t3_sandbox import paths as storage


class StorageTests(unittest.TestCase):
    def paths(self, fixture, name='work'):
        return storage.profile_paths(storage.ProfileIdentity(name, fixture.host.uid), fixture.profile_dir, fixture.host)

    @unittest.skipIf(os.getuid() == 0, 'Requires filesystem permission enforcement')
    def test_inaccessible_project_descendants_warn_and_continue_checking_symlinks(self):
        with ProfileFixture() as f:
            profile = f.load('work', {})
            project = profile.project.directory
            project.mkdir(parents=True)
            paths = self.paths(f)
            for mode in (0o000, 0o400):
                with self.subTest(mode=mode):
                    blocked = project / 'container-data'
                    blocked.mkdir()
                    (blocked / 'session.jsonl').touch()
                    blocked.chmod(mode)
                    try:
                        stderr = io.StringIO()
                        with redirect_stderr(stderr):
                            storage.validate_storage(profile, paths, f.host)
                        self.assertEqual(len(stderr.getvalue().splitlines()), 1)
                        self.assertIn('Warning:', stderr.getvalue())
                        self.assertIn(str(project), stderr.getvalue())
                        link = project / 'policy-link'
                        link.symlink_to(paths.runtime)
                        try:
                            with redirect_stderr(io.StringIO()), self.assertRaisesRegex(ValueError, 'protected'):
                                storage.validate_storage(profile, paths, f.host)
                        finally:
                            link.unlink()
                    finally:
                        blocked.chmod(0o700)
                        (blocked / 'session.jsonl').unlink()
                        blocked.rmdir()

    @unittest.skipIf(os.getuid() == 0, 'Requires filesystem permission enforcement')
    def test_permission_errors_remain_fatal_for_project_root_and_provider_state(self):
        with ProfileFixture() as f:
            profile = f.load('work', {'state': {'share_host_provider_state': True}})
            paths = self.paths(f)
            project = profile.project.directory
            project.mkdir(parents=True)
            for blocked in (project, profile.state.claude_directory / 'projects'):
                blocked.mkdir(parents=True, exist_ok=True)
                blocked.chmod(0o000)
                try:
                    with self.subTest(blocked=blocked), self.assertRaises(PermissionError):
                        storage.validate_storage(profile, paths, f.host)
                finally:
                    blocked.chmod(0o700)

    def test_default_shares_original_t3_and_private_profile_has_host_home(self):
        with ProfileFixture() as f:
            default = f.load('default')
            mounts = storage.prepare_home(default, self.paths(f, 'default'), f.host)
            self.assertIn((f.host.home / '.t3', '/home/testuser/.t3'), mounts)
            private = f.load('work', {'state': {'share_host_t3_state': False}})
            paths = self.paths(f)
            self.assertEqual(paths.home, f.host.home / '.local/share/t3-sandbox/work/home')
            mounts = storage.prepare_home(private, paths, f.host)
            self.assertIn((paths.home, '/home/testuser'), mounts)
            self.assertIn((private.project.directory, '/workspace'), mounts)
            self.assertFalse(any(destination == '/home/testuser/.t3' for _, destination in mounts))
            self.assertFalse(paths.runtime.exists())
            self.assertFalse(paths.logs.exists())

    def test_browser_tmpfs_parent_is_created_before_podman_for_private_and_shared_state(self):
        with ProfileFixture() as f:
            for shared in (False, True):
                profile = f.load('work', {'state': {'share_host_t3_state': shared}})
                paths = self.paths(f)
                storage.prepare_home(profile, paths, f.host)
                t3 = profile.state.t3_directory if shared else paths.home / '.t3'
                self.assertTrue((t3 / 'tools').is_dir())
                self.assertEqual((t3 / 'tools').stat().st_uid, paths.home.stat().st_uid)

    def test_browser_tmpfs_parent_rejects_symlink_without_touching_target(self):
        with ProfileFixture() as f:
            profile = f.load('work', {'state': {'share_host_t3_state': False}})
            paths = self.paths(f)
            (paths.home / '.t3').mkdir(parents=True)
            target = f.root / 'unrelated-tools'
            target.mkdir()
            (paths.home / '.t3/tools').symlink_to(target, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, 'symlink'):
                storage.prepare_home(profile, paths, f.host)
            self.assertEqual(list(target.iterdir()), [])

    def test_provider_and_t3_sharing_flags_are_independent(self):
        with ProfileFixture() as f:
            for providers in (False, True):
                for t3 in (False, True):
                    with self.subTest(providers=providers, t3=t3):
                        profile = f.load('work', {'state': {'share_host_provider_state': providers, 'share_host_t3_state': t3}})
                        mounts = storage.prepare_home(profile, self.paths(f), f.host)
                        for leaf, shared in [('.codex', providers), ('.claude', providers), ('.t3', t3)]:
                            self.assertEqual(any(dst == f'/home/testuser/{leaf}' for _, dst in mounts), shared)
                            self.assertTrue((self.paths(f).home / leaf).is_dir())
                            if shared:
                                self.assertTrue((f.host.home / leaf).is_dir())

    def test_policy_runtime_and_logs_cannot_be_inside_any_writable_mount(self):
        # Removing real-path overlap checks exposes policy through a project or state bind.
        with ProfileFixture() as f:
            paths = self.paths(f)
            for protected in [paths.runtime, paths.logs, paths.profile_file.parent, paths.lock]:
                for source in [protected, protected.parent, protected / 'nested']:
                    for section, key in [('project', 'directory'), ('state', 'codex_directory'),
                                         ('state', 'claude_directory'), ('state', 't3_directory')]:
                        with self.subTest(source=source, key=key):
                            paths.profile_file.unlink(missing_ok=True)
                            profile = f.load('work', {section: {key: str(source)}, 'state': {
                                'share_host_provider_state': True, 'share_host_t3_state': True,
                                **({key: str(source)} if section == 'state' else {})}})
                            with self.assertRaises(ValueError):
                                storage.prepare_home(profile, paths, f.host)
                            self.assertFalse(paths.home.exists())
            # A mount root may itself be a symlink, or contain one to protected state.
            for target in [paths.runtime, paths.logs, f.profile_dir]:
                paths.profile_file.unlink(missing_ok=True)
                alias = f.root / 'alias'
                alias.symlink_to(target, target_is_directory=True)
                profile = f.load('work', {'project': {'directory': str(alias)}})
                with self.assertRaises(ValueError):
                    storage.validate_storage(profile, paths, f.host)
                alias.unlink()
            project = f.root / 'project'
            project.mkdir()
            (project / 'policy-link').symlink_to(paths.runtime / 'policy', target_is_directory=True)
            profile = f.load('work', {'project': {'directory': str(project)}})
            with self.assertRaises(ValueError):
                storage.prepare_home(profile, paths, f.host)

    def test_other_profile_runtime_and_logs_are_also_protected(self):
        with ProfileFixture() as f:
            other = self.paths(f, 'other')
            other.runtime.mkdir(parents=True)
            other.logs.mkdir()
            for directory in [other.runtime, other.logs, other.home.parent]:
                profile = f.load('work', {'project': {'directory': str(directory)}})
                with self.subTest(directory=directory), self.assertRaises(ValueError):
                    storage.prepare_home(profile, self.paths(f), f.host)
                self.assertFalse(self.paths(f).home.exists())

    def test_private_state_symlink_cannot_write_protected_state(self):
        with ProfileFixture() as f:
            profile = f.load('work', {'state': {'share_host_provider_state': False}})
            paths = self.paths(f)
            paths.home.mkdir(parents=True)
            for leaf in ['.codex', '.claude', '.t3']:
                link = paths.home / leaf
                link.symlink_to(paths.logs, target_is_directory=True)
                with self.subTest(leaf=leaf), self.assertRaises(ValueError):
                    storage.prepare_home(profile, paths, f.host)
                link.unlink()
            self.assertFalse(paths.logs.exists())

    def test_home_symlink_and_protected_directory_symlink_are_rejected(self):
        with ProfileFixture() as f:
            profile = f.load('work', {})
            paths = self.paths(f)
            paths.home.parent.mkdir(parents=True)
            paths.home.symlink_to(paths.runtime, target_is_directory=True)
            with self.assertRaises(ValueError):
                storage.prepare_home(profile, paths, f.host)
            paths.home.unlink()
            paths.runtime.symlink_to(profile.project.directory, target_is_directory=True)
            with self.assertRaises(ValueError):
                storage.prepare_home(profile, paths, f.host)

    def test_root_host_home_and_ancestor_mounts_are_rejected_before_creation(self):
        with ProfileFixture() as f:
            for source in [Path('/'), f.host.home, f.root]:
                profile = f.load('work', {'project': {'directory': str(source)}})
                with self.assertRaises(ValueError):
                    storage.prepare_home(profile, self.paths(f), f.host)
                self.assertFalse(self.paths(f).home.exists())

    def test_project_create_if_missing_and_files_are_respected(self):
        with ProfileFixture() as f:
            profile = f.load('work', {'project': {'create_if_missing': False}})
            with self.assertRaises(ValueError):
                storage.prepare_home(profile, self.paths(f), f.host)
            self.assertFalse(profile.project.directory.exists())
            self.assertFalse(self.paths(f).home.exists())
            profile.project.directory.parent.mkdir(parents=True)
            profile.project.directory.write_text('original')
            with self.assertRaises(ValueError):
                storage.prepare_home(profile, self.paths(f), f.host)
            self.assertEqual(profile.project.directory.read_text(), 'original')
            profile.project.directory.unlink()
            profile.project.directory.mkdir()
            storage.prepare_home(profile, self.paths(f), f.host)

    def test_state_switch_preserves_both_directories(self):
        with ProfileFixture() as f, FakePodman(f.root) as fake:
            profile = f.load('default')
            paths = self.paths(f, 'default')
            storage.prepare_home(profile, paths, f.host)
            directories = [paths.home / '.t3', f.host.home / '.t3', f.host.home / '.codex', f.host.home / '.claude']
            owners = {}
            for directory in directories:
                (directory / 'marker').write_text(str(directory))
                owners[directory] = (directory.stat().st_uid, directory.stat().st_gid)
            for share in (False, True):
                profile = f.load('default', {'state': {'share_host_t3_state': share, 'share_host_provider_state': share}})
                storage.prepare_home(profile, paths, f.host)
                for directory in directories:
                    self.assertEqual((directory / 'marker').read_text(), str(directory))
                    self.assertEqual((directory.stat().st_uid, directory.stat().st_gid), owners[directory])
            self.assertEqual(fake.calls(), [])

    def test_profile_mutation_locks_do_not_serialize_other_profiles(self):
        with ProfileFixture() as f, ThreadPoolExecutor(max_workers=2) as pool:
            entered = threading.Event()
            def acquire(paths):
                with storage.mutation_lock(paths):
                    entered.set()
            work, other = self.paths(f), self.paths(f, 'other')
            with storage.mutation_lock(work):
                pending = pool.submit(acquire, work)
                self.assertFalse(entered.wait(.1))
                pool.submit(acquire, other).result(timeout=2)
            pending.result(timeout=2)
            self.assertTrue(work.lock.is_file())
            self.assertFalse(work.runtime.exists())


class PodmanTests(unittest.TestCase):
    def podman(self):
        from t3_sandbox.podman import Podman
        return Podman()

    def test_owned_resource_lookup_survives_invalid_or_deleted_profile(self):
        with ProfileFixture() as f, FakePodman(f.root) as fake:
            identity = storage.ProfileIdentity('work', f.host.uid)
            resource = fake.add_container(identity.container)
            source = f.write('work', {})
            source.write_text('invalid: [')
            podman = self.podman()
            self.assertEqual(podman.inspect_owned('container', identity.container, identity, role='t3'), resource)
            source.unlink()
            self.assertEqual(podman.inspect_owned('container', identity.container, identity, role='t3'), resource)
            self.assertIsNone(podman.inspect('container', 'missing'))

    def test_similarly_named_unowned_container_is_never_removed(self):
        with ProfileFixture() as f, FakePodman(f.root) as fake:
            identity = storage.ProfileIdentity('work', f.host.uid)
            podman = self.podman()
            for labels in [{'managed': 'false'}, {'uid': '5678'}, {'profile': 'work-other'}, {'role': 'proxy'}]:
                fake.add_container(identity.container, **labels)
                with self.subTest(labels=labels), self.assertRaises(ValueError):
                    resource = podman.inspect_owned('container', identity.container, identity, role='t3')
                    if resource:
                        podman.run(['rm', identity.container])
            self.assertFalse(any(call[0] in ('rm', 'volume', 'unshare') for call in fake.calls()))
            self.assertIn(identity.container, fake.state['container'])

    def test_network_labels_and_unknown_role_are_checked(self):
        from t3_sandbox.podman import assert_owned
        identity = storage.ProfileIdentity('work', 1234)
        labels = {'io.t3-sandbox.managed': 'true', 'io.t3-sandbox.uid': '1234',
                  'io.t3-sandbox.profile': 'work', 'io.t3-sandbox.role': 'private'}
        assert_owned({'name': identity.private_network, 'labels': labels}, identity)
        labels['io.t3-sandbox.role'] = 'unknown'
        with self.assertRaises(ValueError):
            assert_owned({'labels': labels}, identity)

    def test_owned_lookup_derives_expected_role_from_identity(self):
        with ProfileFixture() as f, FakePodman(f.root) as fake:
            identity = storage.ProfileIdentity('work', f.host.uid)
            fake.add_container(identity.container, role='proxy')
            with self.assertRaises(ValueError):
                self.podman().inspect_owned('container', identity.container, identity)
            fake.add_container('t3-sandbox-1234-work-similar')
            with self.assertRaises(ValueError):
                self.podman().inspect_owned('container', 't3-sandbox-1234-work-similar', identity)

    def test_inspection_runtime_errors_and_malformed_json_are_not_missing(self):
        with ProfileFixture() as f, FakePodman(f.root) as fake:
            podman = self.podman()
            fake.state['failure'] = 'permission denied'
            fake.save()
            with self.assertRaises(subprocess.CalledProcessError):
                podman.inspect('container', 'missing')
            fake.state.pop('failure')
            fake.add_container('exists')
            for output in ['garbage', '[]', '[1]', '[{}, {}]']:
                fake.state['inspect_output'] = output
                fake.save()
                with self.subTest(output=output), self.assertRaises(ValueError):
                    podman.inspect('container', 'exists')

    def test_run_preserves_argument_boundaries_check_and_timeout(self):
        with ProfileFixture() as f, FakePodman(f.root) as fake:
            podman = self.podman()
            marker = f.root / 'executed'
            argument = f'$(touch {marker})'
            result = podman.run(['echo', argument])
            self.assertIn(argument, result.stdout)
            self.assertFalse(marker.exists())
            fake.state['failure'] = 'failure'
            fake.save()
            self.assertEqual(podman.run(['info'], check=False).returncode, 125)
            with self.assertRaises(subprocess.CalledProcessError):
                podman.run(['info'])
            fake.state = {'sleep': 1}
            fake.save()
            with self.assertRaises(subprocess.TimeoutExpired):
                podman.run(['info'], timeout=.05)

    def test_t3_conflicts_use_actual_mounts_and_canonical_overlaps(self):
        with ProfileFixture() as f, FakePodman(f.root) as fake:
            podman = self.podman()
            identity = storage.ProfileIdentity('work', f.host.uid)
            profile = f.load('work', {'state': {'share_host_t3_state': True}})
            paths = storage.profile_paths(identity, f.profile_dir, f.host)
            original = f.host.home / '.t3'
            original.mkdir()
            alias = f.root / 't3-alias'
            alias.symlink_to(original, target_is_directory=True)
            for source in [alias, original / 'nested', original.parent]:
                fake.add_container('t3-sandbox-1234-other', profile='other', mounts=[
                    {'Type': 'bind', 'Source': str(source), 'Destination': '/home/testuser/.t3'}])
                with self.subTest(source=source), self.assertRaises(ValueError):
                    storage.validate_t3_state_sharing(profile, paths, f.host, podman)
            # Saved YAML does not determine what a running resource actually mounts.
            fake.state['container'].clear()
            fake.add_container(identity.container, mounts=[
                {'Type': 'bind', 'Source': str(original), 'Destination': '/home/testuser/.t3'}])
            storage.validate_t3_state_sharing(profile, paths, f.host, podman)
            fake.add_container('t3-sandbox-1234-other', profile='other', running=False, mounts=[
                {'Type': 'bind', 'Source': str(original), 'Destination': '/home/testuser/.t3'}])
            storage.validate_t3_state_sharing(profile, paths, f.host, podman)
            fake.state['container'].clear()
            fake.add_container('t3-sandbox-1234-other', profile='other', mounts=[
                {'Type': 'bind', 'Source': str(paths.home), 'Destination': '/home/testuser'}])
            # Private-state conflict: the effective .t3 is under the mounted home.
            profile = replace(profile, state=replace(profile.state, share_host_t3_state=False))
            with self.assertRaises(ValueError):
                storage.validate_t3_state_sharing(profile, paths, f.host, podman)


class HostOwnershipTests(unittest.TestCase):
    def setUp(self):
        from t3_sandbox.launcher import Launcher
        self.f = self.enterContext(ProfileFixture())
        self.profile = self.f.load('work', {'state': {'share_host_t3_state': True}})
        self.launcher = Launcher(None, self.f.host, self.f.profile_dir)
        self.directory = self.profile.state.t3_directory / 'userdata'
        self.directory.mkdir(parents=True)
        self.lock = self.directory / 'server-owner.sqlite'
        self.record = self.directory / 'server-runtime.json'
        self.record.write_text(json.dumps({'version': 1, 'pid': os.getpid(), 'ownerId': 'old-container'}))

    def test_host_exclusive_lock_blocks_without_runtime_record_or_state_writes(self):
        self.record.unlink()
        with sqlite3.connect(self.lock) as owner:
            owner.execute('BEGIN EXCLUSIVE')
            before = self.lock.read_bytes()
            with self.assertRaisesRegex(ValueError, 'host T3 server'):
                self.launcher._host_t3_preflight(self.profile)
            # The probe cannot release or replace another server's transaction.
            self.assertTrue(owner.in_transaction)
            self.assertEqual(self.lock.read_bytes(), before)
            owner.rollback()
        self.launcher._host_t3_preflight(self.profile)
        self.assertEqual(self.lock.read_bytes(), before)
        self.assertFalse(self.record.exists())

    def test_stale_container_record_with_unlocked_database_is_accepted(self):
        sqlite3.connect(self.lock).close()
        before = {p.name: p.read_bytes() for p in self.directory.iterdir()}
        self.launcher._host_t3_preflight(self.profile)
        self.assertEqual({p.name: p.read_bytes() for p in self.directory.iterdir()}, before)

    def test_corrupt_or_unreadable_ownership_lock_fails_closed(self):
        self.lock.write_bytes(b'corrupt SQLite database')
        with self.assertRaisesRegex(ValueError, 'permissions and integrity'):
            self.launcher._host_t3_preflight(self.profile)
        self.assertEqual(self.lock.read_bytes(), b'corrupt SQLite database')
        with patch('t3_sandbox.launcher.sqlite3.connect', side_effect=sqlite3.OperationalError('unable to open database file')):
            with self.assertRaisesRegex(ValueError, 'permissions and integrity'):
                self.launcher._host_t3_preflight(self.profile)

    def test_wal_ownership_lock_is_explicitly_unsupported(self):
        with sqlite3.connect(self.lock) as owner:
            owner.execute('PRAGMA journal_mode=WAL')
            owner.execute('BEGIN EXCLUSIVE')
            before = {p.name: p.read_bytes() for p in self.directory.iterdir()}
            with self.assertRaisesRegex(ValueError, 'journal mode'):
                self.launcher._host_t3_preflight(self.profile)
            self.assertEqual({p.name: p.read_bytes() for p in self.directory.iterdir()}, before)


if __name__ == '__main__':
    unittest.main()
