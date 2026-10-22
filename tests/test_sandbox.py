"""Launcher regression tests with only disposable profiles and fake Podman."""
from dataclasses import replace
import os
import json
from pathlib import Path
import pwd
import subprocess
import fcntl
import time
import unittest

from support import FakePodman, ProfileFixture

ROOT = Path(__file__).resolve().parents[1]


class LauncherTests(unittest.TestCase):
    def setUp(self):
        self.f = self.enterContext(ProfileFixture())
        self.f.host = replace(self.f.host, uid=os.getuid(), gid=os.getgid(), user=pwd.getpwuid(os.getuid()).pw_name)
        self.fake = self.enterContext(FakePodman(self.f.root))
        self.f.write('work', {'server': {'port': 3774}})
        self.env = dict(os.environ, HOME=str(self.f.host.home), PROFILE_DIR=str(self.f.profile_dir))

    def run_make(self, command, profile='work', **settings):
        return subprocess.run(['make', '--no-print-directory', command, 'PROFILE=' + profile,
                               *[key + '=' + str(value) for key, value in settings.items()]],
                              cwd=ROOT, env=self.env, capture_output=True, text=True)

    def start(self):
        built = self.run_make('build')
        self.assertEqual(built.returncode, 0, built.stderr)
        return self.run_make('start')

    def existing(self):
        result = self.start()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.fake.reload()
        return next(iter(self.fake.state['container'].values()))

    def test_unrestricted_named_profile_uses_bind_home_and_no_proxy(self):
        result = self.start()
        self.assertEqual(result.returncode, 0, result.stderr)
        run = self.fake.last_t3_run()
        self.assertIn('0.0.0.0:3774:3773', run)
        self.assertIn('--network=slirp4netns:allow_host_loopback=false', run)
        self.assertFalse(self.fake.created_proxy_resources())
        self.assertNotIn('--volume', run)
        self.assertTrue(any('src=' + str(self.f.host.home / '.local/share/t3-sandbox/work/home') in item for item in run))

    def test_restricted_build_includes_separate_gateway_image(self):
        self.f.write('work', {'network': {'restricted': True}})
        result = self.run_make('build')
        self.assertEqual(result.returncode, 0, result.stderr)
        builds = [call for call in self.fake.calls() if call[0] == 'build']
        self.assertEqual(len(builds), 2)
        proxy = next(call for call in builds if str(ROOT / 'proxy/Dockerfile') in call)
        self.assertIn(f'localhost/t3-code-proxy:{os.getuid()}-work', proxy)
        self.assertIn('io.t3-sandbox.role=proxy', proxy)
        self.assertFalse(any(value.startswith('HOST_UID=') for value in proxy))

    def test_exited_container_uses_configured_port(self):
        container = self.existing()
        container['State']['Running'] = False
        self.fake.save()
        result = self.run_make('start')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(any(call[0] == 'start' for call in self.fake.calls()))
        self.assertFalse(any(call[0] == 'port' for call in self.fake.calls()))

    def test_immediate_exit_is_reported(self):
        self.fake.state['exit_on_start'] = True
        self.fake.save()
        result = self.start()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('exited', result.stderr)
        self.assertIn('78', result.stderr)

    def test_different_configured_port_is_rejected(self):
        self.existing()
        self.f.write('work', {'server': {'port': 3775}})
        result = self.run_make('start')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('recreate', result.stderr)
        self.assertFalse(any(call[0] == 'start' for call in self.fake.calls()))

    def test_different_project_is_rejected(self):
        self.existing()
        self.f.write('work', {'project': {'directory': str(self.f.host.home / 'another-project')}})
        result = self.run_make('start')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('recreate', result.stderr)

    def test_private_t3_keeps_provider_mounts_and_disables_timers(self):
        self.f.write('work', {'state': {'share_host_provider_state': True, 'share_host_t3_state': False}})
        result = self.start()
        self.assertEqual(result.returncode, 0, result.stderr)
        args = self.fake.last_t3_run()
        self.assertIn('--no-healthcheck', args)
        mounts = [args[i + 1] for i, arg in enumerate(args) if arg == '--mount']
        self.assertEqual(len(mounts), 4)
        self.assertTrue(any(m.endswith('/.codex') for m in mounts))
        self.assertTrue(any(m.endswith('/.claude') for m in mounts))
        self.assertFalse(any(m.endswith('/.t3') for m in mounts))

    def test_stop_and_status_work_with_invalid_whitelist(self):
        self.existing()
        self.f.write('work', {'network': {'allow': {'ports': ['invalid']}}})
        self.assertEqual(self.run_make('status').returncode, 0)
        self.assertEqual(self.run_make('stop').returncode, 0)
        self.fake.reload()
        self.assertFalse(next(iter(self.fake.state['container'].values()))['State']['Running'])
        (self.f.profile_dir / 'work.yaml').unlink()
        self.assertEqual(self.run_make('remove').returncode, 0)

    def test_recreate_preserves_home_and_host_t3_markers(self):
        self.existing()
        markers = [self.f.host.home / '.local/share/t3-sandbox/work/home/keep', self.f.host.home / '.t3/keep']
        for marker in markers:
            marker.parent.mkdir(parents=True, exist_ok=True)
            marker.write_text('retained')
        self.assertEqual(self.run_make('recreate').returncode, 0)
        for marker in markers:
            self.assertEqual(marker.read_text(), 'retained')

    def test_default_shared_t3_reports_host_server_lock_conflict(self):
        record = self.f.host.home / '.t3/userdata/server-runtime.json'
        record.parent.mkdir(parents=True)
        contents = json.dumps({'version': 1, 'pid': os.getpid(), 'port': 3773,
                               'origin': 'http://127.0.0.1:3773', 'startedAt': '2026-10-22T00:00:00Z'})
        record.write_text(contents)
        self.f.write('default', {})
        result = self.run_make('start', profile='default')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('host T3 server', result.stderr)
        self.assertEqual(record.read_text(), contents)
        self.assertFalse(any(call[0] in ('run', 'start') for call in self.fake.calls()))

    def test_changed_resources_require_recreate(self):
        self.existing()
        self.f.write('work', {'resources': {'memory': '2g'}})
        result = self.run_make('start')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('recreate', result.stderr)

    def test_selector_with_shell_metacharacters_never_executes(self):
        marker = self.f.root / 'executed'
        for name in [f'work;touch {marker}', f'$(touch {marker})', '--help']:
            result = self.run_make('start', profile=name)
            self.assertNotEqual(result.returncode, 0)
        self.assertFalse(marker.exists())
        self.assertEqual(self.fake.calls(), [])

    def test_make_profile_expression_is_rejected_without_host_evaluation(self):
        result = self.run_make('start', profile='$(shell printf SELECTOR_EVALUATED >&2)')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Profile name', result.stderr)
        self.assertNotIn('SELECTOR_EVALUATED', result.stderr)
        self.assertEqual(self.fake.calls(), [])

    def test_make_exports_never_evaluate_expressions_for_any_input(self):
        for key in ('PROFILE', 'PROFILE_DIR', 'CMD', 'FOLLOW', 'TAIL'):
            with self.subTest(key=key):
                expression = '$(shell printf INPUT_EVALUATED >&2)'
                result = subprocess.run(['make', '--no-print-directory', 'help', key + '=' + expression],
                                        cwd=ROOT, env=self.env, capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertNotIn('INPUT_EVALUATED', result.stderr)
        self.assertEqual(self.fake.calls(), [])

    def test_make_preserves_literal_dollars_in_container_command(self):
        self.existing()
        command = 'printf "%s" "$HOME" "$(printf container)" "${VAR:-fallback}" "$$"'
        result = self.run_make('exec', CMD=command)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.fake.calls()[-1][-3:], ['bash', '-c', command])

    def test_make_uses_environment_defaults_without_expanding_command(self):
        self.existing()
        command = 'printf "%s" "$HOME" "$(printf container)"'
        env = dict(self.env, PROFILE='work', CMD=command, FOLLOW='0', TAIL='9')
        result = subprocess.run(['make', '--no-print-directory', 'exec'], cwd=ROOT,
                                env=env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.fake.calls()[-1][-3:], ['bash', '-c', command])
        result = subprocess.run(['make', '--no-print-directory', 'logs'], cwd=ROOT,
                                env=env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.fake.calls()[-1][:3], ['logs', '--tail', '9'])
        self.assertNotIn('--follow', self.fake.calls()[-1])

    def test_cli_selectors_override_environment_defaults_as_literal_arguments(self):
        env = dict(self.env, PROFILE='invalid selector', PROFILE_DIR=str(self.f.root / 'unused'))
        result = subprocess.run(['bash', str(ROOT / 'scripts/sandbox.sh'), 'config',
                                 '--profile', 'work', '--profile-dir', str(self.f.profile_dir)],
                                cwd=ROOT, env=env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(str(self.f.profile_dir / 'work.yaml'), result.stdout)
        self.assertEqual(self.fake.calls(), [])

    def test_unsafe_build_selector_rejected_before_podman(self):
        self.f.write('work', {'build': {'t3_version': 'latest; touch /tmp/forbidden'}})
        self.assertNotEqual(self.run_make('build').returncode, 0)
        self.assertEqual(self.fake.calls(), [])

    def test_restricted_startup_reports_unsupported_without_running_t3(self):
        self.f.write('work', {'network': {'restricted': True}})
        result = self.run_make('start')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('not implemented', result.stderr)
        self.assertFalse(any(call[0] in ('run', 'start') for call in self.fake.calls()))

    def test_storage_validation_precedes_any_container_start(self):
        self.f.write('work', {'project': {'directory': str(self.f.profile_dir)}})
        result = self.run_make('start')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('protected', result.stderr)
        self.assertFalse(any(call[0] in ('run', 'start') for call in self.fake.calls()))

    def test_shared_t3_rejects_active_other_managed_mount(self):
        self.f.write('work', {'state': {'share_host_t3_state': True}})
        self.fake.add_container('other', uid=str(os.getuid()), profile='other', mounts=[{
            'Type': 'bind', 'Source': str(self.f.host.home / '.t3'), 'Destination': '/home/' + self.f.host.user + '/.t3'}])
        result = self.run_make('start')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('already in use', result.stderr)

    def test_config_does_not_print_runtime_env_contents(self):
        secret = self.f.root / 'runtime.env'
        secret.write_text('KEY=secret-value')
        self.f.write('work', {'runtime': {'env_file': str(secret)}})
        result = self.run_make('config')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn('secret-value', result.stdout + result.stderr)
        self.assertIn(str(secret), result.stdout)

    def test_pair_rewrites_endpoint_and_retains_token(self):
        self.existing()
        result = self.run_make('pair')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('http://127.0.0.1:3774/#token=secret-token', result.stdout)

    def test_exec_passes_command_as_one_container_argument(self):
        self.existing()
        command = 'printf "%s" "hello; world"'
        result = self.run_make('exec', CMD=command)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.fake.calls()[-1][-3:], ['bash', '-c', command])

    def test_runtime_env_resources_and_health_flags_reach_podman(self):
        env_file = self.f.root / 'secrets.env'
        env_file.write_text('KEY=runtime-secret')
        self.f.write('work', {'runtime': {'env_file': str(env_file), 'automatic_healthcheck': True},
                              'resources': {'memory': None, 'cpus': None, 'pids_limit': 512}})
        result = self.start()
        self.assertEqual(result.returncode, 0, result.stderr)
        args = self.fake.last_t3_run()
        self.assertNotIn('--no-healthcheck', args)
        self.assertNotIn('--memory', args)
        self.assertNotIn('--cpus', args)
        self.assertEqual(args[args.index('--pids-limit') + 1], '512')
        self.assertEqual(args[args.index('--env-file') + 1], str(env_file))
        self.assertNotIn('runtime-secret', result.stdout + result.stderr)

    def test_unowned_image_is_rejected(self):
        self.assertEqual(self.run_make('build').returncode, 0)
        self.fake.reload()
        image = next(iter(self.fake.state['image'].values()))
        image['Config']['Labels']['io.t3-sandbox.managed'] = 'false'
        self.fake.save()
        result = self.run_make('start')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('unowned', result.stderr)
        self.assertFalse(any(call[0] == 'run' for call in self.fake.calls()))

    def test_logs_recover_without_yaml_and_honor_follow_tail(self):
        self.existing()
        (self.f.profile_dir / 'work.yaml').unlink()
        result = self.run_make('logs', FOLLOW=0, TAIL=7)
        self.assertEqual(result.returncode, 0, result.stderr)
        call = self.fake.calls()[-1]
        self.assertEqual(call[:3], ['logs', '--tail', '7'])
        self.assertNotIn('--follow', call)

    def test_lifecycle_waits_for_profile_mutation_lock(self):
        self.existing()
        lock = self.f.host.home / '.local/share/t3-sandbox/work/.mutation.lock'
        with lock.open('a') as stream:
            fcntl.flock(stream, fcntl.LOCK_EX)
            child = subprocess.Popen(['make', '--no-print-directory', 'stop', 'PROFILE=work'],
                                     cwd=ROOT, env=self.env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                time.sleep(0.15)
                self.assertIsNone(child.poll())
                self.assertFalse(any(call[0] == 'stop' for call in self.fake.calls()))
            finally:
                fcntl.flock(stream, fcntl.LOCK_UN)
                stdout, stderr = child.communicate(timeout=5)
        self.assertEqual(child.returncode, 0, stderr)
        self.assertTrue(any(call[0] == 'stop' for call in self.fake.calls()))

    def test_allowlist_edits_do_not_require_recreate(self):
        self.existing()
        self.f.write('work', {'network': {'allow': {'domains': ['example.org']}}})
        self.assertEqual(self.run_make('start').returncode, 0)

    def test_default_profile_auto_initializes_without_podman_for_config(self):
        result = self.run_make('config', profile='default')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((self.f.profile_dir / 'default.yaml').exists())
        self.assertIn('3773', result.stdout)
        self.assertEqual(self.fake.calls(), [])

    def test_smoke_checks_published_http_and_removes_only_its_probe(self):
        self.existing()
        project = self.f.host.home / 'projects/t3-sandbox/work'
        keep = project / 'keep'
        keep.write_text('untouched')
        curl = self.fake.root / 'curl'
        curl.write_text('#!/usr/bin/python3\nimport json, os, sys\nwith open(os.environ["CALL_LOG"], "a") as out: out.write(json.dumps(["host-curl", *sys.argv[1:]]) + "\\n")\n')
        curl.chmod(0o755)
        result = self.run_make('smoke')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(any(call[0] == 'host-curl' and 'http://127.0.0.1:3774' in call for call in self.fake.calls()))
        self.assertFalse(list(project.glob('.t3-permission-check.*')))
        self.assertEqual(keep.read_text(), 'untouched')

    def test_build_selector_change_does_not_require_recreate(self):
        self.existing()
        self.f.write('work', {'build': {'t3_version': '0.1.0'}})
        self.assertEqual(self.run_make('start').returncode, 0)


if __name__ == '__main__':
    unittest.main()
