"""Exercise launcher behavior without touching real containers or credentials."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
FAKE_PODMAN = '''#!/usr/bin/env python3
import json, os, sys
a = sys.argv[1:]
with open(os.environ['CALL_LOG'], 'a') as f:
    f.write(json.dumps(a) + '\\n')
if a[0] == 'info': print('true')
elif a[:2] == ['container', 'exists']:
    sys.exit(0 if os.environ.get('EXISTS') == '1' else 1)
elif a[0] == 'inspect':
    template = a[a.index('--format') + 1]
    if '.Mounts' in template: print(os.environ['PROJECT_DIR'])
    elif 'PortBindings' in template: print(json.dumps({'3773/tcp': [{'HostIp': '127.0.0.1', 'HostPort': os.environ.get('CONFIGURED_PORT', '43776')}]}))
    elif 'state-mounts' in template: print('')
    elif '.State.Running' in template:
        calls = [json.loads(s) for s in open(os.environ['CALL_LOG'])]
        started = any(c[0] in ('start', 'run') for c in calls)
        print('true' if started and os.environ.get('STARTED') == '1' else 'false')
    elif '.State.ExitCode' in template: print('78')
    else: sys.exit('Unexpected inspect: ' + template)
elif a[0] == 'port': pass  # Exited containers have no live port output.
elif a[:2] == ['image', 'exists']: pass
elif a[:2] == ['image', 'inspect']: print(os.environ['IDENTITY'])
elif a[0] in ('start', 'run'): print('fake-container')
elif a[0] == 'exec': pass
else: sys.exit('Unexpected call: ' + repr(a))
'''


class LauncherTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='t3-launcher-test-')
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name)
        (self.path / 'project').mkdir()
        fake = self.path / 'podman'
        fake.write_text(FAKE_PODMAN)
        fake.chmod(0o755)
        user = subprocess.check_output(['id', '-un'], text=True).strip()
        self.env = dict(os.environ, PATH=str(self.path) + ':' + os.environ['PATH'],
                        CALL_LOG=str(self.path / 'calls'),
                        PROJECT_DIR=str(self.path / 'project'), SHARE_HOST_STATE='0',
                        SANDBOX='regression', HOST_PORT='43776', MEMORY='', CPUS='',
                        AUTO_HEALTHCHECK='0', SHARE_HOST_T3_STATE='1',
                        IDENTITY=f'{os.getuid()}:{os.getgid()}:{user}', EXISTS='1', STARTED='1')

    def start(self):
        return subprocess.run(['bash', str(ROOT / 'scripts/sandbox.sh'), 'start'],
                              env=self.env, capture_output=True, text=True)

    def calls(self):
        return [json.loads(line) for line in (self.path / 'calls').read_text().splitlines()]

    def test_exited_container_uses_configured_port(self):
        result = self.start()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(any(call[0] == 'start' for call in self.calls()))
        self.assertFalse(any(call[0] == 'port' for call in self.calls()))

    def test_immediate_exit_is_reported(self):
        self.env['STARTED'] = '0'
        result = self.start()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('exited', result.stderr)
        self.assertIn('78', result.stderr)

    def test_different_configured_port_is_rejected(self):
        self.env['CONFIGURED_PORT'] = '43777'
        result = self.start()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Project or port changed', result.stderr)
        self.assertFalse(any(call[0] == 'start' for call in self.calls()))

    def test_private_t3_keeps_provider_mounts_and_disables_timers(self):
        self.env.update(EXISTS='0', SHARE_HOST_STATE='1', SHARE_HOST_T3_STATE='0')
        for var, leaf in [('HOST_CODEX_DIR', 'codex'), ('HOST_CLAUDE_DIR', 'claude')]:
            directory = self.path / leaf
            directory.mkdir()
            self.env[var] = str(directory)
        self.env['HOST_T3_DIR'] = str(self.path / 'unused-missing-t3')
        result = self.start()
        self.assertEqual(result.returncode, 0, result.stderr)
        args = next(c for c in self.calls() if c[0] == 'run')
        self.assertIn('--no-healthcheck', args)
        mounts = [args[i + 1] for i, arg in enumerate(args) if arg == '--mount']
        self.assertEqual(len(mounts), 3)
        self.assertTrue(any(m.endswith('/.codex') for m in mounts))
        self.assertTrue(any(m.endswith('/.claude') for m in mounts))
        self.assertFalse(any(m.endswith('/.t3') for m in mounts))


if __name__ == '__main__':
    unittest.main()
