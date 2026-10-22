"""Browser provisioning and runtime contracts; all state is disposable."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from support import ProfileFixture
from t3_sandbox import launcher

ROOT = Path(__file__).resolve().parents[1]


class BrowserAssetsTests(unittest.TestCase):
    def setUp(self):
        self.temp = self.enterContext(tempfile.TemporaryDirectory())
        self.root = Path(self.temp)

    def browser_module(self):
        path = ROOT / 'scripts/t3_sandbox/browser.py'
        self.assertTrue(path.is_file(), 'local browser verification/seeding is not implemented')
        spec = importlib.util.spec_from_file_location('browser', path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def fixture(self):
        image = self.root / 'image'
        exe = image / 'linux64/154.0.8037.92/chrome-headless-shell'
        exe.parent.mkdir(parents=True)
        exe.write_text('#!/bin/sh\nprintf "Google Chrome for Testing 154.0.8037.92\\n"\n')
        exe.chmod(0o755)
        t3 = self.root / 't3'
        t3.write_text('#!/bin/sh\nprintf "t3 v0.1.0\\n"\n')
        t3.chmod(0o755)
        manifest = {'schema': 1, 't3_version': 't3 v0.1.0',
                    't3_files': {str(t3): hashlib.sha256(t3.read_bytes()).hexdigest()},
                    'platform': 'linux64', 'browser_version': '154.0.8037.92',
                    'executable': 'linux64/154.0.8037.92/chrome-headless-shell',
                    'assets': {'linux64/154.0.8037.92/chrome-headless-shell': hashlib.sha256(exe.read_bytes()).hexdigest()}}
        (image / 'manifest.json').write_text(json.dumps(manifest))
        cache = self.root / 'empty-home/.t3/tools/chrome-headless-shell'
        cache.mkdir(parents=True)
        mountinfo = self.root / 'mountinfo'
        mountinfo.write_text(f'1 0 0:1 / {cache} rw - tmpfs tmpfs rw\n')
        return image, t3, cache, mountinfo

    def test_seed_is_local_and_works_with_empty_home(self):
        image, t3, cache, mountinfo = self.fixture()
        self.browser_module().seed(image, t3, cache, ROOT / 'scripts/browser-launcher.sh', mountinfo)
        entry = cache / 'linux64/154.0.8037.92/chrome-headless-shell'
        self.assertTrue(entry.is_file())
        self.assertTrue(os.access(entry, os.X_OK))

    def test_existing_shared_t3_cache_is_not_modified_without_tmpfs(self):
        image, t3, cache, mountinfo = self.fixture()
        sentinel = cache / 'host-browser'
        sentinel.write_bytes(b'original-host-browser')
        mountinfo.write_text(f'1 0 0:1 / {cache} rw - ext4 /dev/sda rw\n')
        with self.assertRaisesRegex(ValueError, 'tmpfs'):
            self.browser_module().seed(image, t3, cache, ROOT / 'scripts/browser-launcher.sh', mountinfo)
        self.assertEqual(sentinel.read_bytes(), b'original-host-browser')
        self.assertEqual(list(cache.iterdir()), [sentinel])

    def test_browser_asset_version_mismatch_fails_before_server_start(self):
        image, t3, cache, mountinfo = self.fixture()
        t3.write_text('#!/bin/sh\necho "t3 v99"\n')
        with self.assertRaisesRegex(ValueError, 'T3|mismatch'):
            self.browser_module().seed(image, t3, cache, ROOT / 'scripts/browser-launcher.sh', mountinfo)
        self.assertEqual(list(cache.iterdir()), [])

    def test_corrupted_asset_fails_before_seeding(self):
        image, t3, cache, mountinfo = self.fixture()
        (image / 'linux64/154.0.8037.92/chrome-headless-shell').write_bytes(b'corrupt')
        with self.assertRaisesRegex(ValueError, 'asset|hash'):
            self.browser_module().seed(image, t3, cache, ROOT / 'scripts/browser-launcher.sh', mountinfo)
        self.assertEqual(list(cache.iterdir()), [])

    def wrapper(self, args, proxy=''):
        source = ROOT / 'scripts/browser-launcher.sh'
        self.assertTrue(source.is_file(), 'browser wrapper is not implemented')
        fake = self.root / 'executable'
        fake.write_text('#!/usr/bin/python3\nimport json,sys\nprint(json.dumps(sys.argv[1:]))\n')
        fake.chmod(0o755)
        script = self.root / 'wrapper'
        script.write_text(source.read_text().replace('/opt/t3-browser/executable', str(fake)))
        script.chmod(0o755)
        result = subprocess.run([str(script), *args], capture_output=True, text=True,
                                env=dict(os.environ, T3_SANDBOX_BROWSER_PROXY=proxy))
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def test_wrapper_preserves_argv_and_handles_version_probe(self):
        args = ['--user-data-dir=/tmp/a b', '$(touch NOPE)', ';echo bad', '--version']
        self.assertEqual(self.wrapper(args, 'http://10.89.0.2:3128'), args)
        self.assertFalse((ROOT / 'NOPE').exists())

    def test_restricted_wrapper_replaces_upstream_socks_and_retains_loopback(self):
        args = self.wrapper(['--proxy-server=socks5://127.0.0.1:8000', '--proxy-bypass-list=<-loopback>',
                             '--no-proxy-server', '--proxy-pac-url', 'http://bad/proxy', 'about:blank'],
                            'http://10.89.0.2:3128')
        self.assertIn('--proxy-server=http://10.89.0.2:3128', args)
        self.assertIn('--proxy-bypass-list=localhost;127.0.0.1;[::1]', args)
        self.assertNotIn('--no-sandbox', args)
        self.assertNotIn('--no-proxy-server', args)
        self.assertFalse(any('socks5' in a or 'bad/proxy' in a for a in args))
        self.assertIn('about:blank', args)

    def test_unrestricted_wrapper_uses_no_proxy(self):
        args = ['--proxy-server=socks5://127.0.0.1:8000', 'about:blank']
        self.assertEqual(self.wrapper(args), args)

    def test_browser_cache_mount_is_only_cache_subtree(self):
        with ProfileFixture() as fixture:
            profile = fixture.load('work', {})
            self.assertTrue(hasattr(launcher, 'browser_cache_mount'), 'missing browser cache mount')
            self.assertEqual(launcher.browser_cache_mount(profile, fixture.host),
                ['--tmpfs', '/home/testuser/.t3/tools/chrome-headless-shell:rw,nosuid,nodev,exec,mode=1777,notmpcopyup'])

    def test_runtime_env_file_cannot_override_selected_proxy(self):
        with ProfileFixture() as fixture:
            envfile = fixture.root / 'runtime.env'
            envfile.write_text('HTTPS_PROXY=http://wrong\nT3_SANDBOX_BROWSER_PROXY=http://wrong\n')
            profile = fixture.load('work', {'network': {'restricted': True}, 'runtime': {'env_file': str(envfile)}})
            calls = []
            class Recorder:
                def run(self, args, **kwargs): calls.append(args)
            launch = launcher.Launcher(Recorder(), fixture.host, fixture.profile_dir)
            from t3_sandbox.paths import ProfileIdentity, profile_paths
            paths = profile_paths(ProfileIdentity(profile.name, fixture.host.uid), fixture.profile_dir, fixture.host)
            self.assertIn('browser_proxy', __import__('inspect').signature(launch._create_t3).parameters, 'missing authoritative proxy environment')
            with patch.object(launcher.storage, 'prepare_home', return_value=[]):
                launch._create_t3(profile, paths, ProfileIdentity('work', fixture.host.uid), {'Id':'test'},
                    network_args=[], publish_args=[], browser_proxy='http://10.89.0.2:3128')
            args = calls[0]
            env = {args[i+1].split('=', 1)[0]: args[i+1].split('=', 1)[1]
                   for i, value in enumerate(args) if value == '--env'}
            for key in ('HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'http_proxy', 'https_proxy', 'all_proxy', 'T3_SANDBOX_BROWSER_PROXY'):
                self.assertEqual(env[key], 'http://10.89.0.2:3128')
                self.assertGreater(args.index(key + '=' + env[key]), args.index('--env-file'))
            self.assertEqual(env['NO_PROXY'], 'localhost,127.0.0.1,::1')
            self.assertEqual(env['no_proxy'], env['NO_PROXY'])
            self.assertEqual(env['NODE_USE_ENV_PROXY'], '1')

    def installer(self):
        path = ROOT / 'scripts/install-t3-browser.py'
        self.assertTrue(path.is_file(), 'installed-T3 provisioning helper is missing')
        spec = importlib.util.spec_from_file_location('installer', path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_installer_copies_only_verified_browser_assets_and_manifest(self):
        image, t3, cache, mountinfo = self.fixture()
        browser = cache / 'linux64/154.0.8037.92/chrome-headless-shell'
        browser.parent.mkdir(parents=True)
        browser.write_bytes((image / 'linux64/154.0.8037.92/chrome-headless-shell').read_bytes())
        browser.chmod(0o755)
        (cache.parent / 'credentials.sqlite').write_text('do not copy')
        (browser.parent / 'resource.pak').write_text('browser resource')
        (browser.parent / 'resource.pak').chmod(0o600)
        destination = self.root / 'output'
        self.installer().publish(cache, destination, t3, [t3])
        manifest = json.loads((destination / 'manifest.json').read_text())
        self.assertEqual(manifest['browser_version'], '154.0.8037.92')
        self.assertEqual(manifest['platform'], 'linux64')
        self.assertIn('linux64/154.0.8037.92/resource.pak', manifest['assets'])
        self.assertEqual((destination / 'executable').resolve(), destination / manifest['executable'])
        self.assertFalse((destination / 'credentials.sqlite').exists())
        self.assertTrue((destination / 'linux64/154.0.8037.92/resource.pak').stat().st_mode & 0o004, 'browser resources must be readable by the runtime user')
        self.browser_module().verify(destination, t3)

    def test_installer_rejects_incomplete_or_wrong_version_download(self):
        image, t3, cache, mountinfo = self.fixture()
        browser = cache / 'linux64/154.0.8037.92/chrome-headless-shell'
        browser.parent.mkdir(parents=True)
        browser.write_text('#!/bin/sh\necho "Chrome 99.1.1.1"\n')
        browser.chmod(0o755)
        destination = self.root / 'output'
        with self.assertRaisesRegex(ValueError, 'version'):
            self.installer().publish(cache, destination, t3, [t3])
        self.assertFalse(destination.exists())

    def test_build_mcp_initializes_session_before_thread_scoped_tool(self):
        module = self.installer()
        self.assertTrue(hasattr(module, 'trigger_preview'), 'MCP session handshake is missing')
        calls = []
        def service(port, token, path, payload=None, session=None):
            calls.append((path, payload))
            if payload and payload['method'] == 'initialize':
                session['Mcp-Session-Id'] = 'local-session'
                return {'result': {'protocolVersion': '2025-03-26'}}
            if payload and payload['method'] == 'tools/call':
                self.assertEqual(session['Mcp-Session-Id'], 'local-session')
                return {'error': {'message': 'This tool requires thread scope'}}
            if path == '/ws': return {'orchestrationProtocolVersion': 2}
            raise AssertionError('Unexpected local API request')
        with patch.object(module, 'request', side_effect=service), patch.object(module, 'preview_socket', return_value='socket'):
            self.assertEqual(module.trigger_preview(1234, lambda subject: 'local-token'), 'socket')
        self.assertEqual([call[1]['method'] for call in calls if call[1]], ['initialize', 'tools/call'])

    def test_build_does_not_fallback_for_unrelated_mcp_failure(self):
        module = self.installer()
        self.assertTrue(hasattr(module, 'trigger_preview'), 'MCP compatibility check is missing')
        with patch.object(module, 'request', return_value={'error': {'message': 'No such method'}}):
            with self.assertRaisesRegex(ValueError, 'initialize'):
                module.trigger_preview(1234, lambda subject: 'local-token')

    def test_new_npm_launcher_materializes_native_runtime_for_empty_offline_home(self):
        module = self.installer()
        self.assertTrue(hasattr(module, 'materialize'), 'npm runtime still depends on the overlaid home')
        package = self.root / 'npm/t3'
        (package / 'bin').mkdir(parents=True)
        (package / 'package.json').write_text('{"version":"0.1.1"}')
        wrapper = package / 'bin/t3.mjs'
        wrapper.write_text('''#!/usr/bin/python3
import os,pathlib
p=pathlib.Path(os.environ['T3CODE_HOME'])/'runtime/versions/0.1.1'
p.mkdir(parents=True,exist_ok=True)
p.chmod(0o700)
(p/'.install-complete').write_text('0.1.1')
(p/'t3').write_text('#!/bin/sh\\necho "t3 v0.1.1"\\n')
(p/'t3').chmod(0o755)
(p/'client').mkdir(exist_ok=True)
(p/'client/index.html').write_text('bundled T3 client')
print('t3 v0.1.1')
''')
        wrapper.chmod(0o755)
        t3 = self.root / 'bin/t3'
        t3.parent.mkdir()
        t3.symlink_to(wrapper)
        build = self.root / 'build'
        immutable = self.root / 'immutable/t3'
        files = module.materialize(t3, build, immutable)
        import shutil
        shutil.rmtree(build)
        result = subprocess.run([str(t3), '--version'], env={'HOME': str(self.root / 'new-empty-home')},
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), 't3 v0.1.1')
        self.assertTrue((immutable.parent / 'client/index.html').is_file(), 'native runtime sidecars must survive empty homes')
        self.assertEqual(immutable.parent.stat().st_mode & 0o005, 0o005, 'immutable runtime must be readable/traversable by the container user')
        self.assertEqual(t3.resolve(), immutable)
        self.assertEqual(set(files), {wrapper, immutable})

    def test_unknown_npm_launcher_layout_fails_precisely(self):
        module = self.installer()
        self.assertTrue(hasattr(module, 'materialize'), 'npm layout compatibility validation missing')
        t3 = self.root / 'unknown.mjs'
        t3.write_text('unsupported')
        with self.assertRaisesRegex(ValueError, 'npm|layout|package'):
            module.materialize(t3, self.root / 'build', self.root / 'immutable/t3')

    def test_optional_package_npm_layout_materializes_exact_native_executable(self):
        module = self.installer()
        self.assertTrue(hasattr(module, 'materialize'), 'npm binary materialization missing')
        package = self.root / 'npm/t3'
        (package / 'bin').mkdir(parents=True)
        import platform
        arch = {'x86_64':'x64', 'aarch64':'arm64'}[platform.machine()]
        native = package / ('node_modules/@t3code/t3-linux-' + arch)
        native.mkdir(parents=True)
        (native / 'package.json').write_text('{"version":"0.1.0"}')
        binary = native / 't3'
        binary.write_text('#!/bin/sh\necho "t3 v0.1.0"\n')
        binary.chmod(0o755)
        wrapper = package / 'bin/t3.js'
        wrapper.write_text('#!/bin/sh\nexec "' + str(binary) + '" "$@"\n')
        wrapper.chmod(0o755)
        t3 = self.root / 't3'
        t3.symlink_to(wrapper)
        immutable = self.root / 'immutable/t3'
        # Node's package resolver is an image dependency; keep the filesystem,
        # native version check and copy real while stubbing this external lookup.
        run = subprocess.run
        def resolve_node(args, **kwargs):
            if args[0] == 'node':
                return subprocess.CompletedProcess(args, 0, str(binary) + '\n', '')
            return run(args, **kwargs)
        with patch.object(module.subprocess, 'run', side_effect=resolve_node):
            files = module.materialize(t3, self.root / 'build', immutable)
        self.assertEqual(t3.resolve(), immutable)
        self.assertEqual(immutable.read_bytes(), binary.read_bytes())
        self.assertEqual(set(files), {wrapper, immutable})

    def test_entrypoint_seed_ignores_python_environment_hooks(self):
        home = self.root / 'home'
        home.mkdir()
        marker = self.root / 'poisoned'
        hooks = self.root / 'hooks'
        hooks.mkdir()
        (hooks / 'sitecustomize.py').write_text('from pathlib import Path; Path(' + repr(str(marker)) + ').touch()')
        check = self.root / 'check.py'
        check.write_text('pass\n')
        script = self.root / 'entrypoint'
        script.write_text((ROOT / 'scripts/entrypoint.sh').read_text()
            .replace('/workspace', str(self.root))
            .replace('/usr/local/lib/t3-sandbox/browser.py', str(check)))
        result = subprocess.run(['bash', str(script), 'true'], capture_output=True, text=True,
            env=dict(os.environ, HOME=str(home), PYTHONPATH=str(hooks)))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(marker.exists(), 'browser seeding imported a writable startup hook')
