"""Profile persistence and the boundary between YAML data and host execution."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError, asdict
import os
from pathlib import Path
import socket
import threading
import unittest
from unittest.mock import patch

from support import ProfileFixture
from t3_sandbox.paths import ProfileIdentity, profile_paths
from t3_sandbox.profiles import decode_profile, initialize_profile, load_profile

ROOT = Path(__file__).resolve().parents[1]


class ProfileTests(unittest.TestCase):
    def test_runtime_hostname_is_optional_and_accepts_dns_names(self):
        with ProfileFixture() as f:
            self.assertIsNone(f.load("default").runtime.hostname)
            for hostname in (None, "my-sandbox", "dev.example.com", "A" * 63):
                with self.subTest(hostname=hostname):
                    profile = f.load("work", {"runtime": {"hostname": hostname}})
                    self.assertEqual(profile.runtime.hostname, hostname)

    def test_runtime_hostname_rejects_invalid_names(self):
        with ProfileFixture() as f:
            for hostname in ("", True, 123, "has spaces", "bad_name", "-bad", "bad-",
                             "a..b", "a.", "a" * 64, ".".join(["a" * 63] * 4), "bad\nname"):
                with self.subTest(hostname=hostname), self.assertRaisesRegex(ValueError, "runtime.hostname"):
                    f.load("work", {"runtime": {"hostname": hostname}})

    def test_persisted_defaults_and_named_profile(self):
        with ProfileFixture() as f:
            p = load_profile("default", f.profile_dir, f.host)
            self.assertTrue(p.source.is_file())
            self.assertFalse(p.network.restricted)
            self.assertEqual((p.server.bind_address, p.server.port), ("0.0.0.0", 3773))
            self.assertTrue(p.state.share_host_t3_state)
            self.assertTrue(p.state.share_host_provider_state)
            self.assertEqual(p.project.directory, f.host.home / "projects/t3-sandbox/default")
            self.assertFalse(p.project.directory.exists())
            self.assertFalse((f.host.home / ".local").exists())
            self.assertEqual((p.resources.memory, p.resources.cpus, p.resources.pids_limit), ("8g", 4, 2048))
            self.assertEqual(p.network.allow.domains, (
                "api.openai.com", "auth.openai.com", "chatgpt.com", "api.anthropic.com",
                "claude.ai", "platform.claude.com", "console.anthropic.com", "t3.codes", "app.t3.codes"))
            self.assertEqual(p.network.allow.ports, (443,))
            initialize_profile("work", f.profile_dir, f.host)
            work = load_profile("work", f.profile_dir, f.host)
            self.assertFalse(work.state.share_host_t3_state)
            self.assertNotEqual(work.server.port, p.server.port)
            self.assertEqual(load_profile("work", f.profile_dir, f.host).server.port, work.server.port)
            with self.assertRaises(FrozenInstanceError):
                work.network.restricted = True

    def test_template_equals_normalized_auto_created_default(self):
        with ProfileFixture() as f:
            auto = asdict(f.load("default"))
            template = asdict(decode_profile((ROOT / "config/profile.default.yaml").read_bytes(),
                                            name="default", source=f.profile_dir / "default.yaml", host=f.host))
            self.assertEqual(auto, template)

    def test_init_preserves_user_edits_under_concurrency(self):
        with ProfileFixture() as f:
            barrier = threading.Barrier(2)
            def initialize():
                barrier.wait()
                return initialize_profile("default", f.profile_dir, f.host)
            with ThreadPoolExecutor(max_workers=2) as pool:
                paths = list(pool.map(lambda _: initialize(), range(2)))
            self.assertEqual(paths[0], paths[1])
            self.assertEqual(f.load("default").server.port, 3773)
            edited = b"version: 1\nserver:\n  port: 43781\n# user comment\n"
            paths[0].write_bytes(edited)
            with ThreadPoolExecutor(max_workers=2) as pool:
                list(pool.map(lambda _: initialize_profile("default", f.profile_dir, f.host), range(2)))
            self.assertEqual(paths[0].read_bytes(), edited)
            self.assertEqual(list(f.profile_dir.glob("*.yaml")), [paths[0]])

    def test_named_profile_before_default_reserves_default_port(self):
        with ProfileFixture() as f:
            with patch("t3_sandbox.profiles._port_available", return_value=True):
                initialize_profile("work", f.profile_dir, f.host)
            default = f.load("default")
            self.assertEqual(default.server.port, 3773)
            self.assertEqual(f.load("work").server.port, 3774)
            self.assertNotEqual(f.load("work").server.port, default.server.port)

    def test_concurrent_named_profile_ports_are_unique(self):
        with ProfileFixture() as f:
            f.load("default")
            with ThreadPoolExecutor(max_workers=4) as pool:
                list(pool.map(lambda name: initialize_profile(name, f.profile_dir, f.host), ["a", "b", "c", "d"]))
            ports = [f.load(name).server.port for name in ["default", "a", "b", "c", "d"]]
            self.assertEqual(len(set(ports)), 5)

    def test_named_profile_avoids_host_ipv4_listener(self):
        with ProfileFixture() as f, socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            try:
                listener.bind(("127.0.0.1", 3774))
                listener.listen()
            except OSError:
                self.skipTest("3774 already in use on this host")
            initialize_profile("work", f.profile_dir, f.host)
            self.assertGreater(f.load("work").server.port, 3774)

    def test_missing_named_profile_does_not_create_file(self):
        with ProfileFixture() as f:
            with self.assertRaisesRegex(ValueError, "make init PROFILE=work"):
                f.load("work")
            self.assertFalse(f.profile_dir.exists())
            with self.assertRaises(ValueError):
                load_profile("default", f.profile_dir, f.host, initialize_default=False)
            self.assertFalse(f.profile_dir.exists())

    def test_profile_name_cannot_traverse(self):
        with ProfileFixture() as f:
            for name in ["../default", "a/b", "", ".", "..", "a b", "-option"]:
                with self.subTest(name=name), self.assertRaises(ValueError):
                    initialize_profile(name, f.profile_dir, f.host)
                with self.subTest(name=name), self.assertRaises(ValueError):
                    decode_profile(b"version: 1", name=name, source=f.root / "x.yaml", host=f.host)
            self.assertFalse(f.profile_dir.exists())

    def test_duplicate_unknown_and_unsafe_yaml_are_rejected(self):
        invalid = [
            "version: 1\nversion: 1", "version: true", "version: '1'", "version: 2",
            "version: 1\nsandbox: other", "server: {port: 3773, unknown: true}",
            "network: {restricted: 'false'}", "network: {restricted: yes}",
            "state: {share_host_t3_state: 1}", "server: {port: true}",
            "server: {port: 0}", "server: {port: 65536}", "server: {port: '3773'}",
            "server: {port: 3.5}", "server: {bind_address: bad}",
            "project: {directory: relative/path}", "project: {directory: ~other/project}",
            "project: {directory: '/tmp/$(touch /tmp/t3-profile-unsafe)'}",
            "runtime: {env_file: '/tmp/`id`'}", "project: {directory: '${USER}/x'}",
            "network: {allow: {ports: [true]}}", "network: {allow: {domains: api.openai.com}}",
            "network: {allow: {ips: [123]}}", "resources: {cpus: true}",
            "resources: {memory: '8g --privileged'}", "resources: {pids_limit: 0}",
            "build: {codex_version: '--help'}", "build: {ubuntu_image: 'image with spaces'}",
            "a: &a [*a]", "network: &n {restricted: false}\nstate: *n",
            "!!python/object/apply:os.system ['touch /tmp/t3-profile-unsafe']", "[]", "null",
        ]
        with ProfileFixture() as f:
            for data in invalid:
                with self.subTest(data=data), self.assertRaises(ValueError):
                    decode_profile(data.encode(), name="default", source=f.root / "x.yaml", host=f.host)
            with self.assertRaises(ValueError):
                decode_profile(b"#" * (1024 * 1024 + 1), name="default", source=f.root / "x", host=f.host)
            with self.assertRaises(ValueError):
                decode_profile(b"\xff", name="default", source=f.root / "x", host=f.host)

    def test_paths_expand_only_host_home_and_limits_remain_nullable(self):
        with ProfileFixture() as f:
            p = f.load("work", {"project": {"directory": "${HOME}/my project"},
                "runtime": {"env_file": "~/secrets.env"}, "resources": {"memory": None, "cpus": None},
                "state": {"share_host_provider_state": False, "share_host_t3_state": True}})
            self.assertEqual(p.project.directory, f.host.home / "my project")
            self.assertEqual(p.runtime.env_file, f.host.home / "secrets.env")
            self.assertIsNone(p.resources.memory)
            self.assertIsNone(p.resources.cpus)
            self.assertFalse(p.state.share_host_provider_state)
            self.assertTrue(p.state.share_host_t3_state)
            self.assertFalse((f.host.home / "my project").exists())

    def test_allowlist_is_normalized_at_profile_boundary(self):
        with ProfileFixture() as f:
            profile = f.load("work", {"network": {"allow": {
                "domains": ["API.OPENAI.COM.", "*.example.com"], "ips": ["8.8.8.9/24"], "ports": [443, 443]}}})
            self.assertEqual(profile.network.allow.domains, ("api.openai.com", "*.example.com"))
            self.assertEqual(profile.network.allow.ips, ("8.8.8.0/24",))
            self.assertEqual(profile.network.allow.ports, (443,))

    def test_profile_rejects_domain_and_ip_policy_injection(self):
        with ProfileFixture() as f:
            for field, value in (("domains", "https://example.com"), ("domains", "*"),
                                 ("domains", "bücher.example"), ("ips", "localhost")):
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    f.load("work", {"network": {"allow": {field: [value]}}})

    def test_comments_and_key_order_do_not_change_policy_digest(self):
        from t3_sandbox.policy import compile_policy
        from test_policy import gateway
        with ProfileFixture() as f:
            first = decode_profile(b"network: {allow: {domains: [a.example, b.example], ips: [], ports: [443, 80]}}",
                name="work", source=f.root / "a", host=f.host)
            second = decode_profile(b"# user comment\nnetwork: {allow: {ports: [80, 443], ips: [], domains: [b.example, a.example]}}",
                name="work", source=f.root / "b", host=f.host)
            self.assertEqual(compile_policy(first.network.allow, gateway(), proxy_uid=2001, relay_uid=2002).digest,
                             compile_policy(second.network.allow, gateway(), proxy_uid=2001, relay_uid=2002).digest)

    def test_legacy_environment_cannot_override_yaml(self):
        with ProfileFixture() as f:
            marker = f.root / "executed"
            (f.root / ".env").write_text(f"touch {marker}\nHOST_PORT=1\n")
            previous = Path.cwd()
            try:
                os.chdir(f.root)
                with patch.dict(os.environ, {"HOME": "/hostile", "PROJECT_DIR": "/", "HOST_PORT": "1", "SHARE_HOST_STATE": "0"}):
                    p = f.load("default")
            finally:
                os.chdir(previous)
            self.assertEqual(p.server.port, 3773)
            self.assertEqual(p.state.t3_directory, f.host.home / ".t3")
            self.assertFalse(marker.exists())

    def test_publication_preserves_an_intervening_user_file(self):
        with ProfileFixture() as f:
            original_link = os.link
            edited = b"version: 1\nserver: {port: 43782}\n"
            def racing_link(source, target):
                target.write_bytes(edited)
                original_link(source, target)
            with patch("t3_sandbox.profiles.os.link", side_effect=racing_link):
                result = initialize_profile("default", f.profile_dir, f.host)
            self.assertEqual(result.read_bytes(), edited)
            self.assertEqual(list(f.profile_dir.glob(".profile-*")), [])

    def test_port_exhaustion_does_not_publish_partial_profile(self):
        with ProfileFixture() as f:
            f.load("default")
            with patch("t3_sandbox.profiles.MAX_MANAGEMENT_PORT", 3773):
                with self.assertRaisesRegex(ValueError, "No unused management port"):
                    initialize_profile("work", f.profile_dir, f.host)
            self.assertFalse((f.profile_dir / "work.yaml").exists())
            self.assertEqual(list(f.profile_dir.glob(".profile-*")), [])

    def test_invalid_advertised_url_is_rejected(self):
        with ProfileFixture() as f:
            for url in ["not a url", "file:///etc/passwd", "https://user:password@example.com", "http://example.com:bad"]:
                with self.subTest(url=url), self.assertRaises(ValueError):
                    f.load("work", {"server": {"advertised_url": url}})

    def test_oversized_cpu_count_fails_as_configuration_error(self):
        with ProfileFixture() as f:
            with self.assertRaises(ValueError):
                f.load("work", {"resources": {"cpus": 10 ** 400}})

    def test_profile_identity_scopes_all_resources_to_uid_and_name(self):
        identity = ProfileIdentity("work", 1234)
        self.assertEqual(identity.container, "t3-sandbox-1234-work")
        self.assertEqual(identity.proxy, "t3-sandbox-1234-work-proxy")
        self.assertEqual(identity.private_network, "t3-sandbox-1234-work-private")
        self.assertEqual(identity.external_network, "t3-sandbox-1234-work-external")
        self.assertEqual(identity.image, "localhost/t3-code-sandbox:1234-work")
        self.assertEqual(identity.proxy_image, "localhost/t3-code-proxy:1234-work")

    def test_profile_paths_are_derived_without_creating_storage(self):
        with ProfileFixture() as f:
            identity = ProfileIdentity("work", f.host.uid)
            paths = profile_paths(identity, f.profile_dir, f.host)
            base = f.host.home / ".local/share/t3-sandbox/work"
            self.assertEqual(paths.profile_file, f.profile_dir / "work.yaml")
            self.assertEqual((paths.home, paths.runtime, paths.logs), (base / "home", base / "runtime", base / "logs"))
            self.assertFalse(paths.lock.is_relative_to(paths.runtime))
            self.assertFalse(base.exists())


if __name__ == "__main__":
    unittest.main()
