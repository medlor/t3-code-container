"""Policy boundary tests; Task 5 separately validates real Squid/nft parsers."""
from dataclasses import replace
import hashlib
import json
import re
import unittest

from t3_sandbox import policy
from t3_sandbox.policy import Allowlist


def gateway():
    return policy.GatewayConfig("10.89.1.2", "10.89.1.3", "10.89.1.0/24",
        ("10.89.2.0/24",), ("93.184.216.34", "192.168.1.5", "2606:4700::1234"),
        ("10.89.2.1", "1.1.1.1"), "0.0.0.0", 3774)


class NormalizationTests(unittest.TestCase):
    def test_normalizes_case_root_dot_duplicates_cidrs_and_ports(self):
        result = policy.normalize_allowlist(Allowlist(
            ("API.OPENAI.COM.", "*.example.com", "api.openai.com", "xn--bcher-kva.example"),
            ("8.8.8.9/24", "2001:4860:4860::8888", "8.8.8.8", "8.8.8.8/32"), (443, 80, 443)))
        self.assertEqual(result, Allowlist(("api.openai.com", "*.example.com", "xn--bcher-kva.example"),
            ("8.8.8.0/24", "2001:4860:4860::8888/128", "8.8.8.8/32"), (443, 80)))

    def test_rejects_bare_wildcard_urls_userinfo_ports_and_control_characters(self):
        for domain in ("*", "https://api.openai.com", "user@api.openai.com", "api.openai.com:443",
                       "api.openai.com\nhttp_access allow all", "a\x00.com", "a\x7f.com", " example.com",
                       "bücher.example", "a.*.com", "**.com", ".example.com", "a..com", "-a.com",
                       "a_.com", "a-.com", "a.com..", "127.0.0.1", "::1", "123", "xn--.com",
                       "a" * 64 + ".com", "a." * 127 + "a"):
            with self.subTest(domain=domain), self.assertRaises(ValueError):
                policy.normalize_allowlist(Allowlist((domain,), (), (443,)))

    def test_rejects_non_integer_zero_and_out_of_range_ports(self):
        for port in (True, False, 0, -1, 65536, "443", 443.0, None):
            with self.subTest(port=port), self.assertRaises(ValueError):
                policy.normalize_allowlist(Allowlist((), (), (port,)))
        self.assertEqual(policy.normalize_allowlist(Allowlist((), (), (1, 65535))).ports, (1, 65535))

    def test_rejects_malformed_ip_and_collection_types(self):
        for value in ("8.8.8.8\nallow all", "localhost", "8.8.8.8:443", "fe80::1%eth0", "1.2.3.4/33"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                policy.normalize_allowlist(Allowlist((), (value,), (443,)))
        for value in (Allowlist("example.com", (), (443,)), Allowlist((), (), [443]),
                      Allowlist((1,), (), (443,)), Allowlist((), (None,), (443,))):
            with self.subTest(value=value), self.assertRaises(ValueError):
                policy.normalize_allowlist(value)


class ProtectionTests(unittest.TestCase):
    def test_nonpublic_mapped_host_and_sandbox_addresses_are_protected(self):
        for address in ("0.0.0.0", "0.1.2.3", "127.0.0.1", "10.0.0.1", "100.64.1.1", "169.254.169.254",
                        "172.16.0.1", "192.168.1.1", "192.0.0.9", "192.0.2.1", "192.88.99.1", "198.18.0.1",
                        "198.51.100.1", "203.0.113.1", "224.0.0.1", "240.0.0.1", "255.255.255.255",
                        "::", "::1", "::8.8.8.8", "::ffff:127.0.0.1", "::ffff:8.8.8.8", "64:ff9b::808:808",
                        "100::1", "2001:db8::1", "2001::1", "2002:0808:0808::1", "fc00::1", "fe80::1",
                        "ff02::1", "4000::1", "93.184.216.34", "2606:4700::1234", "10.89.1.99", "10.89.2.99"):
            with self.subTest(address=address):
                self.assertTrue(policy.is_protected_address(address, gateway()))
        for address in ("8.8.8.8", "1.1.1.1", "2606:4700:4700::1111", "2001:4860:4860::8888"):
            with self.subTest(address=address):
                self.assertFalse(policy.is_protected_address(address, gateway()))
        public_topology = replace(gateway(), private_ip="9.10.11.2", t3_ip="9.10.11.3",
                                  private_cidr="9.10.11.0/24", external_cidrs=("9.10.12.0/24",))
        self.assertTrue(policy.is_protected_address("9.10.11.99", public_topology))
        self.assertTrue(policy.is_protected_address("9.10.12.99", public_topology))

    def test_rejects_ipv6_operational_subnets_and_resolvers(self):
        allow = Allowlist(("example.com",), ("2001:4860:4860::8888",), (443,))
        baseline = json.loads(policy.encode_snapshot(allow, gateway()))
        cases = (
            ("external_cidrs", ("2001:4860::/64",)),
            ("external_cidrs", ("10.89.2.0/24", "2001:4860::/64")),
            ("dns_servers", ("2001:4860:4860::8888",)),
            ("dns_servers", ("1.1.1.1", "2001:4860:4860::8888")),
        )
        for field, values in cases:
            topology = replace(gateway(), **{field: values})
            with self.subTest(field=field, values=values, boundary="compiler"), self.assertRaisesRegex(ValueError, field + ".*IPv4"):
                policy.compile_policy(allow, topology, proxy_uid=2001, relay_uid=2002)
            with self.subTest(field=field, values=values, boundary="encoder"), self.assertRaisesRegex(ValueError, field + ".*IPv4"):
                policy.encode_snapshot(allow, topology)
            snapshot = {**baseline, "gateway": {**baseline["gateway"], field: list(values)}}
            with self.subTest(field=field, values=values, boundary="decoder"), self.assertRaisesRegex(ValueError, field + ".*IPv4"):
                policy.decode_snapshot(json.dumps(snapshot).encode())

    def test_invalid_addresses_and_topology_fail_closed(self):
        for address in ("example.com", "fe80::1%eth0", "8.8.8.8\n", 123):
            with self.subTest(address=address), self.assertRaises(ValueError):
                policy.is_protected_address(address, gateway())
        for changes in ({"private_ip": "0.0.0.0"}, {"t3_ip": "10.89.1.2"},
                        {"t3_ip": "10.88.1.3"}, {"private_ip": "10.89.1.0"},
                        {"private_cidr": "10.89.1.2/24"}, {"external_cidrs": ("10.89.1.0/24",)},
                        {"external_cidrs": ()}, {"dns_servers": ()}, {"dns_servers": ("0.0.0.0",)},
                        {"host_ips": ("1.1.1.1\naccept",)}, {"bind_address": "localhost"}, {"host_port": True}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                policy.compile_policy(Allowlist((), (), (443,)), replace(gateway(), **changes), proxy_uid=2001, relay_uid=2002)


class CompilationTests(unittest.TestCase):
    def compile(self, allow=None):
        return policy.compile_policy(allow or Allowlist(("api.openai.com", "*.example.com"), ("8.8.8.8",), (443,)),
                                     gateway(), proxy_uid=2001, relay_uid=2002)

    def domain_patterns(self):
        lines = self.compile().squid_conf.splitlines()
        return [line.split(" -i ", 1)[1] for line in lines if "dstdom_regex" in line]

    def test_exact_host_inclusion(self):
        self.assertTrue(any(re.fullmatch(pattern, "api.openai.com") for pattern in self.domain_patterns()))

    def test_suffix_spoofing_is_denied(self):
        for host in ("api.openai.com.evil.test", "evilapi.openai.com", "evil-example.com"):
            self.assertFalse(any(re.fullmatch(pattern, host) for pattern in self.domain_patterns()))

    def test_wildcard_excludes_apex_but_includes_nested_subdomains(self):
        patterns = self.domain_patterns()
        self.assertFalse(any(re.fullmatch(pattern, "example.com") for pattern in patterns))
        for host in ("www.example.com", "a.b.example.com"):
            self.assertTrue(any(re.fullmatch(pattern, host) for pattern in patterns))

    def test_no_reverse_dns_grants(self):
        for line in self.compile().squid_conf.splitlines():
            if "dstdom_regex" in line:
                self.assertIn("dstdom_regex -n -i ", line)
        self.assertNotIn("dstdomain ", self.compile().squid_conf)

    def test_squid_private_listener_ports_cache_and_final_deny(self):
        conf = self.compile().squid_conf
        self.assertEqual([line for line in conf.splitlines() if line.startswith("http_port ")], ["http_port 10.89.1.2:3128"])
        self.assertIn("acl allowed_ports port 443\n", conf)
        self.assertIn("http_access deny !allowed_ports tag_port\n", conf)
        self.assertIn("http_access deny CONNECT !allowed_ports tag_port\n", conf)
        self.assertIn("cache deny all\n", conf)
        self.assertIn("access_log stdio:/run/t3-proxy/decisions.fifo", conf)
        self.assertNotIn("%ru", conf)
        self.assertNotIn("%>rp", conf)
        self.assertIn("%#.253>rd", conf)
        self.assertIn("dns_nameservers 1.1.1.1 10.89.2.1\n", conf)
        access = [line for line in conf.splitlines() if line.startswith("http_access ")]
        self.assertEqual(access[-1], "http_access deny all tag_unlisted")
        self.assertLess(access.index("http_access deny protected_dst tag_protected"), access.index("http_access allow t3_client allowed_domains"))
        self.assertIn("http_access allow t3_client allowed_ips", access)

    def test_explicit_private_and_mapped_allow_entries_never_override_protection(self):
        compiled = self.compile(Allowlist(("private.example",), ("127.0.0.1", "::ffff:127.0.0.1", "93.184.216.34"), (53, 443)))
        conf = compiled.squid_conf
        self.assertLess(conf.index("http_access deny protected_dst tag_protected"), conf.index("http_access allow t3_client allowed_ips"))
        for address in ("127.0.0.0/8", "::/3", "93.184.216.34/32", "10.0.0.0/8"):
            self.assertIn(address, conf)
            self.assertIn(address, compiled.nft_conf)

    def test_empty_destination_or_port_lists_permit_nothing(self):
        for allow in (Allowlist((), (), (443,)), Allowlist(("api.openai.com",), (), ())):
            conf = self.compile(allow)
            self.assertNotIn("http_access allow ", conf.squid_conf)
            self.assertNotIn("meta skuid 2001 tcp dport", conf.nft_conf)

    def test_nft_dns_and_relay_exceptions_are_scoped_to_uid_and_destination(self):
        conf = self.compile(Allowlist(("example.com",), ("10.89.2.1",), (53, 443))).nft_conf
        output = conf.split("chain output {", 1)[1].split("\n    }", 1)[0].splitlines()
        allows = [line.strip() for line in output if line.strip().endswith("accept")]
        self.assertIn("meta skuid 2001 ip daddr 10.89.2.1 udp dport 53 accept", allows)
        self.assertIn("meta skuid 2001 ip daddr 1.1.1.1 udp dport 53 accept", allows)
        self.assertIn("meta skuid 2002 ip daddr 10.89.1.3 tcp dport 3773 accept", allows)
        self.assertNotIn("tcp dport 53 accept", "\n".join(allows))
        self.assertIn("ct direction reply ct state established accept", allows)
        drop_index = next(i for i, line in enumerate(output) if "ip daddr @protected_v4 drop" in line)
        global_index = next(i for i, line in enumerate(output) if "meta skuid 2001 tcp dport { 53, 443 } accept" in line)
        self.assertLess(drop_index, global_index)
        self.assertEqual(len(allows), 5)  # Replies, two resolver exceptions, exact relay, global TCP.

    def test_nft_default_drop_and_private_input_boundaries(self):
        conf = self.compile().nft_conf
        self.assertIn("table inet t3_egress {", conf)
        for chain in ("input", "output", "forward"):
            self.assertIn(f"type filter hook {chain} priority 0; policy drop;", conf)
        self.assertIn("ip saddr 10.89.1.3 ip daddr 10.89.1.2 tcp dport 3128 accept", conf)
        self.assertLess(conf.index("ip saddr 10.89.1.0/24 drop"), conf.index("tcp dport 3773 accept"))
        self.assertNotIn("flush ruleset", conf)

    def test_uids_must_be_distinct_nonroot_integers(self):
        for proxy_uid, relay_uid in ((0, 2002), (2001, 0), (True, 2002), (2001, 2001), (-1, 2002), (2**32, 2002)):
            with self.subTest(uids=(proxy_uid, relay_uid)), self.assertRaises(ValueError):
                policy.compile_policy(Allowlist((), (), (443,)), gateway(), proxy_uid=proxy_uid, relay_uid=relay_uid)

    def test_digest_matches_canonical_allowlist_only(self):
        a = self.compile(Allowlist(("API.OPENAI.COM.", "*.example.com"), ("8.8.8.8",), (443,)))
        b = self.compile(Allowlist(("*.example.com", "api.openai.com", "api.openai.com"), ("8.8.8.8/32",), (443, 443)))
        canonical = b'{"domains":["*.example.com","api.openai.com"],"ips":["8.8.8.8/32"],"ports":[443]}'
        self.assertEqual(a.digest, hashlib.sha256(canonical).hexdigest())
        self.assertEqual(a, b)
        changed_topology = policy.compile_policy(Allowlist(("*.example.com", "api.openai.com"), ("8.8.8.8",), (443,)),
            replace(gateway(), host_port=4000), proxy_uid=2001, relay_uid=2002)
        self.assertEqual(a.digest, changed_topology.digest)


class SnapshotTests(unittest.TestCase):
    def test_snapshot_roundtrip_contains_only_validated_allowlist_and_topology(self):
        allow = Allowlist(("API.OPENAI.COM.",), (), (443,))
        encoded = policy.encode_snapshot(allow, gateway())
        raw = json.loads(encoded)
        self.assertEqual(set(raw), {"version", "allow", "gateway", "digest"})
        decoded, topology = policy.decode_snapshot(encoded)
        self.assertEqual(decoded, Allowlist(("api.openai.com",), (), (443,)))
        self.assertEqual(topology.private_ip, "10.89.1.2")
        self.assertEqual(policy.encode_snapshot(decoded, topology), encoded)
        self.assertEqual(raw["digest"], policy.compile_policy(decoded, topology, proxy_uid=2001, relay_uid=2002).digest)

    def test_decoder_rejects_bad_schema_injection_digest_and_types(self):
        original = json.loads(policy.encode_snapshot(Allowlist(("example.com",), (), (443,)), gateway()))
        invalid = []
        for key, value in (("version", True), ("version", 2), ("digest", "a" * 64), ("extra", 1)):
            invalid.append({**original, key: value})
        invalid += [{**original, "allow": {**original["allow"], "domains": ["example.com\nallow all"]}},
                    {**original, "allow": {**original["allow"], "ports": [True]}},
                    {**original, "allow": {"domains": [], "ips": []}},
                    {**original, "gateway": {**original["gateway"], "host_port": True}},
                    {**original, "gateway": {**original["gateway"], "extra": "directive"}},
                    {**original, "gateway": {**original["gateway"], "dns_servers": "1.1.1.1"}}]
        for raw in invalid:
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                policy.decode_snapshot(json.dumps(raw).encode())
        for data in (b"{}", b"[]", b"null", b"\xff", b"{" * 1000, b" " * (1024 * 1024 + 1),
                     b'{"version":1,"version":1}', b'{"version":NaN}'):
            with self.subTest(data=data[:30]), self.assertRaises(ValueError):
                policy.decode_snapshot(data)
