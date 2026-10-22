# Optional Egress Proxy and YAML Profiles Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Provide selectable, persistent YAML-configured T3 sandboxes with optional proxy-enforced outbound allowlisting, independent proxy restarts, and useful denial logs.

**Architecture:** Keep Make and a thin Bash entry point, moving host orchestration to focused Python modules so YAML never becomes executable shell. In restricted mode T3 joins only an unaddressed internal bridge; a separate Squid/nftables gateway provides outbound proxying and fixed inbound management forwarding. Host profile homes persist independently of images, and validated policy snapshots can change without restarting T3.

**Tech Stack:** Rootless Podman/Netavark, Python 3 standard library and distribution PyYAML, Bash, Make, Squid, nftables, socat, existing Ubuntu/Node image build, unittest.

**Spec:** [Approved design](../specs/2026-10-22-optional-egress-proxy-design.md); also read the [network experiment](../specs/2026-10-22-network-isolation-spike.md).

## Global Constraints

- “Restricted mode is optional and defaults to off.” Off requires no proxy image/container/network.
- “All Make commands select a profile through `PROFILE=<name>`, defaulting to `default`.”
- The sole editable configuration is `${HOME}/.config/t3-sandbox/profiles/<name>.yaml`; ship `config/profile.default.yaml`. `PROFILE_DIR` is a location selector only.
- “Persistent profile homes are ordinary host directories under `~/.local/share/t3-sandbox/<profile>/home`, not Podman named volumes.”
- “The `default` profile reuses the original host `.t3` by default, with an independent flag to disable that sharing. Other profiles default to private T3 state.”
- `state.share_host_provider_state` and `state.share_host_t3_state` are independent. Never copy, merge, chown recursively, or delete existing state implicitly.
- Host management bind defaults to `0.0.0.0`; host port defaults to `3773`; T3's internal HTTP/WebSocket port stays `3773`; private proxy port is `3128` and is not host-published.
- Rootless Podman with Netavark is required for restricted mode. Podman 4.9.3 is the experimentally verified baseline, not a promise about every later version. Inspect actual invariants and reject unsupported behavior.
- “No untrusted T3 process starts before these checks succeed”: unaddressed host-side private bridge, disabled bridge IPv6, correct memberships, no T3 default route, gateway forwarding disabled, and gateway egress controls installed.
- T3 retains matching UID/GID, `--cap-drop=all`, `no-new-privileges`, private process/IPC namespaces, no engine/host namespace sockets, and no network-administration capability.
- T3 must not directly reach internet, host, LAN, or unrelated containers, even after removing proxy variables. Policy and logs stay outside all T3-writable mounts.
- Whitelist edits apply with `make proxy-restart`; T3 remains running. Brief management and outbound-stream interruption is explicitly accepted.
- `make firewall-logs` emits the latest 100 denials and follows by default. It is a proxy-policy log; locally failing direct attempts never reach it.
- All runtime and browser dependencies are installed during image build. No default registry, update, browser-download, broad vendor wildcard, or telemetry grant.
- Keep secrets in the optional runtime env file, referenced by the profile. Never bake host credentials or generated T3 authentication into an image or print them in logs.
- Use standard-library unittest; no new test framework or application runtime dependency beyond PyYAML and the packaged proxy components. No product changes occur while writing this plan.

## Review Focus

1. Existing host `.t3` contains a browser cache: container browser wrappers must never replace host executables with container-only paths. Task 8 tests an unchanged host-cache sentinel after container exit.
2. Invalid YAML or a deleted profile during an incident: `stop`, `status`, and log viewing must still resolve owned resources without accepting the edited policy. Tasks 2, 3, and 7 test recovery by identity.
3. Concurrent profile creation and mutations: defaults must not overwrite user edits, private bridge setup must finish before T3 starts, and separate profiles must not share state accidentally. Tasks 1, 3, and 6 test races and ordered failure cleanup.
4. Rotated logs and proxy restarts while following: output must remain profile-specific and continue without a held mutation lock or leaked token/query. Tasks 5 and 7 test event classification and rotation.
5. Hostile YAML/path/hostname inputs and DNS answers: quoting is not enough; parsing, filesystem boundaries, ACL ordering, and kernel egress restrictions must independently reject unsafe input. Tasks 1, 2, 4, 5, and 9 pin these behaviors.

---

## File structure and shared contracts

Create `scripts/t3_sandbox/` as a Python package. Keep `scripts/sandbox.sh` only as a stable `exec python3 ...` wrapper; do not pass parsed YAML back through `source`, `eval`, or shell-generated assignments. Use Python subprocess argument arrays throughout host orchestration.

- `config/profile.default.yaml`: commented default configuration; the exact schema and provider entries from the approved spec.
- `scripts/sandbox.py`: argument handling, selectors, exit codes, and dispatch.
- `scripts/t3_sandbox/profiles.py`: strict YAML, typed settings, initialization, normalization, profile names, default port allocation.
- `scripts/t3_sandbox/paths.py`: host identity, derived names/paths, protected mount boundaries, persistent homes, locks.
- `scripts/t3_sandbox/podman.py`: bounded subprocess adapter, JSON inspection, ownership checks; no lifecycle policy.
- `scripts/t3_sandbox/launcher.py`: build/start/restart/recreate/remove and existing Make commands.
- `scripts/t3_sandbox/policy.py`: immutable allowlist, normalized policy, protected ranges, Squid/nft configuration generation; shared with the gateway image.
- `scripts/t3_sandbox/network.py`: per-profile network creation, addressing, rootless bridge hardening, membership inspection.
- `scripts/t3_sandbox/denials.py`: normalized denial records, bounded log writing and rotation-aware reading.
- `proxy/Dockerfile`, `proxy/runtime.py`: trusted initialization, privilege drop, Squid/relay/log process supervision.
- `scripts/install-t3-browser.py`, `scripts/browser-launcher.sh`: build-time provisioning and runtime browser proxy arguments.
- `scripts/entrypoint.sh`: local-only browser cache seeding plus existing identity/writability checks.
- `tests/support.py`: temporary profile fixtures; extend the existing fake-Podman fixture without touching real state.
- `tests/test_profiles.py`, `test_paths.py`, `test_sandbox.py`, `test_policy.py`, `test_proxy_runtime.py`, `test_network.py`, `test_firewall_logs.py`, `test_browser_assets.py`: unit and launcher behavior.
- `tests/integration/`: opt-in real Podman tests and disposable HTTP/WebSocket/DNS helpers.
- Modify `Dockerfile`, `.dockerignore`, `Makefile`, `README.md`, and `.gitignore` as their owning tasks need them; remove tracked `.env.example` when the launcher migrates. Do not delete a user's ignored `.env` or touch `.codex/`.

Use frozen dataclasses, not a general configuration framework. Define these contracts once; later tasks import them:

- `HostContext(home: Path, uid: int, gid: int, user: str)` in `paths.py`.
- `ProfileIdentity(name: str, uid: int)` in `paths.py`; deterministic resource names are `t3-sandbox-<uid>-<name>`, the same plus `-proxy`, `-private`, and `-external`; images are `localhost/t3-code-sandbox:<uid>-<name>` and `localhost/t3-code-proxy:<uid>-<name>`.
- `ProfilePaths(profile_file: Path, home: Path, runtime: Path, logs: Path, lock: Path)` in `paths.py`. Data siblings are `<host-home>/.local/share/t3-sandbox/<name>/{home,runtime,logs}`; the mutation lock is outside the removable runtime snapshot directory.
- `Allowlist(domains: tuple[str, ...], ips: tuple[str, ...], ports: tuple[int, ...])` in `policy.py`.
- `Profile(name, source, project, server, build, resources, state, runtime, network)` in `profiles.py`, with typed nested dataclasses matching the YAML names verbatim. `NetworkSettings(restricted: bool, allow: Allowlist)`; `ServerSettings(bind_address: str, port: int, advertised_url: str | None)`; path-valued fields normalize to `Path`; nullable limits stay `None`.
- `GatewayConfig(private_ip: str, t3_ip: str, private_cidr: str, external_cidrs: tuple[str, ...], host_ips: tuple[str, ...], dns_servers: tuple[str, ...], bind_address: str, host_port: int)` in `policy.py`. Internal ports are fixed constants `PROXY_PORT=3128`, `T3_PORT=3773`.
- `CompiledPolicy(digest: str, squid_conf: str, nft_conf: str)` in `policy.py`; digest is SHA-256 over canonical normalized allowlist JSON, independent of comments/key order.
- `Podman.run(args: Sequence[str], *, check=True, timeout=30, capture=True) -> CompletedProcess[str]` and `Podman.inspect(kind: str, name: str) -> dict | None` in `podman.py`; distinguish not-found from permission/runtime failure.

Test snippets below are unittest method bodies. `tests/support.py` supplies `ProfileFixture` as a context manager with `root`, `host`, `profile_dir`, `write(name, overrides) -> Path`, and `load(name, overrides=None) -> Profile`. Overrides are nested dict merges for test setup only, never a production override mechanism. Run unit tests with `PYTHONPATH=scripts python3 -m unittest discover -s tests -p 'test_*.py' -v`; integration tests are in a separate directory and require explicit opt-in.

## Task 1: Typed YAML profiles and safe default initialization

**Files:** Create `config/profile.default.yaml`, `scripts/t3_sandbox/{__init__,profiles,paths,policy}.py`, `tests/support.py`, `tests/test_profiles.py`. Modify `README.md` prerequisites.

**Interfaces:**
- Produces shared dataclasses above; only define the basic `Allowlist` structure in `policy.py` for now.
- `load_profile(name: str, profile_dir: Path, host: HostContext, *, initialize_default=True) -> Profile`.
- `initialize_profile(name: str, profile_dir: Path, host: HostContext) -> Path`.
- `decode_profile(data: bytes, *, name: str, source: Path, host: HostContext) -> Profile`.
- `profile_paths(identity: ProfileIdentity, profile_dir: Path, host: HostContext) -> ProfilePaths`.

- [ ] **Step 1: Write failing tests for persisted defaults, named profiles, and untrusted YAML.**

```python
with ProfileFixture() as f:
    p = load_profile("default", f.profile_dir, f.host)
    self.assertTrue(p.source.is_file())
    self.assertFalse(p.network.restricted)
    self.assertEqual((p.server.bind_address, p.server.port), ("0.0.0.0", 3773))
    self.assertTrue(p.state.share_host_t3_state)
    initialize_profile("work", f.profile_dir, f.host)
    work = load_profile("work", f.profile_dir, f.host)
    self.assertFalse(work.state.share_host_t3_state)
    self.assertNotEqual(work.server.port, p.server.port)
```

Also name and implement `test_init_preserves_user_edits_under_concurrency`, `test_missing_named_profile_does_not_create_file`, `test_profile_name_cannot_traverse`, `test_duplicate_unknown_and_unsafe_yaml_are_rejected`, and `test_legacy_environment_cannot_override_yaml`. Assert: two initializers produce one intact file; a user edit survives; missing `work` raises an error containing `make init PROFILE=work`; reject `../default`, aliases/recursive anchors, duplicate keys, unknown fields, `version: true`, quoted booleans, invalid ports, and YAML object tags. A hostile `.env` must never execute. Template defaults must equal normalized auto-created default settings.

- [ ] **Step 2: Run `PYTHONPATH=scripts python3 -m unittest discover -s tests -p test_profiles.py -v`.** Expected: failures for missing profile API, not environment errors.

- [ ] **Step 3: Implement these APIs and the exact approved YAML defaults.** Use distribution PyYAML safe loading with duplicate-key and alias rejection, 1 MiB input limit, strict key/type validation, and path-only `~`/`${HOME}` expansion. Reject relative configuration paths and shell substitutions. Preserve existing UID/GID-derived identity without assigning to `$HOME`. Atomic initialization uses exclusive publication, not overwrite-by-rename; serialize named-profile port selection under a short profile-directory allocation lock. Inspect existing profile ports plus host IPv4 listeners, persist the chosen port, and fail cleanly if allocation is exhausted. Profile loading parses data; it does not create project/provider/home storage, which Task 2 owns.

- [ ] **Step 4: Rerun the Task 1 command.** Expected: all tests pass. Document `sudo apt install python3-yaml` as a host prerequisite, without installing anything during runtime/profile loading.

- [ ] **Step 5: Commit only these files:** `feat: add strict YAML sandbox profiles`.

## Task 2: Persistent host homes, ownership, and recovery identity

**Files:** Modify `paths.py`; create `podman.py`, `tests/test_paths.py`; extend `tests/support.py` with the existing fake-Podman command recorder.

**Interfaces:**
- Consumes `Profile`, `HostContext`, `ProfileIdentity`, `ProfilePaths`.
- `validate_storage(profile: Profile, paths: ProfilePaths, host: HostContext) -> None`.
- `prepare_home(profile: Profile, paths: ProfilePaths, host: HostContext) -> list[tuple[Path, str]]` returns host source/container destination bind mounts.
- `mutation_lock(paths: ProfilePaths) -> ContextManager[None]` using `fcntl.flock`.
- `Podman` adapter above and `assert_owned(resource: dict, identity: ProfileIdentity) -> None`.
- Labels: `io.t3-sandbox.managed=true`, `io.t3-sandbox.uid`, `io.t3-sandbox.profile`, `io.t3-sandbox.role` (`t3`, `proxy`, `private`, `external`).

- [ ] **Step 1: Write failing storage and identity tests.**

```python
with ProfileFixture() as f:
    default = f.load("default")
    mounts = prepare_home(default, profile_paths(ProfileIdentity("default", f.host.uid), f.profile_dir, f.host), f.host)
    self.assertIn((f.host.home / ".t3", f"/home/{f.host.user}/.t3"), mounts)
    private = f.load("work", {"state": {"share_host_t3_state": False}})
    paths = profile_paths(ProfileIdentity("work", f.host.uid), f.profile_dir, f.host)
    self.assertEqual(paths.home, f.host.home / ".local/share/t3-sandbox/work/home")
    self.assertNotEqual(paths.home, f.host.home / ".t3")
```

Add `test_provider_and_t3_sharing_flags_are_independent` over all four boolean combinations; `test_policy_runtime_and_logs_cannot_be_inside_any_writable_mount` including symlink/ancestor cases; `test_state_switch_preserves_both_directories`; `test_profile_mutation_locks_do_not_serialize_other_profiles`; `test_owned_resource_lookup_survives_invalid_or_deleted_profile`; `test_similarly_named_unowned_container_is_never_removed`. Assert marker files and original ownership remain unchanged and no `podman volume rm`/recursive `chown` occurs.

- [ ] **Step 2: Run `PYTHONPATH=scripts python3 -m unittest discover -s tests -p test_paths.py -v`.** Expected: missing-function failures.

- [ ] **Step 3: Implement filesystem and Podman adapters.** Resolve identities from validated selector names independently of YAML. Validate real mount sources against the profile, runtime, and log locations before creating them; refuse `/`, host home, and overlapping sensitive locations. Create only absent directories as the host user, including an absent shared provider/T3 state directory without changing existing contents. Respect `project.create_if_missing` for the project. Mount only the profile `home` subtree into T3. Resolve T3-state sharing conflicts by canonical source path plus actual managed-container mounts, not profile filenames. Keep original host state and legacy volumes untouched.

- [ ] **Step 4: Run Task 1 and Task 2 tests.** Expected: pass, including subprocess errors being distinguished from missing resources.

- [ ] **Step 5: Commit:** `feat: persist profile homes in host directories`.

## Task 3: Migrate the launcher with unrestricted mode working

**Files:** Create `scripts/sandbox.py`, `launcher.py`; replace orchestration in `scripts/sandbox.sh` with a thin wrapper. Modify `Makefile`, `tests/test_sandbox.py`, `README.md`, `.gitignore`; remove tracked `.env.example`.

**Interfaces:**
- Consumes Tasks 1–2.
- `Launcher(podman: Podman, host: HostContext, profile_dir: Path)` with `dispatch(command: str, name: str, *, cmd: str | None=None, follow=True, tail=100) -> int`.
- `topology_digest(profile: Profile, paths: ProfilePaths) -> str` excludes comments, allowlist entries, and build-only selectors; includes actual T3 mounts, resources, network mode, stable endpoint, bind and port. Record the selected image ID separately.
- CLI: `sandbox.py COMMAND [--profile NAME] [--profile-dir PATH] [--cmd STRING] [--follow 0|1] [--tail N]`. Make exports `PROFILE` (default `default`), optional `PROFILE_DIR`, `CMD`, `FOLLOW`, and `TAIL` using Make export directives; argparse reads those environment entries as defaults. Never interpolate their values into Make recipe shell text. The thin shell wrapper forwards only its actual argument array and the command name.

- [ ] **Step 1: Adapt the existing launcher regression tests and add unrestricted-profile cases.**

```python
result = self.run_make("start", profile="work")
self.assertEqual(result.returncode, 0, result.stderr)
run = self.fake.last_t3_run()
self.assertIn("0.0.0.0:3774:3773", run)
self.assertFalse(self.fake.created_proxy_resources())
self.assertFalse(any(arg == "--volume" for arg in run))
```

Retain meaningful existing cases: restart an exited container using configured port bindings, report immediate exit code 78, reject changed project/port, retain provider mounts when T3 is private, and disable automatic health timers by default. Add `test_stop_and_status_work_with_invalid_whitelist`, `test_recreate_preserves_home_and_host_t3_markers`, `test_default_shared_t3_reports_host_server_lock_conflict`, `test_changed_resources_require_recreate`, and `test_selector_with_shell_metacharacters_never_executes`. Reject unsafe selector input before invoking Podman. T3's own host-process lock is authoritative; never delete it.

- [ ] **Step 2: Run `PYTHONPATH=scripts python3 -m unittest discover -s tests -p test_sandbox.py -v`.** Expected: failures against the current `.env` launcher.

- [ ] **Step 3: Implement the Python dispatch and Make migration.** Preserve rootless/UID checks, build args, direct local readiness, pairing-token rewriting via existing `pair-url.py`, interactive TTY behavior, project ownership smoke check, resource limits and env-file handling. Off uses `slirp4netns:allow_host_loopback=false` and publishes T3 directly on the configured host address. Build only the T3 image when off. `config` resolves settings without printing env-file contents. Restricted startup must report “not implemented” until Task 6, never run unrestricted as a fallback. Full structural changes require explicit recreation. Recovery commands discover resources by owned labels even if YAML is invalid or missing.

- [ ] **Step 4: Run the full unit suite and `bash -n scripts/sandbox.sh scripts/entrypoint.sh`; run `shellcheck` if installed.** Expected: all unit tests pass; no syntax failures. README first-run instructions now use profile paths, not `.env`/`SANDBOX`. Do not run real existing containers during this task.

- [ ] **Step 5: Commit:** `feat: select persistent sandboxes through YAML profiles`.

## Task 4: Compile allowlists and independent destination-address protection

Support boundary: operational `external_cidrs` and `dns_servers` are IPv4-only in this version; reject IPv6 and mixed settings. Retain IPv6 allowlist parsing, IPv6 host/protected ranges, and mapped-address denial. IPv6 egress needs a separately reviewed neighbor-discovery extension.

**Files:** Extend `policy.py`, profile validation, and `tests/test_policy.py`.

**Interfaces:**
- `normalize_allowlist(value: Allowlist) -> Allowlist`.
- `compile_policy(value: Allowlist, gateway: GatewayConfig, *, proxy_uid: int, relay_uid: int) -> CompiledPolicy`.
- `is_protected_address(address: str, gateway: GatewayConfig) -> bool`.
- Derived snapshots use schema `{"version": 1, "allow": {...}, "gateway": {...}, "digest": "..."}`; no secrets or entire profile. Decoder revalidates all fields.

- [ ] **Step 1: Write failing matching/compilation tests with exact policy assertions.**

```python
p = normalize_allowlist(Allowlist(("API.OPENAI.COM.", "*.example.com"), (), (443,)))
self.assertEqual(p.domains, ("api.openai.com", "*.example.com"))
self.assertTrue(is_protected_address("127.0.0.1", self.gateway))
self.assertTrue(is_protected_address("::ffff:127.0.0.1", self.gateway))
self.assertEqual(compile_policy(p, self.gateway, proxy_uid=2001, relay_uid=2002).digest,
                 compile_policy(p, self.gateway, proxy_uid=2001, relay_uid=2002).digest)
```

Add named cases for suffix spoofing (`api.openai.com.evil.test`, `evilapi.openai.com`), wildcard apex exclusion, exact host inclusion, bare wildcard/URL/userinfo/port/control-character rejection, CIDR canonicalization, boolean/zero/out-of-range ports, no reverse DNS grants, and stable digest across harmless ordering/comments. Pin protected-address precedence for explicitly allowlisted private IPs, IPv4-mapped IPv6, host public IPs, both sandbox subnets, multicast/link-local/unspecified/reserved ranges. Add `test_nft_dns_and_relay_exceptions_are_scoped_to_uid_and_destination`: only proxy DNS to selected resolvers and relay UID to exact T3:3773 are exceptions, never general private-address grants.

- [ ] **Step 2: Run `PYTHONPATH=scripts python3 -m unittest discover -s tests -p test_policy.py -v`.** Expected: missing compiler/normalizer failures.

- [ ] **Step 3: Implement normalization and generation.** Require explicit ASCII DNS/Punycode spelling; no automatic broad domain expansion. Generate Squid ACLs in deny-before-allow order with non-public destination denial before domain/IP grants, safe ports from YAML, CONNECT only to allowed ports, cache off, reverse DNS matching off, private-interface listener only, and final deny-all. An empty domain/IP list permits nothing. Generate an `inet` nft table with default-drop forwarding/output, established replies, trusted management INPUT, private-proxy INPUT, UID-scoped DNS/relay exceptions, and permitted global TCP destination ports after protected-address drops. Build protected ranges explicitly for supported Python versions and test mapped addresses; do not rely on one Python version's `is_global` quirks. Resolver addresses are trusted topology, not client-selected destinations. No arbitrary NFT/Squid text is accepted from YAML.

- [ ] **Step 4: Run policy and profile tests.** Expected: all pass. Real parser and connection tests are added in Tasks 5 and 9; string generation tests alone do not establish enforcement.

- [ ] **Step 5: Commit:** `feat: compile outbound policy with protected address guards`.

## Task 5: Trusted gateway image, service supervision, and denial records

**Files:** Create `proxy/Dockerfile`, `proxy/runtime.py`, `denials.py`, `tests/test_proxy_runtime.py`; extend `.dockerignore`, `Makefile` build behavior, and policy tests as needed.

**Interfaces:**
- Gateway CLI: `python3 /opt/t3-proxy/runtime.py {validate,serve} --snapshot /run/t3-policy/active.json`; `validate` installs no firewall and starts no listeners.
- `validate_snapshot(path: Path) -> CompiledPolicy`; `serve(snapshot: Path, logs: Path) -> int`.
- `DenialRecord(timestamp: str, destination: str, port: int, method: str, reason: str, policy_digest: str)` with canonical JSON-line output.
- `parse_denial(line: str, *, policy_digest: str) -> DenialRecord | None`, `append_denial(path: Path, record: DenialRecord) -> None` in `denials.py`.
- Health marker `/run/t3-proxy/ready.json` includes the applied digest only after firewall and both daemons are ready.

- [ ] **Step 1: Write failing supervision/logging tests.**

```python
self.assertIsNone(parse_denial(self.upstream_403_record, policy_digest="a" * 64))
denied = parse_denial(self.policy_denied_record, policy_digest="a" * 64)
self.assertEqual((denied.destination, denied.port, denied.reason),
                 ("blocked.example", 443, "unlisted_destination"))
self.assertNotIn("token=secret", json.dumps(dataclasses.asdict(denied)))
```

Name cases `test_validate_starts_no_daemons`, `test_firewall_failure_prevents_listener_start`, `test_proxy_and_relay_drop_capabilities_and_use_distinct_uids`, `test_child_failure_terminates_gateway`, `test_denial_writer_rotation_is_bounded`, `test_upstream_403_is_not_a_policy_denial`, and `test_log_backpressure_has_bounded_memory`. Assert no credentials, paths, query strings, or control characters escape into records. Use fixed reason enum `unlisted_destination`, `forbidden_port`, `protected_address`.

- [ ] **Step 2: Run `PYTHONPATH=scripts python3 -m unittest discover -s tests -p test_proxy_runtime.py -v`.** Expected: missing runtime/log API failures.

- [ ] **Step 3: Implement the image and runtime.** Install Squid, nftables, socat, Python/PyYAML, CA certificates, and privilege-dropping utilities in the Dockerfile. Use proxy UID 2001 and relay UID 2002. Start privileged initialization only in the gateway's own rootless namespace with `CAP_NET_ADMIN`; set IPv4/IPv6 forwarding to zero, install the compiled firewall, then drop capabilities for supervisor and daemons. Use separate UIDs and `no-new-privileges`. Expose no engine socket or T3 data mounts. A fixed relay forwards gateway:3773 only to configured T3:3773. Squid listens only on private_ip:3128. Ensure the packaged Squid config has no inherited unrestricted ACL/listener. SIGTERM stops all children; loss of either daemon exits nonzero. Suppress unsafe default access logging.

- [ ] **Step 4: Configure Squid to emit bounded, escaped policy-decision fields.** Use ACL tags/error identifiers to distinguish policy denials from upstream status codes; do not infer denial from HTTP status alone. Normalize through `parse_denial`, write JSONL to the gateway-only log directory, and rotate at 5 MiB with 3 retained files. Read malformed records defensively; no unbounded queue between Squid and log writer. Use unit fixtures from the installed Squid version's actual emitted records, not invented log syntax.

- [ ] **Step 5: Build a disposable proxy image and validate actual Squid/nft parsers.** Run `podman build -f proxy/Dockerfile -t localhost/t3-code-proxy-plan-check .` and an offline `validate` container with a temporary snapshot directory mounted read-only. For nft syntax use a disposable isolated rootless container with `CAP_NET_ADMIN`, never the host/global firewall. Expected: valid policy accepted; missing/malformed snapshot, injected directives, and broken nft/Squid configs exit nonzero before readiness. Remove only the disposable check container/image when no longer needed.

- [ ] **Step 6: Rerun the full unit suite and commit:** `feat: add isolated Squid gateway and structured denial logs`.

## Task 6: Enforce private-network startup and lifecycle

Support boundary: create/accept only IPv4 operational external topology and select only IPv4 resolvers. Reject unsupported IPv6/mixed external subnets or resolver settings before startup; retain IPv6 host-address discovery/protection and all private-bridge IPv6 hardening. Do not add ICMP/NDP exceptions to enable unsupported egress.

**Files:** Create `network.py`, `tests/test_network.py`; extend `launcher.py`, `podman.py`, `tests/test_sandbox.py`, and README restricted-mode instructions.

**Interfaces:**
- `ensure_networks(podman: Podman, identity: ProfileIdentity, server: ServerSettings) -> GatewayConfig` creates/inspects owned networks and assigns stable addresses; `server` supplies host bind/port.
- `harden_bridge(podman: Podman, identity: ProfileIdentity) -> None`.
- `assert_isolated(podman: Podman, identity: ProfileIdentity, gateway: GatewayConfig) -> None`.
- `start_restricted(profile: Profile, paths: ProfilePaths, *, podman: Podman, host: HostContext) -> None` called by `Launcher`.
- Runtime files: `runtime/topology.json` and atomically published `runtime/policy/active.json`; only `runtime/policy` is mounted read-only to the proxy. Record the active policy digest in readiness/host runtime metadata, not only immutable container labels.

- [ ] **Step 1: Write failing network/startup sequencing tests.**

```python
self.fake.set_bridge_addresses(["fe80::1234/64"])
self.launcher.dispatch("start", "work")
self.assertLess(self.fake.event_index("disable_bridge_ipv6"),
                self.fake.event_index("start_t3"))
self.assertEqual(self.fake.t3_networks(), [self.identity.private_network])
self.assertEqual(self.fake.gateway_published_ports(), ["0.0.0.0:3774:3773"])
self.assertFalse(self.fake.proxy_port_is_published())
```

Add `test_ipv4_addressed_bridge_is_rejected_before_t3_start`, `test_bridge_hardening_failure_never_falls_back`, `test_unexpected_network_member_prevents_reuse`, `test_proxy_precedes_t3_and_cleanup_is_owned_only`, `test_restart_rechecks_recreated_bridge`, `test_unowned_name_collision_is_rejected`, `test_policy_change_and_topology_change_report_different_actions`, `test_two_profiles_cannot_reuse_one_shared_t3_state`, and `test_profile_mutations_are_serialized`. Fake errors must distinguish unsupported host/runtime from a security-invariant failure.

- [ ] **Step 2: Run `PYTHONPATH=scripts python3 -m unittest discover -s tests -p test_network.py -v`.** Expected: missing networking behavior failures.

- [ ] **Step 3: Implement restricted networking and ordered creation.** Create `--internal --disable-dns` private network and a dedicated external network. Inspect the allocated subnet; reserve two deterministic free host addresses and set them explicitly on T3/gateway so a gateway restart preserves the endpoint. Configure external routing only on the external interface. Start the trusted gateway first to materialize the bridge, disable host-side bridge IPv6 using `podman unshare --rootless-netns sysctl`, and verify `ip -j addr` has no addresses. Reject an IPv4-addressed private bridge instead of quietly deleting its address. After gateway readiness and host-side checks, run a trusted disposable route probe attached only to the private network, without user mounts or runtime env-file settings; verify no IPv4/IPv6 default route and remove that owned probe before final membership verification. Then start T3 on the same network with no public DNS service or host aliases and immediately verify its actual routes. All enforcement controls outside T3 must already be active before launch; a route mismatch stops the new workload with a diagnostic. Do not assume inspecting network configuration alone proves container routes.

- [ ] **Step 4: Implement mode-aware lifecycle.** On failure stop/remove only resources this operation created; do not prune other networks. Stop T3 before proxy; remove both owned containers before owned networks, preserving homes, live profiles, logs, legacy volumes and original host state. Mode changes use full recreation. Off never attaches restricted networks or requires a proxy image. Build the proxy image in `build`/`rebuild` only when selected profile is restricted. Verify actual image identity, memberships, bind/ports, and mount topology when reusing resources. Isolate mutation locks by profile; hold a separate short allocation lock only for shared address/port decisions.

- [ ] **Step 5: Run network, launcher, and full unit tests.** Expected: pass. Add a real disposable two-container connectivity check using the production gateway image, repeating the IPv6 host-side service probe from the spike; this is a prerequisite to marking restricted startup usable, not a substitute for Task 9.

- [ ] **Step 6: Commit:** `feat: enforce proxy-only networking outside the T3 namespace`.

## Task 7: Proxy-only policy restart and firewall-log command

**Files:** Extend `launcher.py`, `denials.py`, `scripts/sandbox.py`, `Makefile`; create `tests/test_firewall_logs.py`, add proxy-restart cases to `tests/test_sandbox.py`; update README commands.

**Interfaces:**
- `Launcher.proxy_restart(name: str) -> int`.
- `read_denials(directory: Path, *, tail: int=100, follow: bool=True) -> Iterator[DenialRecord]`.
- `make proxy-restart PROFILE=work`; `make firewall-logs PROFILE=work FOLLOW=0 TAIL=100` for finite output; omitted `FOLLOW` means follow. These selectors do not mutate YAML.

- [ ] **Step 1: Write failing hot-policy and log-follow tests.**

```python
before = self.fake.t3_identity_and_start_time()
self.edit_policy(domains=["api.openai.com", "new.example"])
self.assertEqual(self.launcher.proxy_restart("work"), 0)
self.assertEqual(self.fake.t3_identity_and_start_time(), before)
self.assertFalse(self.fake.t3_was_stopped_or_recreated())
self.assertTrue(self.fake.snapshot_replacement_visible_on_restart())
```

Add `test_invalid_policy_keeps_old_proxy_and_digest`, `test_topology_edit_requires_recreate_without_stopping_proxy`, `test_failed_proxy_restart_leaves_t3_running_and_no_fallback`, `test_off_mode_does_not_create_proxy`, `test_firewall_logs_follow_rotation_and_restart`, `test_firewall_logs_work_with_invalid_yaml`, `test_log_follow_does_not_hold_mutation_lock`, and `test_log_stdout_has_only_selected_profile_denials`. Assert Ctrl-C leaves containers running; finite mode emits at most the requested records in chronological order across retained files; errors use stderr/nonzero exit status. Assert active-vs-saved digest remains accurate after a failed restart.

- [ ] **Step 2: Run `PYTHONPATH=scripts python3 -m unittest discover -s tests -p test_sandbox.py -v` and `PYTHONPATH=scripts python3 -m unittest discover -s tests -p test_firewall_logs.py -v`.** Expected: failures for missing commands.

- [ ] **Step 3: Implement transactional validation and proxy-only restart.** Under the selected profile lock, read YAML once, compare topology with actual active resources, compile a candidate into a new temporary file, and validate it with the actual proxy image/software before stopping anything. Atomically publish the candidate into the existing policy directory, restart only the existing proxy container, and verify stable private IP and host binding, hardened bridge, installed firewall, matching readiness digest, and published T3 readiness. Directory mounting must expose the new inode. On invalid candidate leave the running proxy untouched; on failed restart leave it unavailable without automatic broader-policy rollback. T3 is not stopped or reconfigured. Report that active streams must reconnect.

- [ ] **Step 4: Implement denial viewing and safe recovery dispatch.** Discover log location from validated identity even when edited YAML is invalid. Follow files by inode/rotation without holding the profile mutation lock, use bounded memory, and keep diagnostic output out of the JSONL stdout stream. No new log or proxy is created when mode is off. Explain direct no-route attempts are not visible here.

- [ ] **Step 5: Run full unit suite and commit:** `feat: restart proxy policy independently and expose denial logs`.

## Task 8: Build-time browser provisioning and proxy-compatible runtimes

**Files:** Modify `Dockerfile`, `.dockerignore`, `scripts/entrypoint.sh`, `launcher.py`; create `scripts/install-t3-browser.py`, `scripts/browser-launcher.sh`, `tests/test_browser_assets.py`; update README included-tool/browser sections.

**Interfaces:**
- Build helper CLI: `install-t3-browser.py --t3 /usr/local/bin/t3 --destination /opt/t3-browser`.
- Output: immutable browser assets plus `manifest.json` recording installed T3 binary hash/version, browser platform/version, cache-relative executable path, and asset hashes. Runtime helper uses this manifest only; no discovery/download service calls at startup.
- `browser_cache_mount(profile: Profile, host: HostContext) -> list[str]` in `launcher.py` mounts a writable tmpfs at the container's `.t3/tools/chrome-headless-shell` cache subtree, shadowing shared/private caches without changing the original host cache. It is seeded locally by entrypoint before T3 starts.
- `T3_SANDBOX_BROWSER_PROXY` is a launcher-injected browser-wrapper variable, set only in restricted mode. This is our own variable, not a claimed upstream T3 setting.

- [x] **Step 1: Write failing asset/runtime tests.**

```python
self.seed_browser_cache_with_image_manifest()
self.assertEqual(self.host_browser_sentinel.read_bytes(), b"original-host-browser")
self.assertTrue(self.seeded_browser_entry.is_file())
self.assertTrue(os.access(self.seeded_browser_entry, os.X_OK))
self.assertIn("--proxy-server=http://10.89.0.2:3128", self.wrapper_args_for_restricted_mode())
self.assertNotIn("--no-sandbox", self.wrapper_args_for_restricted_mode())
```

Add `test_seed_is_local_and_works_with_empty_home`, `test_existing_shared_t3_cache_is_not_modified`, `test_wrapper_preserves_argv_and_handles_version_probe`, `test_unrestricted_wrapper_uses_no_proxy`, `test_runtime_env_file_cannot_override_selected_proxy`, and `test_browser_asset_version_mismatch_fails_before_server_start`. Test both uppercase/lowercase proxy vars, loopback-only NO_PROXY, and arguments containing spaces without shell evaluation.

- [x] **Step 2: Run `PYTHONPATH=scripts python3 -m unittest discover -s tests -p test_browser_assets.py -v`.** Expected: missing provisioning/seeding failures.

- [x] **Step 3: Implement build-time provisioning using the installed T3 executable's own installer.** In a disposable build-only T3 base directory, materialize the installed npm release's exact native runtime (including its adjacent modules/client assets) into immutable `/opt/t3-runtime`, then start a loopback T3 server and initialize its authenticated local `/mcp` session before invoking the HTML tool. If the installed release rejects a threadless client, use its authenticated public `/ws` `preview.open` RPC with the advertised orchestration protocol, a disposable thread UUID, `runtime: "server"`, and URL omitted. The installed releases reject explicit `about:blank`; the omitted optional URL creates the blank preview. Both supported paths invoke the installed T3's own pinned browser installer. This fallback is controller-approved and verified against installed v0.1.0/v0.1.1. Use a generated local T3 session credential, keep it out of output, and delete its entire database/auth state in that same Dockerfile RUN layer. Wait for the executable and verify its local version/hash; a browser-launch sandbox failure after a verified download is distinct from download failure and must not silently disable sandboxing at runtime. Copy only verified browser assets and a manifest into `/opt/t3-browser`. All downloads occur in the Dockerfile build; use no host auth mounts. Avoid installing an unrelated Playwright/browser version.

  Source evidence for the cache contract: T3 revision `ed3f965e0768f9a77729a17c5145a90ff3ab6210`, `apps/server/src/preview/PreviewBrowser.ts`, uses `<baseDir>/tools/chrome-headless-shell/<platform>/<version>/chrome-headless-shell`; it validates release size/SHA-256. `ServerBrowserContexts.ts` supplies an executable and does not expose a proxy option. Match the installed binary's observed behavior; do not hardcode that source revision's browser version for a different `T3_VERSION`. If the installed release lacks the documented auth/tool interface, detect that during build and fail with a precise compatibility error rather than shipping runtime downloads.

- [x] **Step 4: Implement cache shadowing and browser proxy wrapper.** The entrypoint copies a tiny executable wrapper into the expected cache-relative path inside the tmpfs. The wrapper execs immutable image browser assets with Chromium's explicit `--proxy-server` when restricted and otherwise preserves normal behavior. The rest of the browser's libraries/resources remain together in `/opt/t3-browser`. Shadowing prevents a wrapper referring to `/opt/...` from damaging the original host T3 browser after the container exits. Never overwrite a real executable in shared `~/.t3`. Use Podman 4.9.3-compatible `mode=1777,notmpcopyup` (uid/gid options are rejected); verify the actual writable tmpfs before writes. Ensure permissions permit non-root cache seeding and all user homes remain persistent outside this rebuildable cache subtree.

- [x] **Step 5: Set and validate runtime proxy environments.** Set both cases of HTTP_PROXY/HTTPS_PROXY/ALL_PROXY after env-file options, NO_PROXY to in-container loopback only, and Node's environment-proxy opt-in supported by the installed Node 24. Native T3/Bun and Codex must be exercised against the production proxy; a client bypassing variables fails closed. Do not add a generic SOCKS service or external route to fix it. Update `.dockerignore` to include only provisioning/package files required by each Dockerfile; credentials, local profiles, and `.codex/` remain excluded.

- [x] **Step 6: Build a selected test profile image and run its browser entry/CLI version probes with `--network=none` and an empty home.** Expected: browser binary and all CLIs are present, no dependency lookup occurs, and shared host-cache sentinels remain unchanged. Actual T3 browser rendering and Codex streaming are Task 9 acceptance checks. Run full unit suite, shell syntax checks, then commit: `feat: provision T3 browser assets during image build`.

## Task 9: Real Podman security/regression verification and migration guide

Support boundary: verify IPv4-only operational external topology/resolvers and explicit rejection of IPv6/mixed settings. Keep every IPv6 direct-access, host-side bridge, protected-literal, and mapped-address negative test. IPv6-only resolver/upstream success is outside this version; no broader ICMP/NDP grant is authorized.

**Files:** Create `tests/integration/{support,test_network,test_runtime}.py` and `docs/network-verification.md`; modify `Makefile` (`test`, `test-integration`, mode-aware `smoke`), README migration/operations, and affected launcher smoke code.

**Interfaces:**
- `make test` runs the unit suite, no real Podman resources or network.
- `T3_SANDBOX_INTEGRATION=1 make test-integration` runs only against unique temporary profiles, separate test data roots/selectors, explicitly owned labels, and random unused host ports. Never use the real `default` profile or actual host `.t3` for fixtures.
- Test helper context manager owns disposable containers/networks/services, creates temporary host/provider directories, and guarantees bounded cleanup. Cache/built images may be retained, but no data volume or existing resource is pruned.
- Instantiate `Launcher` with an injected `HostContext` using actual UID/GID/user and a temporary host-home path; do not repurpose the process's `$HOME` or touch real user credentials. CLI selector forwarding is covered by the unit subprocess fixture.
- All real resource identities use unique `it-<random>` profile names even with a temporary host-home path, because UID/profile-derived Podman names otherwise collide. Default-name normalization is unit-tested; integration applies those resolved sharing flags explicitly to a uniquely named fixture profile pointing at fake host state. Never launch a real container named `t3-sandbox-<uid>-default` for a test.
- `SandboxLab` in `tests/integration/support.py` supplies `t3_identity_and_start_time() -> tuple[str, str]`, `start_local_counter_job() -> CounterJob` (`initial_count: int`), `counter(job: CounterJob) -> int`, `allow(domain: str) -> None`, `proxy_restart() -> None`, `https_via_proxy(url: str) -> ProxyResponse` (`status: int | None`, `connect_status: int | None`), and `management_websocket_reconnects() -> bool`. It drives production launcher APIs, not a second implementation of lifecycle logic.

- [ ] **Step 1: Write the integration assertions before running the complete implementation.** Cases must observe results, not only generated flags:

```python
before = lab.t3_identity_and_start_time()
job = lab.start_local_counter_job()
lab.allow("example.com")
lab.proxy_restart()
self.assertEqual(lab.t3_identity_and_start_time(), before)
self.assertGreater(lab.counter(job), job.initial_count)
self.assertEqual(lab.https_via_proxy("https://example.com").status, 200)
self.assertEqual(lab.https_via_proxy("https://unlisted.example").connect_status, 403)
self.assertTrue(lab.management_websocket_reconnects())
```

  Implement separately named cases for: direct IPv4/IPv6 and DNS failure with every proxy env cleared; reachable proxy only; host/LAN/unrelated-profile denial; the previously successful host-side bridge IPv6 service failing; protected literal/mapped addresses denied even when listed; allowed DNS hostname resolving privately and deterministic DNS-answer changes still denied; proxy UID direct socket attempt to a protected destination blocked by nft even if application ACLs were bypassed; fixed relay cannot become an arbitrary forwarder; wildcard and allowed-IP behavior through real Squid; upstream 403 excluded from denial logs; log rotation/restart persistence; proxy crash/restart preserving T3 and isolation; host non-loopback HTTP/WebSocket/pairing; and two simultaneously running profiles staying separate.

- [ ] **Step 2: Run the integration suite and confirm it initially detects at least the corresponding incomplete behavior before treating a new test as useful.** For code already implemented, a targeted reversible fault injection inside the owned fixture (e.g. omit bridge IPv6 hardening or corrupt candidate policy) must make the relevant assertion fail. Do not weaken production controls or edit existing host networks for a test.

- [ ] **Step 3: Add persistent-state and unrestricted-mode regressions.** Verify private state markers through actual image rebuild/recreation/removal; fake host `.t3` sharing only for `default`; independent provider flags; no implicit migration or deletion; unchanged host browser cache after exit; and an unrestricted profile working with no proxy image/container/network. Validate missing default initialization plus independent second-profile ports, recovery commands after malformed YAML, and command concurrency. Change a structural field and prove proxy-only restart rejects it before stopping anything.

- [ ] **Step 4: Verify actual T3/browser/Codex paths.** With production sandbox settings, render local HTML and open a local browser page using installed image assets, then demonstrate allowed browser HTTPS through the proxy and blocked unlisted HTTPS. Exercise a real Codex model request and streaming/WebSocket path with existing credentials only when explicitly available to that disposable test; do not expose credentials in reports or make them a fixture dependency. If unavailable, separately report successful unauthenticated TLS/HTTP transport and mark authenticated model validation pending. Claude authenticated validation remains optional. A host AppArmor/browser-sandbox prerequisite failure is a documented prerequisite, not permission to turn off sandboxing silently.

- [ ] **Step 5: Finish mode-aware smoke and operational documentation.** `make smoke` must not probe npm in restricted mode; use a permitted provider HTTPS endpoint and distinguish expected 401/403 from connection failure, check local/published T3 readiness, and retain real project UID/GID ownership checking. README covers default-profile auto-save, `PROFILE=...`, private/shared state paths, one T3 server per shared `.t3`, disable flag, policy edit plus `proxy-restart`, denial log scope/FOLLOW=0, profile locks, `0.0.0.0` exposure versus advertised URL, and host/WSL firewall prerequisites. Include a manual `.env`-to-YAML mapping and an explicit offline, inspect-first legacy-volume copy procedure; normal commands never migrate/delete it. Include limits: destination grants permit data transfer, TLS not intercepted, host/kernel/proxy trusted.

- [ ] **Step 6: Run final checks once after the last implementation change.**

```bash
make test
T3_SANDBOX_INTEGRATION=1 make test-integration
bash -n scripts/sandbox.sh scripts/entrypoint.sh scripts/browser-launcher.sh
git diff --check
```

  Expected: unit suite passes; mandatory integration cases actually run and pass (not all skipped); syntax/whitespace checks exit zero; owned test resource lists empty after cleanup. Record Podman/Netavark, Squid, nftables, T3, Codex, Node and browser versions plus any unavailable authenticated/architecture/external-machine checks in `docs/network-verification.md`. Run `shellcheck` where available. Do not claim LAN access from another physical device merely from a host non-loopback test.

- [ ] **Step 7: Commit:** `test: verify restricted networking and document profile migration`.

## Self-review and handoff

- Spec coverage: Tasks 1–3 cover configuration, parallel profiles, persistence and unrestricted compatibility; Tasks 4–6 enforce policy and the external boundary; Task 7 covers mutable policy/logging; Task 8 covers offline runtime assets; Task 9 verifies real behavior and migration limits.
- Interfaces: keep the exact selector names, dataclass names, paths, fixed ports, and reason enum above. Update both this plan and dependent task contracts if an implementation seam changes.
- Review Focus coverage: host cache in Tasks 8–9; recovery in Tasks 2/3/7; races/order in Tasks 1/3/6; rotation in Tasks 5/7; hostile policy/path/DNS input in Tasks 1/2/4/5/9.
- Execution is sequential because later tasks consume earlier policy/lifecycle interfaces. Independent implementation work is not required for this plan. A whole-branch security review is required before presenting the feature as complete, with particular attention to raw gateway paths, DNS exceptions, state sharing, and fail-closed startup/restart.
- This plan does not authorize deployment, publication, a PR, destructive state cleanup, or changes to other running containers. Follow the approved scope and preserve the pre-existing untracked `.codex/` directory.
- User review and execution-method selection are the next steps; no implementation has started.
