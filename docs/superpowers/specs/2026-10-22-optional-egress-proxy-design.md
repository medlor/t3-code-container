# Optional outbound proxy for the T3 sandbox

Status: revised proposal; awaiting user approval. Implementation must follow a separate plan.

## Intent and agreed requirements

Restrict every process in the T3 container to approved external destinations,
without relying on those processes to honor proxy settings. The user primarily
uses Codex and also wants a predefined Claude allowlist.

- Restricted mode is optional and defaults to off. Off uses ordinary outbound
  networking and creates or requires no proxy container.
- On uses a separate proxy container. One host-side YAML profile combines
  launcher settings and network policy; there is no separate `.env` or live
  `network.yaml` to keep in sync.
- Named profiles support independent parallel sandboxes. All Make commands select
  a profile through `PROFILE=<name>`, defaulting to `default`.
- Editing the whitelist and restarting only the proxy must leave the T3 container
  and its jobs running. The user explicitly accepts brief interruption of
  management connections and active outbound streams during that restart.
- `make firewall-logs` writes denied proxy connection requests to stdout to help
  the user maintain the whitelist.
- T3 must not directly reach the internet, host, LAN, or unrelated containers.
- Incoming management connections and their replies must remain functional,
  published on host `0.0.0.0`. The current management service is TCP 3773 and
  includes HTTP and WebSocket traffic.
- T3, Codex, Claude, and T3's browser runtime dependencies are installed during
  image build. Package registries and download services need no runtime grants.
- The user selected separate network namespaces connected by an isolated
  network. They rejected dependence on a firewall in T3's own namespace.

This is a project-sized change to launcher lifecycle, networking, image builds,
configuration, documentation, and integration verification.

## Current repository

`scripts/sandbox.sh` controls rootless Podman through Make. T3 currently uses
slirp4netns for outbound access. It runs as the matching host UID/GID, with all
capabilities dropped and `no-new-privileges`. Project and selected provider
state directories are writable bind mounts; the rest of its home is a volume.
The existing `.env` and Make/environment setting overrides will be replaced by
named YAML profiles; the current `SANDBOX` selector becomes `PROFILE`.

`Dockerfile` already installs a broad toolchain and the provider CLIs. The cached
T3 package is a launcher for a self-contained executable. Its `t3 browser` command
offers host setup, not a browser-download subcommand; first browser use downloads
a runtime into T3 home. Shared home/state mounts must not hide any runtime added
to the image.

## Approaches considered

1. **Separate namespaces and an isolated bridge — selected.** Only the proxy
   has an external connection. The proxy also relays management traffic to T3.
   This adds lifecycle and bridge-hardening work, but keeps the enforcement
   boundary outside T3's namespace.
2. **Shared namespace with firewall rules per process user — rejected.** This
   simplifies management publishing but puts routing and firewall state in the
   same network namespace as the workload. The user prefers stronger separation.

The initial experiment is recorded in
[network-isolation-spike](2026-10-22-network-isolation-spike.md). On rootless Podman
4.9.3 with Netavark, `--internal` alone left a reachable host-side IPv6 link-local
address. Disabling IPv6 on that private bridge, outside T3, closed the tested
path. This is a required control, not optional hardening.

## Network topology and invariants

Each profile in restricted mode owns one private bridge network, one external
network, one proxy container, and its T3 container. Names and ownership labels
include the host UID and profile name. T3 has only the private network; the proxy
has both networks. They do not share network, PID, or IPC namespaces.

The private bridge has DNS disabled, no IPv4/IPv6 address in Podman's host-side
network namespace, and no default route in T3. Disable IPv6 on the host-side
bridge and verify the absence of addresses. Refuse to start restricted workloads
if the backend creates an IPv4-addressed bridge or any required invariant cannot
be verified. Use no host gateway mappings or container-engine sockets.

The private network contains only this sandbox's two containers. The external
network contains only its proxy. Membership and settings must be inspected when
reusing resources; similarly named resources are not assumed to be trusted.

Gateway IPv4 and IPv6 packet forwarding are disabled. The outbound proxy binds
only its private IPv4 address, on TCP 3128; it is never published on the host.
T3 can contact that listener and its own local services. Incoming management
connections enter the proxy container through a published TCP port and a fixed
relay to T3's private address on 3773. The relay is not an arbitrary destination
forwarder. T3 replies over that connection; it gains no route to the client.

All processes in T3 retain the existing non-root identity, dropped capabilities,
and `no-new-privileges`. The host launcher and proxy setup own the controls. No
firewall, host network namespace handle, or policy-control socket is exposed
inside T3.

## Proxy implementation proposal

My implementation choice is a dedicated small Linux image with Squid, Python
and a safe YAML parser for policy compilation, nftables for destination-address
protection, and a fixed TCP relay such as socat. Use packaged, maintained proxy
software rather than promote the experiment's Python proxy into production.

The proxy accepts ordinary HTTP proxy requests and HTTPS CONNECT tunnels.
CONNECT preserves end-to-end TLS, streaming, and secure WebSockets; there is no
TLS interception or custom CA. Turn caching off. Log destination, port, outcome,
and denial reason without credentials, headers, bodies, or URL query strings.

The policy compiler validates YAML, emits proxy ACLs, and rejects invalid
configuration before any listener becomes ready. Validate the generated Squid
configuration as well. Use safe YAML loading with duplicate-key rejection,
strict types, bounded size, and unknown-key rejection. Do not accept arbitrary
Squid directives or shell fragments.

Protect non-public destination addresses independently of hostname matching.
Reject loopback, private, link-local, multicast, unspecified, reserved ranges,
the sandbox networks, and host interface addresses, including IPv4-mapped IPv6.
Protected addresses cannot be overridden by allow entries. Put an additional
egress firewall in the proxy namespace so a DNS answer changing to a protected
address cannot evade a hostname check. This firewall is separate from T3.

Permit firewall exceptions only for management relay traffic to the exact T3
address/port, replies to incoming connections, and DNS to explicitly selected
resolvers. Scope resolver exceptions to the resolver/proxy process and DNS
ports. Proxy requests must never use these exceptions to reach private services.
No recursive DNS service is offered to T3. External TCP destination ports are
limited to those declared in the YAML. Drop forwarded packets.

Only trusted proxy initialization needs network-administration capability,
inside its own rootless container namespace. Drop that capability before running
the unprivileged proxy and relay processes. Do not grant it to T3. Daemons use
separate identities, minimal writable temporary paths, and no project/provider
credential mounts. If either required daemon fails, terminate the proxy
container rather than report partial health.

## Unified configuration profiles

The sole editable launcher/policy configuration is
`${HOME}/.config/t3-sandbox/profiles/<name>.yaml`. `HOME` means the host Linux
user's home directory. Ship a commented `config/profile.default.yaml` template
with the same defaults. A bootstrap-only `PROFILE_DIR` selector may choose an
alternative host directory; this is not an additional launcher settings file.
Keep it outside every T3-writable mount.

Every Make command accepts `PROFILE=<name>` and otherwise selects `default`:

```bash
make start
make init PROFILE=work
make start PROFILE=work
make status PROFILE=work
make proxy-restart PROFILE=work
make firewall-logs PROFILE=work
make stop PROFILE=work
```

Profile names must pass the existing safe sandbox-name validation and cannot
contain slashes or traverse directories. A profile name is also its resource
identity; do not introduce an independent `sandbox` property that can collide.
Recovery/read commands such as `stop`, `status`, `logs`, and `firewall-logs`
resolve owned resources from that identity without requiring a valid edited
whitelist. A malformed whitelist must not prevent stopping the sandbox or
reading why requests were denied.

If `default.yaml` does not exist, atomically create it from the repository
template with reasonable resolved defaults and report its path. Never overwrite
an existing file. A missing nondefault profile is an error pointing to
`make init PROFILE=<name>`; do not create profiles silently after a typo.
Initialization is idempotent and concurrent creation must not clobber a file.

Defaults are unrestricted networking, host bind `0.0.0.0`, management port 3773,
the existing toolchain/resource defaults, and a dedicated project directory at
`~/projects/t3-sandbox/<profile>`. Create that dedicated project directory on
first start if the profile permits it; do not mount the host home or `/`.
`make init` for another profile chooses and persists the next unused management
port starting at 3773, accounting for existing profiles and host listeners.
Once saved, never silently change the selected port on startup; report a
collision and let the user edit it. Concurrent starts still handle bind failure.

Give each profile its own T3 state/home by default. Preserve the option to reuse
host Codex/Claude state, but do not share `.t3` between default-created profiles:
multiple T3 servers cannot safely share it. Explicitly configured shared `.t3`
paths require collision detection before starting parallel profiles. Images may
be shared deliberately, but default image tags include UID/profile so building
one profile with different tool versions does not overwrite another's image.

All build selectors, project path, management binding, resources, state mounts,
runtime env-file reference, and network policy live in this YAML. Defaults can
fill omitted fields; `make config` displays the effective configuration and its
source path. Values are parsed as data, never sourced as Bash. Support `~` and
`${HOME}` in path fields only, without command substitution or arbitrary shell
expansion. Add host Python/PyYAML as an explicit prerequisite; the host must be
able to parse profiles even when no proxy image/container exists.

`PROFILE`, `PROFILE_DIR`, and execution/logging command arguments are selectors,
not overrides for persisted launcher settings. Remove implicit `.env` sourcing
and legacy settings overrides. Document a manual migration mapping from the
current `.env`; do not execute it automatically. Existing containers/volumes
remain untouched until the user explicitly selects a migration/recreation path.
An optional secret runtime env file remains separate by reference: it contains
credentials, not a second launcher or whitelist configuration.

Proposed profile shape (actual template and parser are implementation work):

```yaml
version: 1
project:
  directory: ~/projects/t3-sandbox/default
  create_if_missing: true
server:
  bind_address: 0.0.0.0
  port: 3773
  advertised_url: null
build:
  image: null # derive from host UID and profile name
  ubuntu_image: docker.io/library/ubuntu:rolling
  node_image: docker.io/library/node:24-bookworm-slim
  codex_version: latest
  claude_version: latest
  t3_version: latest
resources:
  memory: 8g
  cpus: 4
  pids_limit: 2048
state:
  share_host_state: true
  share_host_t3_state: false
  t3_directory: ~/.t3
  codex_directory: ~/.codex
  claude_directory: ~/.claude
runtime:
  env_file: null
  automatic_healthcheck: false
network:
  restricted: false
  allow:
    domains:
      - api.openai.com
      - auth.openai.com
      - chatgpt.com
      - api.anthropic.com
      - claude.ai
      - platform.claude.com
      - console.anthropic.com
      - t3.codes
      - app.t3.codes
    ips: []
    ports: [443]
```

Null memory/CPU values omit those limits. `server.port` is the host port; T3
continues to listen on 3773 internally. `server.advertised_url`, when set, is
used for pairing instead of the default local URL. Build image paths and version
strings are validated as arguments, not interpolated into shell code.

Validate resolved profile paths and reject files inside the project or shared
state mounts. A read-only proxy mount alone does not protect a source file T3
can edit through another mount. Keep derived runtime snapshots and logs under
host-managed per-profile directories outside those mounts. Send only the
required network policy and trusted topology settings to the proxy, not the
entire profile or runtime secrets. There is still only one editable source.

Track T3/topology settings separately from the mutable allowlist. A changed
project, network mode, proxy endpoint, state mount, resource setting, or
management binding requires `make recreate`. Whitelist domains, IPs, and allowed
ports can change through `make proxy-restart` without T3 recreation. `status`
reports the active policy digest and whether the saved policy has unapplied
changes. General `start` never silently claims to have applied such changes;
it tells the user to run the appropriate proxy restart or full recreation.

Domains match exact hostnames, case-insensitively, normalized for a trailing dot.
An optional `*.example.com` matches its subdomains, not the apex. Reject a bare
`*`, URLs, paths, embedded ports, userinfo, and malformed hostnames. Support
explicit IPv4/IPv6 addresses and CIDRs in `ips`, without reverse-DNS matching.
Domain rules authorize the requested hostname; an IP rule authorizes addresses
in the resolved destination set. Protected-address denial always wins. A
redirect is a new request and must independently pass the policy.

The default uses exact provider hosts rather than entire vendor domains. Treat
this as a documented starting list to verify against the image's installed CLI
versions, not a claim that every optional plugin or login provider works.
OAuth completed in the user's normal external browser needs no container grant
for that browser's identity-provider requests. Device authentication and reuse
of existing host auth state remain the recommended Codex paths.

The T3 server's direct pairing path is inbound and does not itself need internet
access. The two T3 hosts above are predefined product origins, not evidence that
T3 Connect or every optional feature is supported. During implementation inspect
the installed T3 source/runtime for additional essential runtime endpoints; add
only specific documented or observed destinations with their purpose. Do not add
broad GitHub, npm, PyPI, distro-mirror, browser-CDN, telemetry, or update grants.
CLI updates continue through image rebuilds. Additional remote MCP servers,
Git remotes, browsing sites, regional APIs, and enterprise identity services
require explicit host policy edits.

## Proxy-only policy updates

`make proxy-restart PROFILE=<name>` reads and validates the selected full profile,
checks that its T3/topology settings still match the active sandbox, and compiles
a candidate network-policy snapshot. Parse-check it using the actual proxy
software before stopping the existing proxy. Invalid edits leave the existing
proxy and active policy running unchanged, with an actionable error.

On success, atomically publish the derived snapshot and restart only the
existing proxy container. Preserve its fixed private address, network
memberships, published management port, and the running T3 container's ID/PID,
home, and mounts. Do not remove/recreate networks or run T3 entrypoint hooks.
Mount the snapshot directory read-only into the proxy so atomic file replacement
is visible after restart; binding an individual old file inode would not work.
Each snapshot is generated from a validated immutable read of the host profile.

Verify bridge isolation before the new gateway accepts traffic, reinstall its
namespace-local egress controls, and wait for proxy plus management readiness.
If the replacement fails, leave the proxy unavailable and report the failure;
do not revert to a broader policy automatically. T3 stays running with no
external route. The external management endpoint is temporarily unavailable
while the gateway is down. Existing CONNECT tunnels, API streams, and management
WebSockets disconnect; clients may reconnect/retry after readiness. Local T3 jobs
continue, although jobs awaiting network traffic can fail or retry. This
interruption was explicitly accepted by the user.

`proxy-restart` in unrestricted mode reports that there is no proxy and does not
create one. Full `make restart` still restarts the selected profile's T3 and
proxy; `make recreate` applies structural profile changes. Commands for one
profile must not restart another profile's resources.

## Denied-request logs

`make firewall-logs PROFILE=<name>` prints the selected profile's denied proxy
requests to stdout, using the latest 100 records and following new records by
default. Ctrl-C ends viewing and leaves services running. Provide a finite
non-follow option for scripts, without changing the profile. Operational errors
go to stderr with a nonzero exit code. With restricted mode off, report that
there is no proxy log rather than enabling the feature.

Use a dedicated normalized denial log rather than grepping arbitrary stderr or
every HTTP 403: an upstream 403 is not necessarily a policy denial. Each record
contains UTC timestamp, requested destination hostname or IP, destination port,
method, policy-denial reason (unlisted domain/IP, forbidden port, or protected
address), and policy digest. It contains no request path, query, tokens,
headers, body, or pairing credentials. Persist a bounded/rotated log outside
T3's mounts so recent denials survive proxy restart; profiles have separate logs.
Respect backpressure and rotation without blocking traffic indefinitely.

This command exposes application-proxy policy decisions. A direct attempt from
T3 that fails locally because there is no route never reaches the proxy and
cannot be reported with its requested domain. Observable proxy-side firewall
blocks may be logged separately with destination IP/port, but must not be
presented as domain-aware events. Do not promise an audit of every syscall or
silently add packet interception inside T3 to populate this log. Document this
scope next to `firewall-logs`; it is intended for adjusting proxy whitelist
entries, not as a complete container activity recorder.

## Client compatibility and dependencies

Set uppercase and lowercase `HTTP_PROXY`, `HTTPS_PROXY`, and `ALL_PROXY` to the
private HTTP proxy URL. Set both forms of `NO_PROXY` only for loopback and
explicit in-container service addresses. Apply these after runtime env-file
loading so stale host proxy settings do not accidentally replace them. Enable
Node's environment-proxy support where supported by the installed Node version.
Validate Codex's HTTP and WebSocket model paths, not just curl. T3, native Bun
code, and Chromium may need their own proxy configuration; inspect the installed
version and supply it. A client that does not support the proxy must fail closed.
Never add direct internet access to fix such a client.

All tool packages, proxy packages, native libraries, and the matching T3 browser
binary are downloaded in Dockerfile build steps. Store browser assets outside
the user's overlaid home/state mounts. Point T3 at the immutable image assets
using a supported runtime setting; if it only supports a home cache, seed the
exact versioned cache from image assets locally before startup, without network.
Include newly empty private homes and existing shared `.t3` mounts in validation.
Browser sandbox constraints remain explicit; do not disable its sandbox silently.

Project-specific npm/Python/etc. dependencies are not inferred or downloaded at
startup. Users add those to image build steps when needed. The promise is that
the bundled T3/provider/tool runtime is ready without dependency download grants.

## Startup, reuse, and cleanup

1. Validate settings, rootless Netavark support, policy location/content, image
   identity, and existing resource ownership before changing running resources.
   Materialize a missing default profile safely before resolving its settings.
2. Create the per-sandbox networks and start only trusted gateway initialization.
   Use a deterministic T3 private address to configure its fixed relay.
3. Harden the private bridge in the rootless host-side network namespace, verify
   that it has no addresses, and verify gateway forwarding and egress controls.
   No untrusted T3 process starts before these checks succeed.
4. Start T3 on the private network with the current identity/mount restrictions,
   and wait for both local T3 readiness and the published management endpoint.
5. On partial failure, stop anything newly started and remove only newly created
   resources. Never silently switch to unrestricted mode.

Every start/restart revalidates actual membership, interfaces, bridge addresses,
forwarding, and active policy digest before starting a stopped T3 container.
Distinguish saved whitelist changes, which need proxy restart, from conflicting
T3/topology settings, which require recreation.
Recreating a bridge invalidates earlier hardening; it must be applied again.

Stop T3 before the proxy. Remove only owned per-sandbox containers/networks and
generated snapshots, preserving home volumes, project files, live profiles, and
bounded denial history.
Switch modes through explicit recreation; it must not leave an unexpected
gateway running. Existing unrestricted sandboxes require recreation to adopt
the new host binding or restricted mode. `config`, `status`, `doctor`, logs, and
smoke commands describe the active mode and its managed resources. Pairing keeps
the token and accepts an optional reachable advertised URL; `0.0.0.0` is a bind
address, not a destination to put in a pairing link. Default local pairing can
continue to advertise `127.0.0.1`; external users configure the host's LAN/DNS URL.
Serialize mutations per profile with a host-side lock, while permitting different
profiles to start/stop/restart concurrently. Log viewing is not a mutation and
must not hold that lock while following.

## Verification and acceptance

- Regression checks cover mode off: only the unified profile is required, with
  no proxy image, network, or container required; ordinary outbound access and
  host publishing on the selected bind remain functional.
- Profile checks cover automatic default creation, repository-template parity,
  no overwrite under concurrent initialization, missing nondefault names,
  strict YAML, path expansion, port persistence/conflicts, and removal of implicit
  legacy `.env`/environment overrides.
- Unit/launcher checks cover strict YAML and matching rules, protected-address
  precedence, policy path protection, stale resource detection, fail-closed
  startup, and resource lifecycle without modifying unrelated resources.
- Real rootless Podman checks repeat the experiment with the actual proxy image:
  allowed/denied HTTP(S), changed or cleared proxy variables, direct IPv4/IPv6,
  direct DNS, host-side link-local service, host/LAN, and unrelated containers.
- Use controlled destinations to test private DNS answers/rebinding and the
  egress firewall; an allowed hostname resolving privately must still fail.
- Validate management HTTP, WebSocket upgrades and pairing over the published
  non-loopback host address, and independent sandboxes without cross-access.
- Kill/restart the proxy, recreate the bridge, change policy/mode, and inject
  invalid YAML; every failure must preserve the restriction and existing state.
- Change a whitelist entry and run `proxy-restart`: confirm the new decision,
  unchanged T3 container ID/start time and ongoing local job, stable proxy
  endpoint, and management reconnection. Invalid edits must leave the old policy
  active; failed restarts must leave T3 isolated. Confirm other profiles remain
  unaffected and T3 databases/home volumes are independent by default.
- Generate a known denial and verify `firewall-logs` stdout fields, correct
  classification, finite/follow modes, profile separation, restart persistence,
  rotation, and absence of sensitive data. Confirm allowed requests and upstream
  application 403 responses are not misclassified as policy denials.
- Verify browser/HTML rendering against local content with internet unavailable,
  including a fresh home and shared state, and explicit browser proxy routing.
- Verify Codex model traffic through the actual proxy without exposing auth in
  logs. Existing auth may be reused; if live credentials are unavailable, state
  that limit rather than calling an unauthenticated transport probe a full test.
- Claude policy and transport are predefined; an authenticated Claude session
  is optional validation because the user's active provider is Codex.

## Limits and non-goals

The host user controlling Podman and the launcher is trusted. Do not run
agent-modified host launcher/configuration code without reviewing it. This is
not protection from a compromised host, kernel/container-runtime escape, or a
compromised trusted proxy. No general VM-level security claim is made.

Destination allowlisting is not content filtering. Allowed services can receive
data; CONNECT does not restrict their HTTPS URL paths. The proxy's resolver is
trusted infrastructure. In-container local communication remains possible.
No arbitrary inbound development ports, SOCKS/UDP tunneling, automatic policy
expansion, generic internet browsing, VPN/Tailscale, or T3 Connect relay support
is promised by this change. Host/WSL/Windows firewalls can still affect external
reachability; binding `0.0.0.0` does not reconfigure those firewalls.

## Decisions left to the builder

Choose precise package versions, generated filenames, address allocation,
supervision details, minimal tests, and T3-version-specific browser provisioning.
Maintain the invariants above. If runtime compatibility requires materially
broader endpoints, host privileges, or a different boundary, stop and revise the
design with the user rather than weakening restricted mode.

## Sources and evidence

- [Podman network creation](https://docs.podman.io/en/latest/markdown/podman-network-create.1.html)
  describes internal bridge behavior; this repo's live experiment is the
  version-specific evidence for the unaddressed bridge plus IPv6 control.
- [Codex authentication](https://learn.chatgpt.com/docs/auth) documents device
  login and stored authentication.
- [Codex app-server authentication](https://learn.chatgpt.com/docs/app-server)
  includes the `auth.openai.com` device-code path.
- [ChatGPT gateway routing](https://learn.chatgpt.com/docs/enterprise/sign-in-with-chatgpt-through-a-gateway)
  identifies `chatgpt.com/backend-api/codex` for model requests.
- [Claude authentication](https://code.claude.com/docs/en/authentication),
  [proxy configuration](https://code.claude.com/docs/en/network-config), and
  [network data usage](https://code.claude.com/docs/en/data-usage) inform the
  initial Claude entries and HTTP proxy compatibility.
- [T3 remote access](https://github.com/pingdotgg/t3code/blob/main/docs/user/remote-access.md)
  describes direct pairing and first-use browser downloads. CLI help from the
  cached image corroborated the absence of a browser-install subcommand.

Endpoint and browser compatibility must be checked against the actual versions
selected at build time; floating `latest` versions can change these requirements.
