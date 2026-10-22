# Optional outbound proxy for the T3 sandbox

Status: proposed; awaiting user approval. Implementation must follow a separate plan.

## Intent and agreed requirements

Restrict every process in the T3 container to approved external destinations,
without relying on those processes to honor proxy settings. The user primarily
uses Codex and also wants a predefined Claude allowlist.

- Restricted mode is optional and defaults to off. Off uses ordinary outbound
  networking and creates or requires no proxy container.
- On uses a separate proxy container, with policy in a new YAML file.
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

Each sandbox in restricted mode owns one private bridge network, one external
network, one proxy container, and its T3 container. Names and ownership labels
include the host UID and sandbox name. T3 has only the private network; the proxy
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

## Policy and host configuration

Add `NETWORK_RESTRICTED=0`, `NETWORK_POLICY_FILE`, and `HOST_BIND_ADDRESS=0.0.0.0`
to launcher configuration. Off keeps normal networking; the requested externally
reachable management binding applies in both modes. Users can explicitly select
loopback with `HOST_BIND_ADDRESS=127.0.0.1`. `HOST_PORT` continues to select the
host port mapped to T3's 3773.

Ship a documented YAML template in the repository. Initialize the live policy
at `${HOME}/.config/t3-sandbox/<sandbox>/network.yaml` on the host, outside all
T3-visible writable mounts. Never overwrite an existing live policy. Validate
resolved paths and reject live policy paths inside the project or shared state
mounts. A read-only mount alone does not protect a source file that T3 can edit
through another mount.

Use a host-owned validated snapshot for a running proxy, outside T3's mounts;
mount it read-only into the proxy. Changes take effect with `make recreate`.
Do not reload a mutable workspace file. Track the policy digest and network mode
in resource labels; `make start` must refuse changed settings until recreation.

Proposed schema (the actual file is created during implementation):

```yaml
version: 1
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
forwarding, and policy digest before starting a stopped T3 container. Refuse to
reuse a running container with conflicting mode, binding, or policy settings.
Recreating a bridge invalidates earlier hardening; it must be applied again.

Stop T3 before the proxy. Remove only owned per-sandbox containers/networks and
generated snapshots, preserving home volumes, project files, and live policy.
Switch modes through explicit recreation; it must not leave an unexpected
gateway running. Existing unrestricted sandboxes require recreation to adopt
the new host binding or restricted mode. `config`, `status`, `doctor`, logs, and
smoke commands describe the active mode and its managed resources. Pairing keeps
the token and accepts an optional reachable advertised URL; `0.0.0.0` is a bind
address, not a destination to put in a pairing link. Default local pairing can
continue to advertise `127.0.0.1`; external users supply the host's LAN/DNS URL.

## Verification and acceptance

- Regression checks cover mode off: no proxy image, network, config, or container
  required, ordinary outbound access, and host publishing on the selected bind.
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
