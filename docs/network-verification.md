# Network verification

Run from a local Linux/WSL rootless Podman account with Netavark, subordinate
UID/GID mappings and the prerequisites in the README:

```bash
PATH=/usr/bin:/bin make test
PATH=/usr/bin:/bin T3_SANDBOX_INTEGRATION=1 make test-integration
bash -n scripts/sandbox.sh scripts/entrypoint.sh scripts/browser-launcher.sh
git diff --check
```

Local verification on 2026-10-23: **186 unit tests passed**; the real suite ran
**28 cases: 25 passed, 3 browser prerequisite skips**, in 347.920 seconds.
Shell syntax and whitespace checks passed. `shellcheck` was unavailable.
Every test-owned container/network was absent after cleanup; cached build images
were retained. Browser rendering and authenticated model validation remain
unavailable as detailed below.

Unit discovery excludes `tests/integration`. Real tests require the explicit
environment opt-in. They build through the production launcher and use random
`it-*` names, unused ephemeral host ports, actual UID/GID and temporary injected
host homes. Every selected provider/T3 directory contains fixture state only.
Cleanup checks the owned container/network names, removes only those resources,
then removes the exact newly allocated temporary root through `podman unshare`.
Build images/cache may remain. There is no global prune or real default-profile
container. Initialization of default YAML is tested without launching it.

## Observed boundaries

The network suite observes actual sockets, routes, process privilege state,
gateway nftables and Squid behavior. Cases cover direct IPv4/IPv6 and UDP/TCP DNS
with proxy settings cleared; proxy-only reachability; host/LAN/unrelated-profile
denial; protected IPv4/IPv6/mapped literals; proxy-UID socket attempts bypassing
application ACLs; supervisor wrong-port denial; fixed-relay non-forwarding;
wildcards excluding the apex; allowed public-IP CONNECT; and upstream HTTP 403
exclusion from policy-denial logs. Rotation and gateway restart retain denials.

A positive control starts a temporary HTTP listener in the rootless network
namespace and a disposable client on only the newly owned private bridge before
production hardening. The eventual denial assertion fails while bridge IPv6 is
reachable. The client is removed and production hardening then leaves the bridge
unaddressed with IPv6 disabled; T3 cannot reach the previously working service.
This never changes an existing host network or another container.

The deterministic DNS fixture is an explicit test-only seam: a UDP responder in
the owned gateway namespace, loopback UDP/53 input, and Squid-UID loopback DNS
output. Squid's resolver configuration is temporarily redirected to it. No
protected TCP/output guards are removed and no public recursive resolver is
provided. The same allowed hostname first receives a public answer and succeeds
at CONNECT, then receives a private answer after TTL/cache expiry. The fixture
records fresh queries. Production `proxy_restart` restores normal policy and
resolver settings, followed by normal readiness/HTTPS checks.

Restart assertions compare T3's exact container ID/start timestamp, observe a
progressing local job, and reconnect authenticated management WebSockets.
Crash tests kill only the gateway, verify T3 remains running and isolated, then
recover through the production restart API. Structural edits must be rejected
before either process stops. Runtime tests cover persistent private markers
through image build/recreate/remove, independent sharing flags using fake host
directories, unchanged host browser cache, unrestricted operation without proxy
resources, invalid-YAML recovery, same-profile concurrency and two simultaneous
restricted profiles with distinct state, ports and networks.
One profile's proxy is restarted while the other remains active. Rootless
bridge addresses already denied by fixed protected ranges do not invalidate a
different profile's topology; additional public host-address changes still
require recreation before any gateway stop.

Host non-loopback HTTP and authenticated WebSocket handshakes use production
pairing/session commands with disposable credentials that are never printed.
This verifies the host path only; no second physical device or Windows firewall
configuration is implied.

## Runtime and support limits

Verified platform: Linux x86-64 under WSL, rootless Podman 4.9.3, Netavark 1.4.0,
Squid 5.7 and nftables 1.0.6. The production cached image contains T3 v0.1.1,
Codex 0.163.0, Node v24.22.1, Bun 1.4.4 and Chrome 154.0.8037.92. Versions are
observations, not compatibility promises for all subsequent releases.

External operational topology and DNS are IPv4-only. IPv6/mixed operational
settings fail validation; direct/host/private/mapped IPv6 protection remains
tested. No broader NDP/ICMP exception is installed.

Browser cases invoke the image's installed wrapper and immutable assets with
production caps, NNP, seccomp and browser sandbox settings. A missing host
browser sandbox prerequisite must remain visible; tests never add
`--no-sandbox`. Local T3 preview RPC and browser HTTPS checks are distinct from
offline browser installation/version checks.

On this baseline, rendering and browser HTTPS/preview are **not verified**.
Chrome exits with signal 5 and
`zygote_host_impl_linux.cc:237: Zygote process exited prematurely with exit code -1`.
An isolated trace under production UID 1000, zero capabilities, NNP=1 and
seccomp mode 2 shows the zygote's `chroot("/proc/self/fdinfo/")` returning EPERM.
Nested user/network/PID namespaces themselves succeed. The installed Podman
default seccomp profile allows `chroot` only with `CAP_SYS_CHROOT`, which this
sandbox deliberately drops. The browser cases report a prerequisite skip only
when the observed zygote failure is accompanied by a same-runtime nested
`chroot / /usr/bin/true` EPERM. No capability, syscall-profile or browser-sandbox
relaxation was made. Resolving this requires a separately reviewed runtime
policy decision; installation/version checks do not establish rendering success.

No real provider credentials are mounted. Provider TLS/HTTP transport and Node
proxy transport are checked against an expected unauthenticated response.
Authenticated Codex model requests and provider streaming/WebSocket validation
remain pending explicit disposable credentials; Claude authentication is also
unverified. Management WebSocket verification does not establish provider model
streaming. Other CPU architectures and external physical-device LAN access are
unverified.

Destination grants allow data transfer; HTTPS is tunneled without TLS
interception. Host, kernel, Podman and trusted gateway remain trusted. Direct
attempts failing before the proxy do not appear in its policy-denial logs.
