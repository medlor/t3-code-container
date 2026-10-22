# Rootless Podman network-isolation experiment

Status: throwaway experiment completed; no production implementation.

## Purpose

Check the proposed separate-network-namespace design: T3 connects only to an
isolated private network; a separate gateway connects to that network and an
external network, provides an allowlist proxy, and relays incoming management
connections. Enforcement must not depend on T3 retaining proxy environment
variables or on a firewall editable from inside T3.

## Environment and scope

- Podman 4.9.3, rootless, Netavark backend on the current Linux/WSL host.
- Cached `localhost/t3-code-sandbox:1000` image; no image downloads or builds.
- Unique disposable networks and containers with an experiment-specific label.
- T3 test process: host-matching non-root UID/GID, `--userns=keep-id`, all
  capabilities dropped, `no-new-privileges`.
- Private network: bridge, `--internal`, `--disable-dns`, IPv4 IPAM.
- Separate external network and unrelated container for negative probes.
- Gateway: separate network namespace, both networks attached, IPv4 forwarding
  explicitly disabled, Python TCP relay and minimal HTTPS CONNECT proxy.
- CONNECT allowlist for the experiment: `example.com:443`, `api.openai.com:443`.
  The only positively tested external destination was `example.com`.
- Management relay published on `0.0.0.0` with a temporary random host port.
- A temporary HTTP service in Podman's rootless host-side network namespace
  tested whether T3 could reach services outside its two containers.

## Findings

The private bridge had no IPv4 address or configured IPv4 gateway. T3 had only
its directly connected subnet route and could not add a default route.

However, IPv6 link-local addresses existed despite network inspection reporting
`ipv6_enabled: false`. T3 successfully reached the host-side test HTTP service
using the private bridge's IPv6 link-local address and T3's interface scope.
An internal network alone therefore did not satisfy the requested boundary.

The experiment disabled IPv6 on only its own host-side private bridge using:

```text
podman unshare --rootless-netns sysctl -w net.ipv6.conf.<private-bridge>.disable_ipv6=1
```

The bridge then had no IPv4 or IPv6 addresses. Retrying the previously working
host-side IPv6 URL timed out. This control is outside T3's namespace. It must
be applied and verified before any untrusted T3 workload starts, and reapplied
whenever that bridge is recreated. Nothing changed on existing networks.

After bridge hardening:

- HTTPS through the allowlist proxy to `example.com` returned HTTP 200 after
  successful CONNECT and TLS verification.
- An unlisted domain and an unlisted IP literal received CONNECT 403.
- Direct IPv4 internet and global IPv6 internet connections failed with proxy
  use explicitly bypassed in the client.
- Direct connections to an unrelated container, the rootless external-network
  gateway, and the host's LAN-facing management address failed.
- Public DNS lookup from T3 failed.
- Incoming management HTTP worked through the gateway relay, both through host
  loopback and the host's non-loopback address. Published binding was `0.0.0.0`.
- Gateway IPv4 packet forwarding was confirmed disabled.
- Stopping the gateway left both direct internet and proxy access unavailable.

## Implications for the design

Use separate namespaces, an internal network without host-side IP addresses,
explicit host-side bridge IPv6 suppression, disabled gateway forwarding, and
host-published management forwarding through the gateway. Inspect and enforce
these properties before starting T3; refuse restricted-mode startup if any
required control cannot be installed or verified. There must be no fallback to
unrestricted networking on failure.

## Limits

This validates selected connection paths on this host and Podman version, not
every Podman version or immunity to kernel/container-runtime vulnerabilities.
The test proxy is disposable and is not a production policy implementation.
DNS rebinding, HTTP parsing, resource limits, IPv4-mapped addresses, and complete
Codex/T3/browser compatibility still need production design and validation.
There was no inbound test from a second physical machine; a connection through
the host's non-loopback address succeeded, but WSL/Windows/LAN firewall behavior
remains deployment-specific.

The experiment's temporary containers, networks, and host-side helper were
removed. Label-filtered container and network listings were empty afterward.
Scripts and raw results remain under `/tmp/t3-network-spike/` for this session.
