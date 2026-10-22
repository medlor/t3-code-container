These are unmodified seven-field `t3decision` records captured from Debian
bookworm Squid 5.7 inside an offline disposable Podman container on 2026-10-22.
The generated production logformat uses epoch milliseconds, Squid status,
Squid error ID, our transaction annotation, URL-escaped/bounded domain,
URL port, and URL-escaped/bounded method. It never emits a URL or header.

The characterization config changed the listener/client to loopback and exempted
only 127.0.0.1 from protected destinations to reach a local HTTP server returning
403. This exemption exists only in the disposable characterization; production
Squid/nft configurations were separately parsed and installed without it.

Requests, in captured order:

- CONNECT blocked.example:443, with a Proxy-Authorization header: policy denial.
- GET http://127.0.0.1/private/path?token=secret: real upstream 403, TCP_MISS.
- CONNECT blocked.example:25: forbidden port.
- CONNECT 192.168.1.1:443, explicitly in allowed_ips: protected address.
- CONNECT [::1]:443: Squid emits escaped brackets and an unlisted annotation
  when IPv6 is disabled. Gateway-aware normalization classifies the literal
  using the same protected-address policy, without resolving names.
- CONNECT [::ffff:192.168.1.1]:443: Squid canonicalizes the domain field to IPv4;
  protected address remains denied even though that IPv4 is in allowed_ips.

`NONE_NONE ERR_CLIENT_GONE` from the readiness connection was excluded from the
fixtures. The upstream and policy requests both returned HTTP403: only explicit
local denial status/error plus the policy annotation establishes a policy denial.
