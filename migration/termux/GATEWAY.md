# M5/M6 local-only independent license API gateway

This is an unsigned, opt-in engineering candidate. It does not enable a
tunnel, change the existing mobile controller, replace the installed
authorization binary, modify the database, or grant access to any third
party network. The phone's physically tested M4 head remains 7e0b611.
No public deployment or client release is authorized.

## Isolation contract

A separate Go executable listens only on 127.0.0.1:18445 using TLS 1.2+.
The existing service remains at https://127.0.0.1:18443, and its diagnostics
and database remain on their existing loopback listeners. The gateway has
no database credentials, signing seed, admin session or filesystem export
interface. It forwards only POST to four exact paths:

- /api/v2/licenses/challenge
- /api/v2/licenses/activate
- /api/v2/licenses/validate
- /api/v2/licenses/renew

Everything else is denied locally, including V1, demo, login, dashboard,
purchase, backup, export, metrics, readiness, redirects, query strings,
encoded paths, noncanonical targets and other methods. The independent
origin is still authoritative for JSON fields, signatures, nonce, scope,
binding, expiry, revocation and rate limits. The gateway constructs a
fresh request to the fixed origin; it does not forward caller cookies,
Authorization, client IP, Forwarded or Cloudflare metadata. No arbitrary
destination, proxy environment, redirect following or TLS skip.
The origin Host is always the original loopback host, not the external
hostname. The gateway requires the exact configured external DNS Host.
Responses are limited to expected status codes and JSON, with only
selected request ID and retry headers; no cookies or Location.

Limits: 4096-byte request, 32768-byte reply, 8 simultaneous application
requests, 32 accepted TCP connections, bounded transport timeouts.
The existing server's source rate budget will see the local gateway as
one source. Do not widen it or trust caller-supplied client IP to improve
throughput. Per-client abuse controls, edge quotas, connection saturation
and sustained load still need review; concurrency is not a per-second
rate limit. A loopback listener is not isolation from a compromised
same-UID app or arbitrary local software.

## TLS and connector review

Separate gateway TLS key/certificate (IP SAN 127.0.0.1), explicitly
provisioned gateway trust, and the existing trusted backend certificate
are required. Do not copy the database or signing keys into a gateway
configuration. The candidate accepts configuration via CHEZHI_GATEWAY_HOST,
CHEZHI_GATEWAY_ORIGIN_CA, CHEZHI_GATEWAY_TLS_CERT, CHEZHI_GATEWAY_TLS_KEY.
No default hostname or trust roots. The existing backend certificate
expiry must be monitored separately. The gateway is not a boot service.

cloudflared.disabled.yml is an inert example with a reserved invalid
hostname, zero tunnel ID, nonexistent credential and CA paths; it is
never executed or installed. The intended topology has TLS on both
local hops, explicit CA trust and IP SAN matching, and an unmatched-host
404 fallback. No token, account or domain is needed for offline review.
See https://developers.cloudflare.com/tunnel/troubleshooting/https-origins/
and https://developers.cloudflare.com/tunnel/reference/origin-parameters/.
Do not configure a real tunnel, wildcard, quick tunnel or public DNS for
this candidate. Exact cloudflared version parsing and local origin
certificate validation on the actual phone remain field gates.

## Required test and review gates

CI exercises a real TLS loopback fixture, not the real mobile database.
Before any external access, independently verify:
- exact route matrix with raw HTTP path variations, absolute targets,
  malformed and oversize bodies, methods and spoofed headers;
- no denied request reaches the real origin; signed synthetic V2
  challenge/activation/validation/renewal through the gateway with
  independently provisioned trust; unchanged data and signing policy;
- wrong CA, expired or wrong-name certificates, origin outages,
  redirect and oversized response rejection, concurrency saturation;
- real Android ARM64 binary and loopback-only listener; both local TLS
  hops verified, offline ingress validation, graceful stop;
- external authorized network conditions, separate public hostname
  approval, edge abuse controls, TLS renewal and sustained resource
  testing. No campus authorization or client privilege changes.
- no public access to administration, database, diagnostics or backup,
  including through a malformed or alternate hostname.

Public connectivity, cloudflared service activation, external routing,
production trust and production release remain HOLD. The M4 24/72h
endurance window must not be reset solely to test this source branch.
