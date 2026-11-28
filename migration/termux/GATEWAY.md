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

Limits: 4096-byte request, 32768-byte reply, 2 simultaneous application
requests, 32 accepted TCP connections, bounded transport timeouts.
A process-local shared token bucket admits an initial burst of 12 and
refills 48 tokens per minute. Every attempted upstream request consumes
one token, including unsuccessful upstream attempts. Budget exhaustion
returns 429 with Retry-After; concurrent saturation returns 503. The
origin's default source quota is 60/minute and public concurrency is 3;
these conservative gateway defaults leave headroom but cannot reserve
origin capacity from other local callers. A gateway restart resets its
local bucket, not the authoritative origin quota. This is not a
per-client limiter, a persistent quota or a measured throughput promise.
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

## Reliability follow-up (separate candidate)

The last physically accepted gateway is head 99f418d, artifact 15252152019.
The new reliability branch does not replace that candidate or the M4
controller. Validate the new binary and tests before any local trial.

With the same four reviewed CHEZHI_GATEWAY_* environment variables, the
new binary supports a read-only tls-status command. It loads the local
certificate/key pair and checks current validity and loopback IP SAN,
then performs a real certificate-verified TLS handshake to the fixed
backend. It reports the gateway leaf and earliest verified origin-chain
expiration in UTC, exits nonzero for failed trust or expiry within seven
days, and does not open a gateway listener or send an HTTP request.
A successful check does not prove database readiness or public edge
certificate validity. No automatic certificate replacement, key
distribution, origin restart or boot hook is implemented.

Rotation policy: stage separate fresh TLS credentials in a private
directory and independently verify the new IP SAN, validity and trust
before an approved maintenance window. Keep old known-good credentials
protected for rollback; review all consumers of the origin certificate
including the controller health/backup probes. Coordinate trust updates
and the actual server restart; do not edit live TLS files or bypass
validation during M4 endurance. After maintenance, independently verify
readiness, both TLS hops, backups and synthetic signed V2 requests.
Public edge trust/expiry and authenticated per-client edge limits are
separate release gates. Never use arbitrary client-provided forwarding
headers as source identity.

The automated tests exercise deterministic token accounting, concurrent
admission, a real two-hop TLS fixture with blocked origin handlers,
503/429 refusal and recovery, and read-only certificate status. These
are bounded fixtures, not a sustained phone capacity benchmark. No
tunnel launch, public access, or third-party network change.

### Paced reliability evidence

The first reliability CI (46118826007, head 1d5fe8c, merge checkout
1795883) completed 12/13 jobs successfully. Gateway race tests, real V2
integration, certificate warnings and Android packaging passed. The
dashboard comparison stopped in the historical baseline's mixed
issuance phase; the proposed dashboard comparison was not reached.
Do not waive or weaken the comparison gate because gateway tests passed.

The standalone acceptance now requires GATEWAY_PACED: a disposable
PostgreSQL fixture, actual compiled gateway, default origin source
quota of 60/minute, 24 signed renewals (48 HTTPS requests) paced over at
least 75 seconds, no retry and no quota reset during the window. The
test requires unique nonces, unchanged binding/card snapshots, matching
revision and expiry, and independent signature verification. Reported
P95 combines challenge/sign preparation and renewal request samples;
it is not pure transport latency or maximum throughput. Separate real
TCP listener tests cover slot exhaustion, double close, release and
shutdown while admission is blocked. The test cannot establish a
production concurrency limit or sustained phone/Cloudflare capacity.

### Local observability

CI 46119073427 (head ac8a6f2, checkout 97752f6) actually passed the
paced test: 24/24 signed renewals, 48/48 requests, 77.46 seconds,
sample P95 15.92 ms, zero retry/error, unique nonces and stable card
and binding snapshots. The real TCP listener resource test also passed.
The historical baseline again failed mixed issuance (12/13 overall).
The next workflow collects both profiles even when one fails, preserves
both exit statuses and still fails the job if either fails.

The new gateway emits fixed-cardinality cumulative HTTP counters once
per minute, plus a final report after graceful shutdown. "success"
means HTTP 200, not independently verified authorization. Counts
reset on process restart and concurrent reports are not atomic snapshots.
It does not log request bodies, IPs, paths, credentials or headers.
TLS trust and expiry are checked at startup and every 15 minutes
without HTTP requests; warnings are local logs only. The current
configuration still needs an operator-reviewed bounded log collector
and notification delivery; no public diagnostics endpoint, no automatic
restart/rotation, and no phone boot integration are introduced.

### Independent local gateway lifecycle (new candidate)

CI 46120200624 (head f7c35be, checkout 1af0426) passed metrics
redaction/counting and paced renewals (24/24, 48/48 requests, 77.50s,
sample P95 16.34ms, no retries/errors). Dashboard comparison remains
failed: baseline mixed issuance failed, candidate completed with
18/320 mixed-read 503s, 11 issuance 503s before success, 500ms MISS.

The new artifact includes gateway-service.sh. This is an explicitly
opt-in foreground runit controller for the reserved local test hostname
only. It creates ~/.chezhi-gateway-local-v1, separate from M4. Install
requires a verified artifact and an absent controller directory. It
never installs into global Termux services or Termux:Boot. Verify the
artifact ZIP SHA256 and every manifest entry independently before
running the script; the local code hashes only detect subsequent
unexpected changes, not a compromised same-UID operator.

Commands: install, start (foreground), status, stop. The run subcommand
is internal. After install, independently provision a separate private
test TLS cert and key with IP SAN 127.0.0.1, mode 0600, in credentials
as tls-cert and tls-key; no automatic credential creation. The original
M4 tls-cert is read only. Start requires valid private directories,
code integrity and a valid local self-signed test certificate. It
sanitizes the child environment, fixes the Host to license.example.invalid
and lets runit restart a terminated gateway with a ten-second finish
delay. Stop uses only this service's runit control, not process-name
search or arbitrary signals. Use stop from another terminal rather
than killing the foreground controller. If status/control is ambiguous,
stop the trial and inspect rather than adopting an unknown process.
svlogd limits rotation to five archived logs plus the current log
(approximately 1 MiB per file; not a hard filesystem quota).
The CI fixture uses real runit/svlogd with a synthetic child and scaled
rotation thresholds, not the physical Android runtime. The separate
real V2 acceptance still uses the compiled gateway. Do not install or
start the candidate on the phone if it would interrupt M4 endurance.

No gateway watchdog, boot integration, external tunnel supervisor,
PostgreSQL log rotation, external notification or public routing is
implemented by this controller. Those require separate review.

### PostgreSQL and origin TLS maintenance preflight

CI 46120606866 (head 360d6dc, checkout 5689c29) completed 13/13.
The real runit fixture passed restart, rotation, duplicate denial,
controlled stop, M4 preservation and tamper refusal. The signed paced
fixture passed 24/24 renewals in 77.37s (sample P95 11.92ms).
The candidate dashboard 500ms target passed in that run, but 14/320
mixed reads returned 503 and issuance returned fifteen 503s before
success. Do not treat one green comparison as sustained capacity.

maintenance-preflight.sh is read-only and targets the existing
Termux private staging directory. It checks protected file modes,
origin TLS certificate/key correspondence, IP SAN and validity,
trusted readiness, selected PostgreSQL settings using read-only
session defaults, legacy log size and free space. It prints no
private key, DSN, SQL text from traffic or log contents. A seven-day
expiry warning does not replace an operator maintenance decision.
It does not install a controller, rotate certificates, change
database configuration or restart any service.

postgres-logging.candidate.conf is an unapplied native PG18 collector
profile with time/size rotation, UTC timestamped file names, 0600
log files and conservative statement/parameter logging settings.
PostgreSQL documentation:
https://www.postgresql.org/docs/18/runtime-config-logging.html
https://www.postgresql.org/docs/18/logfile-maintenance.html
Rotation is not a hard size cap or retention policy; log messages may
still contain sensitive context, and old files can accumulate.
No automatic deletion is introduced. The separate CI fixture applies
the exact profile in a disposable network-isolated PG18 container,
restarts that fixture only, verifies current settings and an explicit
native rotation with unchanged postmaster start time. Natural
time/size rotation and retention require additional tests.

Do not apply this profile to M4 during endurance. After the endurance
gate and explicit maintenance approval: inventory settings, preserve
configuration and legacy logs, verify a recoverable backup, review
conflicting overrides, stage the profile, stop managed gateway/app
before a controlled database restart, verify actual settings and
readiness, record new log path and modes, then run isolated signed
business checks and backup verification. If any check fails, restore
the reviewed previous configuration and perform controlled rollback.
Do not truncate open legacy logs or restart an unidentified cluster.
The TLS renewal itself remains a separate coordinated operation;
no automatic certificate replacement or production change is included.

### Encrypted off-device recovery candidate

CI 46121882904 (head 296d5f8, checkout 7eb1164) passed all 13 jobs,
including actual isolated PG18 collector rotation with unchanged
postmaster. The candidate repeated dashboard target passed, but mixed
reads returned 13/320 HTTP 503 and the standalone target missed.

The new encrypted-export.sh operates only on an existing verified
managed daily logical archive. It acquires the daily backup lock,
validates the exact manifest and marker, lists and fully decodes the
archive, checks available storage, encrypts to a reviewed native age
public recipient, rechecks the source checksum, and publishes a
ciphertext-only export directory under ~/.chezhi-encrypted-exports.
No network transfer, database write, key generation or retention
deletion is performed. Failed encrypted partials remain for inspection.
The age recipient must be independently verified with the receiver;
never place its private decryption identity on the phone.

The receiver-side encrypted-receive.sh requires age, compatible
pg_restore and a private identity file. Use encrypted receiver storage
and a fresh private output directory. It checks the ciphertext
manifest, authenticates decryption, fully decodes the archive and
publishes the recovered logical dump only after verification. On
failure it unlinks its temporary plaintext; unlinking is not guaranteed
secure erasure. It never connects to or restores a database.
The receiver must verify the ciphertext digest from an independently
authenticated channel: age recipient encryption does not authenticate
the sender, and a manifest alone is not a signature.

The isolated PG18 CI test exercises a real synthetic database dump,
age encryption, wrong identity rejection, tampering even with a
rewritten checksum, duplicate destination refusal and a real restore
to a separate disposable database with matching rows. The fixture
does not include production data or test a full licensing disaster
recovery. Logical dumps omit signing private keys, role credentials,
TLS private keys and operational configuration. A complete recovery
plan needs separately protected recovery materials or an approved
signing rotation, reviewed grants, deployment-scope recovery, and
independent signed-client checks. No cloud storage, automatic transfer,
backup schedule or remote identity provisioning is authorized.
Retain the original M4 daily backup, existing key material and phone
endurance unchanged. Actual off-device storage and recovery still
require explicit operator approval and physical verification.
