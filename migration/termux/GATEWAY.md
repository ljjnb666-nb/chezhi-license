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
pg_restore and a private identity file.
The receiver now requires a fourth argument: the lowercase SHA256 of
ciphertext obtained independently through an authenticated channel.
It rejects a differing manifest, hashes a private copy before decryption,
and budgets space for both ciphertext and plaintext. The digest is not
trusted merely because it is included in the transferred directory. Use encrypted receiver storage
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

### Certificate transition rehearsal and receiver trust gate

CI 46122663338 (head 721a0c6, checkout 1b4655f) passed 13/13,
including actual age + PG18 fixture restore. Paced signed renewals
passed 24/24, 48 requests in 77.40s, sample P95 12.37ms, zero errors
and retries. Dashboard candidate repeated target passed but mixed
reads returned 14/320 HTTP 503, with fourteen issuance 503s before
success. Sustained capacity is still unresolved.

The strengthened receiver requires the trusted ciphertext SHA256 as
argument four. The tests additionally reject missing trust input,
valid replacement ciphertext encrypted to the same recipient, and
a damaged stream even when its digest is deliberately supplied.
This does not establish sender authenticity unless the operator
actually authenticates the expected digest out of band.

stage-loopback-tls.sh creates a new private candidate directory only,
with a fresh 30-day RSA certificate/key, loopback IP SAN, serverAuth,
0600 modes and independent OpenSSL verification. It refuses existing
destinations and prints only public fingerprint and expiry.
The real loopback TLS fixture exercises old trust, new trust,
cross-trust rejection and restoration of old trust, preserving the
old files. This is a synthetic transition rehearsal, not a rotation
of the physical M4 certificate or a deployment mechanism. No changes
to live origin/gateway configuration, trust distribution, certificate
replacement, restart or recovery key export are performed. A real
rotation requires an approved maintenance window after endurance,
coordination of all existing trust consumers, verified recovery and
a rollback plan. No real secrets should be included in CI artifacts.

### Release integrity and local alert transitions

CI 46124210801 (head 644f917, checkout 767df42) passed 12/13 jobs.
The independent TLS transition/rollback fixture and strengthened age
restore test passed. Paced renewal: 24/24, 48 requests in 77.38s,
sample P95 12.20ms, zero retry/error. Historical baseline mixed
issuance failed; candidate repeated 500ms target passed, with
17/320 mixed-read 503s and eight issuance 503s before success.
Keep the capacity problem open.

Gateway alerts use the existing minute sampling loop. Two consecutive
samples with at least three new 5xx responses or ten new 429 responses
open one alert for that category. Two consecutive samples with no
new events emit QUIET, which means only that the counters were quiet;
it does not prove service recovery. A lower nonzero count does not
clear an alert. No repeated notification while open, no request
contents or caller identifiers, no auto-restart, and no outbound
notification. State is in memory and resets at process restart.
These thresholds are provisional, not a production SLO.

The unsigned gateway artifact now includes the maintenance preflight,
PG logging profile, encrypted export and receive tools and candidate
TLS staging tool. All eleven payload files are covered by SHA256SUMS.
The trusted verifier is migration/termux/verify-maintenance-zip.py
from independently reviewed source, not an executable obtained from
the package being verified. It requires the actual downloaded ZIP
SHA256 from trusted GitHub artifact metadata and the actual CI checkout
SHA (not merely PR head). It reads at most 64 MiB compressed and
permits at most 64 MiB declared uncompressed content, exact flat
allowlist and manifest, rejects duplicate entries, special file types,
encrypted ZIP entries, wrong source and unsigned notice mismatch.
CI verifies a locally assembled ZIP and negative fixtures, not the
server-generated download ZIP. Verify the real downloaded artifact
before extraction. Verification does not grant release approval,
authenticate a compromised build system, install files, or execute
anything.

Keep old known-good phone artifact and private controller directories
for rollback. Before a later approved maintenance activation, verify
both candidate and rollback digests, confirm backup recovery, stop
only the relevant controlled service, stage in a fresh directory,
test locally with explicit trust and restore previous reviewed version
if checks fail. No automatic activation/rollback, remote notification,
per-client edge rate control or public connector configuration is
implemented. No real phone modification during M4 endurance.

### Administrative admission isolation

CI 46125207179 (head 8d47e78, checkout 9504eab) passed 13/13,
including alert transitions and 12-entry local maintenance ZIP
verification. Paced renewal: 24/24, 48 requests in 77.60s, P95
17.23ms. The repeated dashboard candidate passed but standalone
single-trial target missed and 19/320 mixed reads returned 503.

Source audit identified a concrete starvation mechanism: each server
instance has eight shared administrative admission slots and the
mixed benchmark runs eight reading workers per instance. A concurrent
issuance request can repeatedly encounter a full shared queue.
This is a plausible contributor, not proof of the cause of every 503.
The candidate preserves eight admin read slots and adds a separate
one-slot admin POST admission path. This increases the maximum admin
in-flight count from eight to nine; the 12-connection database pool,
public admission, export admission, authorization, CSRF and transaction
boundaries remain unchanged. The POST slot is not reserved for a
specific authenticated account and is not a public per-client quota.
The extra contention and memory cost require measurement.

Loopback-only diagnostics expose fixed-cardinality admission rejection
counters by admin_read, admin_write, public and export. The benchmark
records differences per instance for the mixed phase, including failure;
historical binaries lacking those counters are identified as unavailable.
Other causes of 503 (database errors, drain, application data failures)
are not counted as admission rejection. Keep existing performance
workloads and acceptance limits unchanged. A real before/after result
and renewed phone capacity review are required before activation.
No change to the frozen M4/M6 versions or physical phone.

### Narrow issuance admission follow-up

CI 46126052417 (head d06f9e9, checkout 6c15ac2) produced actual
mixed-load improvement: at 10k and 100k cards, each 320/320 reads
succeeded, issuance succeeded on the first attempt, and all four
admission rejection deltas were zero on both instances. Historical
100k profile had 14/320 read 503s and two issuance 503s before success.
No DB pool waits were observed in the candidate snapshots. However,
100k overview/order repeated P95 was 657.7/677.4ms, still above 500ms.
This single profile is not proof of sustained capacity.

The standalone job failed the six-way sensitive credential limit gate:
actual two 200 and four 503 rather than expected two 200 and four 429.
The generic one-slot POST lane starved the requests before their
account quota checks. The replacement reserves one slot only for
POST /?view=issue with exact raw query. All other administrative
requests retain the original shared eight slots. This is a routing
hint, never an authenticated role or proof of form action. Diagnostics
now label the two categories admin_shared and admin_issue, with public
and export unchanged. The original security test's exact expected
status counts and persistent account quota assertions remain intact.
New tests cover account/password, login, other POSTs and ambiguous
issuance query falling into the shared lane. Re-run both standalone
and repeated dashboard gates on the revised candidate; do not
attribute the earlier zero-503 result to this untested revision.
No activation, merge, or phone operation.

### Dashboard SQL follow-up

CI 46126700580 (head ccc5218, checkout 6975c44) passed 13/13.
The original exact concurrent account quota assertions passed again.
At both 10k and 100k cards the mixed profile had 320/320 successful
reads, first-attempt issuance, and zero admission rejection deltas.
The single-trial 500ms target passed, but repeated overview/order
P95 was 688.9/658.7ms; the comparison job is not a sustained SLO gate.
Representative EXPLAIN ANALYZE logged optimized overview-status
33.02ms, overview-sales 45.51ms, filtered order page 30.29ms with
26830 shared buffer hits. These are single query samples, not HTTP
latency, nor proof of the sole remaining bottleneck.

The new SQL-only candidate uses fixed numeric status counts instead
of grouping localized strings, preserving revoked/expiry/activation
precedence and NULL expiry for perpetual cards. The default order
page groups narrow ref/max(position) keys before joining only the
selected orders and counting page details. It preserves exact order
position semantics, pagination, exclusion of empty orders and the
existing filtered path. The count and page still use the same
repeatable-read transaction. No migration, cache, approximate count,
pool change, or altered access control. Added parity coverage for
perpetual active cards, empty orders and filtered/unfiltered pages,
and plan capture for the new default order path and its prior form.
Actual performance benefit is not established until CI runs.
No phone or public service activation.

### Single-scan overview candidate

CI 46127551010 (head 0c85ba9, checkout 548ea97) passed 13/13.
At 10k and 100k cards mixed reads were 320/320 each, first-attempt
issuance and zero admission rejection deltas. The 100k repeated
overview/order P95 was 604.8/590.3ms, single-trial target also missed.
The default order plan showed 33.72ms and 2746 shared buffer hits
versus 45.60ms and 39274 hits for its prior form in the same fixture.
Keep the default order improvement; the filtered path stays unchanged.
These samples are not a sustained production capacity guarantee.

The new overview candidate groups exact card state counts and order
quantities together, then joins orders and produces lifetime totals
and seven-day trend in a single SQL statement. No cache, schema
migration, approximate count, or additional connection pool. Card
status counts include test orders; paid amounts/order counts exclude
them. Orders outside the window contribute to lifetime totals but
not the trend. The grouping indicator distinguishes lifetime totals
from NULL day buckets. Foreign keys guarantee card/order association;
the transaction remains read-only repeatable-read. Added empty,
test-only and out-of-window parity checks, plus combined query plan
and default order count plan capture. The previous separate status
and sales plan samples remain for comparison. Wider hash aggregate
state can increase memory or spill; inspect temp blocks, HTTP P95,
resource use and actual parity before retaining this candidate.
No changes to the frozen physical-device versions.

### Strict repeat capacity gate

CI 46128035873 (head c64ec94, checkout b726ff3) passed 13/13.
The combined overview empty/test-only parity passed on actual PG18.
The 100k repeated overview/cards/orders/devices/audit P95 medians
were 418.4/81.9/366.4/76.2/65.4ms, all passing, and the standalone
single-trial target also passed. Mixed 10k and 100k reads were
320/320 each, first-attempt issuance and zero admission rejects.
The combined overview plan used 2713 shared hits and zero temp
writes in 51.91ms; separate status/sales samples were 18.01/31.65ms
and 2619/2713 hits. Reduced logical reads and a round trip do not
prove an isolated execution speedup. Keep the current SQL as a
candidate without further speculative tuning.

The comparison workflow now requires two independently initialized
candidate profiles (same runner, separate disposable databases and
processes, identical original 16-reader workloads). Each profile
must pass all repeated 500ms median-trial P95 targets at both data
sizes, exactly 320/320 mixed reads and one first-attempt successful
issuance per size, two instances with all four admission counters
present and unchanged across the mixed phase. Successful activation
remains required by the original fixture. Both profile exit statuses
and explicit CAPACITY_GATE PASS markers are required; the second
runs even if the first fails, and baseline failure still fails the
job. Preserve separate text logs and plan JSON, including the
repeat directory. This is a strengthened synthetic regression gate,
not sustained physical-device or Cloudflare capacity acceptance.
No additional SQL, application admission, quota or phone changes.

### Strict capacity failure and shared order keys

CI 46129021921 (head 34d57e7, checkout c8b33c7) passed 12/13.
Both independently initialized strict profiles failed solely the
repeated latency target: 100k overview/order P95 581.7/553.6ms
and 580.1/509.4ms. All four mixed phases passed (1280/1280
reads, four first-attempt issues and activations, zero admission
reject increments). Standalone single-trial target passed. The
strict gate must remain unchanged. Combined overview plans took
63.76/64.05ms with no temp writes. Default order count and page
separately took 32.14/30.45ms and 32.00/30.58ms.

The new default order SQL materializes the exact ref/max(position)
keys once and shares them between count and clamped page selection.
The foreign key guarantees matching orders; details are computed
only for the selected page. A sentinel represents zero orders.
No schema migration, caching or approximate count; filtered orders
retain the old implementation. Tests cover empty and 23-order
fixtures, navigation links, invalid/overflowing page input and
last-page clamping, plus exclusion of an empty order. Overview
aggregation removes redundant predicates using the existing
constraint that unactivated cards have NULL expiry and derives
active as the exact complement of four disjoint status buckets.
The existing projection parity tests remain authoritative. Added
actual-query EXPLAIN capture alongside the previous separate
order count/page samples. Materialization and aggregation may have
memory or spill costs; new CI results are required before claiming
a gain. No deployment, merge, external access or phone changes.

### V2 controller lifecycle follow-up (separate candidate)

The capacity-passing PR #10 head cf9324c remains frozen. This separate
follow-up introduces a fresh ~/.chezhi-gateway-local-v2 controller;
it does not migrate, edit or delete the V1 tree. Since both bind the
same loopback port, any V1 tree blocks V2 start until an explicitly
reviewed maintenance procedure archives it. Do not perform that
procedure during device endurance.

Foreground runsv is exec'd directly with the controller lease on
FD 9, removing the intermediary flock parent. Generated run, finish
and log scripts close FD 9. The gateway service acquires an independent
FD 8 lifetime lease before exec. Start/stop decisions serialize with
an operation lease; stop waits up to ten iterations for the native
supervise FIFO then uses bounded sv exit and verifies controller and
service leases are released. Unexpected held service lease without a
controller is a HOLD, not a successful stop. No PID discovery, arbitrary
kill, automatic orphan removal, restart of M4 or network exposure.
The service lease is a cooperative same-UID guard, not a security
boundary. No promise of recovery after SIGKILL of runsv itself, which
can also leave an orphan log process. The existing controller package
trust and manual deployment restrictions remain.

The isolated Linux runit fixture now checks the actual foreground
PID, controller/service lease lifetime, simulated held orphan service
lease refusal, legacy tree refusal, duplicate stop serialization,
stop during startup and no-controller direct run rejection, in addition
to the existing restart/log rotation and integrity tests. The synthetic
service is a sleep process; actual Android binary FD inheritance and
Termux runit behavior require separate device validation. The new
branch is not a deployment or a replacement for the frozen artifact.

### Read-only PostgreSQL log retention advisory

postgres-log-retention.py is included in the V2 maintenance package
(13 entries, twelve payloads plus manifest). It requires Python 3
on the device and exact private Termux ARM64 staging home. It reports
legacy and native collector logical byte counts, free bytes, advisory
128 MiB log budget and 1 GiB free-space warning, and counts/bytes of
files beyond the newest seven with at least seven days of mtime age.
The exact current stderr pointer is excluded even if old. A pointer
change, absent pointer with existing collector directory, unexpected
filename/type/mode/owner, hard link, future mtime or more than 10000
entries produces HOLD. The legacy pg_ctl log is never eligible.
No log contents or arbitrary filenames are printed. No files are
deleted, truncated, moved or modified; no SQL, service restart or
scheduled cleanup. The snapshot is advisory and can race concurrent
writes/rotation; retry HOLD, never treat it as authorization to delete.
A hard disk ceiling and safe archival/deletion remain outstanding,
requiring reviewed maintenance and collector/controller coordination.
The thresholds are provisional defaults, not measured phone capacity.
CI tests the inventory on synthetic private fixtures and retains the
separate real PG18 native rotation test. Frozen PR #10 package remains
12 entries and must use its original verifier.
The stacked PR workflow now covers its actual base branch and the
dedicated maintenance push branch, which previously matched neither
trigger. No production activation or phone change.

### V2 concurrent stop budget correction

CI 46131078774 (head f15a83e, checkout 15cd362) executed after the
stacked workflow trigger correction: 12/13 passed. Both strict
capacity profiles passed, as did PG18 native logging and encrypted
synthetic restore. The gateway runit fixture reached duplicate start
refusal and simulated orphan service refusal but failed concurrent
stop with "Controller operation busy." The original 10s operation
wait was shorter than a normal shutdown with the 10s finish delay.
The subsequent successful stop is not evidence that both callers
succeeded. Retention and ZIP verification steps were not reached.

Stop now allows a bounded 75s operation-lock wait for a previous
stop (up to 10s startup wait, 45s native exit, 10s controller release,
and two 5s child lease checks). Start retains its 10s operation wait.
The logger holds its own FD 6 lease; start and stop refuse a surviving
logger without a controller, and successful stop requires both child
leases to release. The fixture tests a synthetic surviving logger,
actual svlogd lease ownership, both concurrent stop exit codes and
all three post-stop lease releases. Test timeout is 180s. Read-only
log inventory now has a separate earlier CI step, so lifecycle
failure cannot hide that test. No PID scanning, automatic orphan
termination or active log deletion. The actual Android descriptor
inheritance and abrupt supervisor-death recovery remain unverified.
No performance or phone changes; PR #10 remains frozen.
