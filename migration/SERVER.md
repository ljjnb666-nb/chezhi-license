# Standalone authorization server

## Modes and startup

| Mode | Transport | Persistence |
| --- | --- | --- |
| `local` or unset | Loopback HTTP, random port by default | JSON by default, PostgreSQL with `CHEZHI_STORAGE=postgres` |
| `server` | Direct HTTPS or the specified trusted HTTPS reverse proxy | PostgreSQL required |
| `test` | Loopback HTTP or direct HTTPS, without proxy forwarding | PostgreSQL required, legacy demo route available |

Server and test modes require a configured supervisor credential. Run
`db-init` and `db-check --migrator` using the migration account. Then select
the intended database mode while all services are stopped:
`db-set-mode <database-name> server` (or `test` for a dedicated fixture). If the
database has no owner, run `db-owner-init` with
`CHEZHI_OWNER_PASSWORD_FILE` pointing to a protected UTF-8 file. Use
14 or more characters and at most 128 UTF-8 bytes. The command refuses a
second initialization. Remove the one-time password file after setup and
change the password through the admin interface when appropriate. The
standalone service prints structured lifecycle events and no bootstrap
password. The local modes retain their existing bootstrap behavior.

Run `db-check --runtime` with the restricted credentials from
[migration/postgres_runtime_grants.sql](postgres_runtime_grants.sql).
Apply those grants again when upgrading an existing database to schema
version 4. These deep checks are part of deployment and recovery
acceptance. Startup checks the restricted grants and configured owner. Readiness checks
version, connection and the minimum resources needed to accept traffic.

## Configuration

| Variable | Purpose |
| --- | --- |
| `CHEZHI_MODE` | Selects local, server or test. |
| `CHEZHI_STORAGE` | JSON or PostgreSQL in local mode. Server/test accept only PostgreSQL. |
| `CHEZHI_LISTEN` | IP and port. Standalone defaults to 127.0.0.1:8080 and requires a nonzero port. Local defaults to 127.0.0.1:0 and refuses nonloopback IPs. |
| `CHEZHI_PUBLIC_ORIGIN` | Exact public scheme and authority, including a nondefault port. Required in standalone/test. |
| `CHEZHI_DATABASE_URL` or `CHEZHI_DATABASE_URL_FILE` | One source for the PostgreSQL connection string. Prefer the protected file for containers. Verify the PostgreSQL CA and hostname outside a disposable local network. |
| `CHEZHI_CSRF_KEY_FILE` | Protected file with 64 random hex digits, identical for instances of one deployment. Also keys the rate-limiter source digest. |
| `CHEZHI_TLS_CERT`, `CHEZHI_TLS_KEY` | Certificate and private key files. The cert must cover the public hostname and be within its validity period. Direct TLS requires TLS 1.2 or newer. |
| `CHEZHI_TRUSTED_PROXIES` | Comma-separated CIDRs for immediate peer addresses in proxy mode. Prefer exact host CIDRs. |
| `CHEZHI_DIAGNOSTICS` | Optional separate loopback IP and port for readiness, liveness and metrics. |
| Sensitive account limit | 5 password re-verification/rotation attempts per account and 12 across all accounts per minute. It is independent of source, session and instance. |
| `CHEZHI_LOGIN_PER_MINUTE` | Default 5 attempts per source, configurable 1 to 30, with a deployment limit of 60 per minute. |
| `CHEZHI_LICENSE_PER_MINUTE`, `CHEZHI_LICENSE_GLOBAL_PER_MINUTE` | License defaults are 60/source and 240/deployment per minute. Allowed maxima are 600 and 3000. |
| `CHEZHI_MAX_CONNECTIONS` | Maximum accepted application TCP connections per instance, default 128, range 16 to 1024. |

Keep configuration files outside Git and Docker build contexts and give
the service account only the file access it needs. Reconfigure instances
together when changing shared CSRF/rate settings. Connection DSNs, passwords,
card keys, and cookies are absent from application request logs.

Direct TLS ignores forwarded headers. In proxy mode the backend accepts
traffic only from a configured immediate peer. The proxy must overwrite
`X-Forwarded-For` with one observed source IP and
`X-Forwarded-Proto` with `https`; the original Host is preserved.
Forwarded Host is ignored. Put the backend on an isolated network and
restrict ingress to the proxy. [The Caddy example](../Caddyfile.example) binds a same-host TLS proxy to
loopback. The integration suite validates and runs the template using Caddy
2.11.4. Run `caddy validate --config <file> --adapter caddyfile` after
changing upstream, listener or certificate paths. Use the exact public Origin with browser form
mutations. The native API declines browser-origin requests and emits no
CORS permission headers. Standalone administrator cookies are Secure,
HttpOnly, host-only and SameSite=Strict.

## Windows PowerShell and Compose

Run from the project directory using Docker Desktop Linux containers and
PowerShell 7. Use a new protected folder outside Git. Give UID 65532 read
access to the mounted application inputs on Linux; restrict the host ACL
to the operator and the Docker service. The example provisions a disposable
local database. Use separately managed credentials for an operational system.

```powershell
$dir = Join-Path $env:LOCALAPPDATA ('CheZhi-server-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $dir | Out-Null
$env:CHEZHI_SERVER_SECRETS_DIR = $dir
$admin = [guid]::NewGuid().ToString('N')
$runtime = [guid]::NewGuid().ToString('N')
$supervisor = Read-Host 'Supervisor password (at least 14 characters)' -MaskInput
[IO.File]::WriteAllText((Join-Path $dir 'pg-password'), $admin)
[IO.File]::WriteAllText((Join-Path $dir 'owner-password'), $supervisor)
[IO.File]::WriteAllText((Join-Path $dir 'migration-url'), "postgres://chezhi_migrator:${admin}@postgres/chezhi?sslmode=disable")
[IO.File]::WriteAllText((Join-Path $dir 'runtime-url'), "postgres://chezhi_runtime:${runtime}@postgres/chezhi?sslmode=disable")
[IO.File]::WriteAllText((Join-Path $dir 'csrf-key'), [Convert]::ToHexString([Security.Cryptography.RandomNumberGenerator]::GetBytes(32)))
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -keyout "$dir/tls-key.pem" -out "$dir/tls-cert.pem" -subj '/CN=localhost' -addext 'subjectAltName=DNS:localhost'
docker compose -f compose.server.yml up -d --wait postgres
docker compose -f compose.server.yml --profile setup run --rm --build migrate db-init
"CREATE ROLE chezhi_runtime LOGIN PASSWORD '$runtime';" | docker compose -f compose.server.yml exec -T postgres psql -U chezhi_migrator -d chezhi -v ON_ERROR_STOP=1
Get-Content -Raw migration/postgres_runtime_grants.sql | docker compose -f compose.server.yml exec -T postgres psql -U chezhi_migrator -d chezhi -v ON_ERROR_STOP=1
docker compose -f compose.server.yml --profile setup run --rm migrate db-owner-init
docker compose -f compose.server.yml --profile setup run --rm migrate db-set-mode chezhi server
docker compose -f compose.server.yml --profile setup run --rm migrate db-check --migrator
docker compose -f compose.server.yml run --rm server db-check --runtime
docker compose -f compose.server.yml up -d --wait server
curl.exe --cacert "$dir/tls-cert.pem" https://localhost:8443/readyz
```

After preflight, remove the one-time owner password file from the protected
folder once it is no longer required by setup commands. The server does not
mount it. The Compose project exposes only the HTTPS port on host loopback,
keeps PostgreSQL on the private project network and runs the service as UID
65532 on a read-only root filesystem. Stop with
`docker compose -f compose.server.yml down`; this retains the project volume.
Keep the secure configuration folder and database volume together for a
future restart. A local CA trusted by your browser is needed for browser
access with the fixture certificate.

## Health, limits and recovery

`GET /healthz` reports process liveness. `GET /readyz` reports whether the
database and critical service tables are available. On the separate
diagnostics listener, `GET /metrics` additionally exposes cumulative
request counts, error counts, timing sums and connection-pool state.
Requests have a 12-second application deadline, 8 KiB maximum request
headers and 4 KiB native licensing bodies. Admin and public route groups
have independent in-flight capacity, and each instance allows only one
interactive export at a time. Oversized interactive exports (over 20,000
cards; business backup also caps audits at 100,000) use PostgreSQL
operational exports and backups instead.

PostgreSQL is the authoritative session and throttle backend. Sessions live
eight hours, with only a cookie digest stored in the database. Expiration,
single-session logout, all-session logout and account revocation are
enforced across instances. In-flight reads already authorized can finish;
admin writes recheck the account revision and session under the existing
transaction lock. Expired sessions and obsolete rate rows are reclaimed.
Client source rates use the remote connection or approved proxy input.
Rate windows are fixed one-minute UTC windows. Login and native licensing
use distinct per-source and deployment limits. Owner password update and
re-verification use a separate account and deployment budget before password
derivation. This budget follows the account across IPs, sessions and
instances. Admitted wrong passwords and successful changes are audited.
429 responses do not add another audit record. Shared-state errors fail closed. The service shuts down on signals, drains requests and stops cleanup
before the database pool closes.

## PostgreSQL deployment modes and offline recovery

CheZhi uses database-enforced mode isolation. Unifying local and standalone
sessions would tie the legacy bootstrap and browser compatibility path to the
HTTPS trust model. A durable mode and one PostgreSQL deployment lease per
process preserve both while preventing the local path from opening the same
database. The local PostgreSQL mode allows one process, server mode allows
multiple HTTPS instances, and loopback test mode has its own designation.
Local JSON is independent. The runtime login cannot change the designation.
Database operations fail closed when the lease or deployment generation is
lost. A reconnect reclaims only the same generation. Each instance reserves
one pool connection for this lease.

To upgrade from v3, stop every service using the database, including binaries
that predate leasing. Apply `db-init` as migrator and reapply runtime grants.
V4 clears old session and limiter rows and initializes the designation to
`local`. Opt back into server mode before starting standalone. All mode
changes are explicit. Stop every instance and use
`db-set-mode <connected-database-name> local|server|test` as migrator. The
command requires an exclusive lease, clears sessions and limits in the same
transaction, advances the generation, and records `runtime_mode_changed`.
A mode switch requires a fresh login. Retire old service binaries after
upgrading.

For recovery, keep every instance offline. Follow [the PostgreSQL runbook](POSTGRES.md)
and restore into a newly created database with a different name, using the
regular database-only dump without `--create`. Compare the restored business
records and audit with the source backup baseline. The application binds the
deployment to PostgreSQL cluster ID, database OID and name. A restore with a
different identity stays unavailable until the migration account runs:

```powershell
.\bin\chezhi-license.exe db-check --migrator
.\bin\chezhi-license.exe db-recover-security chezhi_restore
.\bin\chezhi-license.exe db-check --runtime
```

Use the restored DSN for each call and runtime credentials for the last call.
Recovery checks the explicit database name and the offline lease and refuses
an already-bound database. It deletes only sessions and rate buckets, reports
the committed counts, advances the generation, and appends a
`security_recovered` audit. Keep restored order, card, binding, expiry,
member credentials and prior audit records in place. Verify that an old
cookie is denied, a fresh login works and the intended licensing state is
intact before opening traffic. Reconcile password rotations, disablements
and other writes that happened after the backup. A physical rollback to
the original cluster and database identity is outside this supported
logical recovery workflow. Use a newly named logical recovery target
before exposing the application again.

Use the original order ID to verify a lost issuance response before
retrying. A committed key is only available in its original response.

## Dashboard performance

The overview counts states at request time, including natural expiry.
It groups cards per order and reuses that result for sales and Beijing-time
trends. Order pages locate the requested order IDs before aggregating
their cards. The 20-row pages, order sort, filtered totals and monetary
semantics are preserved. Deep offsets and substring searches still scan or
sort matching rows. There is no second business data store or summary cache.

The functional CI keeps the HTTPS regression. The separate **Dashboard
benchmark and plan comparison** job builds the audited P2.3 and current
binaries on the same runner and PostgreSQL image. Both use 10,000 and
100,000 synthetic cards, two instances and 16 readers. The profile records
first access after restarting the isolated PostgreSQL service (cold shared
buffers, not an OS cache flush), two warm-up passes and three measured
trials of 64 timings per page per trial. It reports P50/P95/P99/max, status
counts, pool waits, mixed issuance/activation with reads, and sampled PG lock
waits. The SQL artifact contains EXPLAIN (ANALYZE, BUFFERS) for overview,
order pagination, card filtering and deep offsets. The Go/PostgreSQL test
artifact also reports independent SQL path timings and sampled Go heap.

The 500 ms target applies to the median of the three trial P95 values for
each page at both sizes. The benchmark emits PASS/MISS separately from
functional success. For an acceptance run on a controlled runner, enable
`enforce_dashboard_slo` in manual CI or set `CHEZHI_REQUIRE_PERF=1` with
`CHEZHI_PERF_PROFILE=benchmark`. Record any MISS and review the plans.
This synthetic profile does not certify production capacity.

## Source review and choice of shared storage

- OpenLicensd [3170156](https://github.com/alvarorg14/openlicensd/tree/3170156f0e527d3e3b14b55a26a0d3ab9fc3ed50), Apache-2.0. Reviewed the main server lifecycle, structured logging, token-hash session store, and PostgreSQL rate limiter. Retained the already attributed `internal/license` authorization core.
- chi [9b9fb55](https://github.com/go-chi/chi/tree/9b9fb55def404397748a9fc7e044efe9db1d618e), MIT. Reviewed request-ID middleware and its context boundary. CheZhi creates a fresh request ID at ingress rather than accepting external request IDs.
- Caddy [551f793](https://github.com/caddyserver/caddy/tree/551f793700fe1550845c824470b623fd1aa03d36), Apache-2.0. Reviewed reverse-proxy forwarding and trusted-peer semantics. CheZhi accepts only a single trusted immediate hop.

New server, middleware, SQL and examples are project implementations. No
additional upstream source is distributed. PostgreSQL keeps session
invalidation atomic with the account transaction and shares limits across
instances without another service. Redis could reduce rate-bucket
contention at higher load but would require a second service and an explicit
security/failure model for revocation and recovery. Measure contention
before revisiting that choice.

## P5 signed-license capacity and operations acceptance

The standalone CI now includes a bounded V2 workload on a disposable
PostgreSQL database and two real HTTPS instances. Sixteen worker threads
perform 32 signed renewals of one already-bound synthetic card, obtaining
the challenge on one instance and completing it on the other. Each instance
has a three-handler public admission limit; the workload uses two permits
per instance (four total), leaving headroom for response finalization.
Worker concurrency is not simultaneous HTTP concurrency. Every
credential is checked independently with OpenSSL; the card and binding
snapshots must stay unchanged. A separate eight-way duplicate-proof race
must yield one success and seven denials. Public request metrics must
account for all 73 HTTP requests (37/36 per instance), with zero additional
5xx errors. Rate buckets are reset only in the isolated fixture between
workloads. Normal production limits are not modified.

The output reports challenge-plus-client-signing, renewal and end-to-end
P50/P95/P99/max, throughput and pool state. It includes worker queue
waiting, fresh TLS connections and local OpenSSL process startup; the values
are not pure server processing latency. V2_RECOVERY_TIMING reports native
dump duration, target creation/restore duration and elapsed time through
verified recovery (including trust reconfiguration and credential checks). Independent response verification is outside
the timed workload. Same-card contention is deliberate; this is a short
functional capacity regression, not a production peak-load or sustained
load claim. The existing 10,000/100,000-card dashboard benchmark and
independent database restore and rotation tests remain mandatory evidence.

Before deployment, select a production concurrency/renewal budget based
on the intended number of licensed users and renewal interval. Run an
authorized isolated load profile with distinct devices/cards, representative
rate limits, mixed issuance/revocation/read traffic, and longer duration.
Record accepted/denied/429/503 counts, request percentiles, connection-pool
wait deltas, process memory and CPU, database size, and recovery timings.
Keep the diagnostics listener private. Monitor readiness failure, 5xx
error-rate increases and pool saturation; the cumulative error counter
counts 5xx only, not normal denials or throttling. Do not infer percentiles
from the timing sum. Use workload latency measurements or a separately
validated histogram when required.

Set and document RPO/RTO and backup retention before deployment. Existing
native logical recovery tests validate data and trust scope but do not
establish a production recovery time or a PITR guarantee. Verify restores
to newly named isolated databases, reconcile post-backup writes and keep
the production deployment unchanged until owner-approved acceptance.
No campus-network or elevated-client operation is involved.
