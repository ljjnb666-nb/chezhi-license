# Standalone authorization server

## Modes and startup

| Mode | Transport | Persistence |
| --- | --- | --- |
| `local` or unset | Loopback HTTP, random port by default | JSON by default, PostgreSQL with `CHEZHI_STORAGE=postgres` |
| `server` | Direct HTTPS or the specified trusted HTTPS reverse proxy | PostgreSQL required |
| `test` | Loopback HTTP or direct HTTPS, without proxy forwarding | PostgreSQL required, legacy demo route available |

Server and test modes require a configured supervisor credential. Run
`db-init` and `db-check --migrator` using the migration account. If the
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
version 3. These deep checks are part of deployment and recovery
acceptance. Startup and readiness only check version, connection and the
minimum resources needed to accept traffic.

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
| `CHEZHI_LOGIN_PER_MINUTE` | Default 5 attempts per source, configurable 1?30, with a deployment limit of 60 per minute. |
| `CHEZHI_LICENSE_PER_MINUTE`, `CHEZHI_LICENSE_GLOBAL_PER_MINUTE` | License defaults are 60/source and 240/deployment per minute. Allowed maxima are 600 and 3000. |
| `CHEZHI_MAX_CONNECTIONS` | Maximum accepted application TCP connections per instance, default 128, range 16?1024. |

Keep configuration files outside Git and Docker build contexts and give
the service account only the file access it needs. Reconfigure instances
together when changing shared CSRF/rate settings. Connection DSNs, passwords,
card keys, and cookies are absent from application request logs.

Direct TLS ignores forwarded headers. In proxy mode the backend accepts
traffic only from a configured immediate peer. The proxy must overwrite
`X-Forwarded-For` with one observed source IP and
`X-Forwarded-Proto` with `https`; the original Host is preserved.
Forwarded Host is ignored. Put the backend on an isolated network and
restrict ingress to the proxy. [The Caddy example](../Caddyfile.example)
shows a same-host proxy. Use the exact public Origin with browser form
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
Rate windows are fixed one-minute UTC windows. Shared-state errors fail
closed. The service shuts down on signals, drains requests and stops cleanup
before the database pool closes.

For recovery, use [the PostgreSQL runbook](POSTGRES.md) and compare the
backup with the source baseline. Before making the restored database
available to a standalone cluster, clear pre-restore ephemeral authorization
state with the migration account:

```sql
TRUNCATE chezhi_sessions, chezhi_rate_limits;
```

Keep every instance offline until reconciliation and role/schema checks
finish. Use the original order ID to verify a lost issuance response before
retrying. A committed key is only available in its original response.
PostgreSQL dashboard reads are section-specific and page their results at
20 rows. Counts and summaries still scan relevant records and can get
slower at greater volumes or deeper offsets; monitor request duration and
pool waits.

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
