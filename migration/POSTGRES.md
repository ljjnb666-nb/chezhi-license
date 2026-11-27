# PostgreSQL setup, migration and recovery

## Local PowerShell setup

Run commands from the project root. The Compose project publishes only on
loopback and uses its own named volume. Pick a free port if 55432 is in use.

```powershell
$env:CHEZHI_LOCAL_DB_PORT = '55432'
$env:CHEZHI_LOCAL_DB_PASSWORD = [guid]::NewGuid().ToString('N')
docker compose up -d --wait
New-Item -ItemType Directory -Force bin | Out-Null
go build -o bin/chezhi-license.exe .
$env:CHEZHI_DATABASE_URL = "postgres://chezhi_migrator:$($env:CHEZHI_LOCAL_DB_PASSWORD)@127.0.0.1:$($env:CHEZHI_LOCAL_DB_PORT)/chezhi?sslmode=disable"
.\bin\chezhi-license.exe db-init
.\bin\chezhi-license.exe db-check --migrator
$env:CHEZHI_STORAGE = 'postgres'
.\bin\chezhi-license.exe
```

The example uses a generated password and a dedicated disposable local
database. Build distributable Windows and Linux binaries with a patched Go
1.26 toolchain (at least 1.26.11 for this release). Set
`$env:GOTOOLCHAIN = 'go1.26.11'` for a reproducible local build. CI pins the
shipping toolchain and PostgreSQL 17.10 Alpine image digest and runs
`go mod verify` and pinned `govulncheck`. Go 1.23 CI checks source
compatibility separately. The Compose-created `chezhi_migrator` account
is the administrator of its disposable local cluster and is suitable for
initialization, imports and creating the separate runtime account. Compose accepts environment variables or a private `.env`;
the Go process reads environment variables from its caller. For PostgreSQL
mode, the service verifies the schema at startup and exits on a missing
connection string, unavailable database or unsupported schema. It listens on
a random loopback port as before. To start the JSON backend explicitly:

```powershell
$env:CHEZHI_STORAGE = 'json'
.\bin\chezhi-license.exe .\data
```

`docker compose down` stops and removes this project's container and network
while retaining the volume. After exporting any needed evidence,
`docker compose down --volumes` deletes this project's development database.
The first initialization password belongs to the volume; changing the local
environment variable alone does not rotate an existing database password.

## Schema and runtime role

Run `db-init` with the schema owner before serving traffic. It applies
ordered SQL migrations atomically under a database advisory lock and checks
the recorded version history. The service requires an exact supported
version and loads startup account configuration. To separate runtime permissions, create a dedicated login in
`psql` as the database administrator and set its password with `\password`.

```sql
CREATE ROLE chezhi_runtime LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION;
GRANT CONNECT ON DATABASE chezhi TO chezhi_runtime;
```

While connected to the application database as the schema owner, run
`\i migration/postgres_runtime_grants.sql` from the repository root. Use the
runtime role's DSN for serving and the dedicated migration role's DSN for
`db-init` and `db-import`. Use an isolated application database with no
untrusted principals able to create objects in `public`. For a remote
database use `sslmode=verify-full` with a trusted CA and supply connection
settings from protected configuration. Local examples use loopback without
TLS. Keep connection strings and database dumps outside the repository.
The grant script permits only the app's table, column and sequence
operations; use the migrator account for dumps and restore. Keep protected
password/service files outside the repository. The Git ignore and CI
repository check cover common dump artifacts and credential-file names.

The PostgreSQL backend uses parameterized SQL, a 12-connection pool, a
three-second connect timeout, eight-second statement timeout, five-second
lock timeout, and ten-second request transaction deadline. Database request
errors are redacted. Clients must treat an interrupted connection during
commit as an indeterminate response. Before retrying issuance, check the
original order reference. The unique order reference prevents duplicate
issuance. Raw card keys are delivered once and only hashes are stored.
If the response is lost or the commit outcome is unknown, wait for the
database to become available and search the exact original order number
under **订单管理**. Cross-check the associated cards and issuance audit.
If there is no order and the original transaction has finished, retry with
the same order number. If the order exists and the original keys were lost,
revoke the affected cards and issue replacements under a new unique
order number linked to the original in your operational records. PostgreSQL
deduplicates the order; delivery of the one-time keys depends on the HTTP
response reaching the operator. Acknowledged issuance with a failed page read
shows the committed keys and an explicit unavailable-data notice.

## JSON cutover

1. Stop all JSON and PostgreSQL application processes for the cutover. Make
   a protected copy of the P2.1.7 source directory. Keep the original in
   place. If you have a business ZIP, first restore it with the existing
   JSON tool into a separate directory. That ZIP only carries business
   data; preserve the old members and owner files separately if required.
2. Set the migration DSN for an empty, dedicated database and run:

   ```powershell
   .\bin\chezhi-license.exe db-init
   .\bin\chezhi-license.exe db-import --dry-run 'D:\path\to\stopped-legacy-data'
   .\bin\chezhi-license.exe db-import --apply 'D:\path\to\stopped-legacy-data'
   .\bin\chezhi-license.exe db-check --migrator
   ```

3. Keep the JSON service stopped. After import, archive the legacy directory
   in protected read-only storage and retire its old startup command or
   scheduled job before starting the PostgreSQL service. Do not point a
   running JSON instance at the archived source. Verify migrated counts, representative orders and cards, member access,
   owner login and the last audit records. Keep users off the service
   until verification is complete. Use existing read-only views for this
   step and avoid activating cards or changing settings. Successful
   dashboard login itself adds security audit records. Switch to the
   restricted runtime DSN and start the PostgreSQL service.

Dry run validates the source without a PostgreSQL connection or file writes.
Apply acquires the same exclusive `instance.lock` sentinel as the JSON
service before reading the legacy files and holds it until the database
command exits. It imports the bytes read under that lock and rechecks
source content immediately before commit. A concurrent JSON start is
rejected. Leave the directory untouched throughout cutover, including
manual edits. Normal exit, cancellation and import errors release the
owned lock. After an uncatchable process termination, verify every source
process has stopped before manually removing a stale sentinel.
Apply rejects a non-pristine destination, preserves card IDs and order references
directly as primary keys, and compares the reconstructed records with the
source before commit. A source fingerprint prevents a second import. Missing
optional files retain legacy defaults, including no stored owner password.
The imported audit preserves original actor strings and empty historical actor
fields. Time is persisted as exact UTC seconds since year 0001 with nine
fractional digits to preserve legacy nanoseconds. SQL foreign keys and checks
enforce order, card, binding and term relationships. Plan prices are stored
in integer cents and operate independently of issued cards.

## Transactions and sessions

Issuance inserts the unique order, all cards and all corresponding audit
rows in one transaction. Validation locks the matching card. Batch mutations
lock selected card rows in card-ID order. Support, plans, members and owner
changes commit with their audit rows. Account updates increment a durable
revision. Each admin request refreshes account state. Admin writes share a
row lock on the configuration revision through commit, and incompatible
concurrent account changes cause a retry. Sessions are in memory and scoped to
the serving process. Changing a member's role or credential, disabling a
member or rotating the owner's password invalidates affected sessions
across processes using the durable per-account revision. Logout and logout
all revoke the serving process's sessions. Each successful account refresh removes
expired and revision-invalid sessions before they can occupy the 32-session
capacity. Login and activation rate budgets are process-local. Global
explicit logout and distributed throttling are deferred to P2.3. The
supported deployment remains local loopback.

The dashboard, CSV export and business ZIP currently materialize a coherent
read snapshot in Go to retain existing filtering and presentation semantics.
Operational writes load only the relevant rows. The full admin read
snapshot remains tracked technical debt for the next query-design phase.
Its proposed acceptance workload is 100,000 cards, 1,000,000 audit records
and 16 concurrent admin readers. Measure dashboard, cards, orders and audit
P95 (target <= 500 ms for interactive pages), peak service memory (target
<= 512 MiB), connection lifetime, and filter/count parity. Measure CSV and
business ZIP separately for throughput and peak memory. These are future
acceptance targets, separate from the current activation workload.

## Startup and independent integrity checks

Startup uses a small connection/schema-history check. Use
`db-check --startup` to run that check explicitly. Use
`db-check --migrator` after migration and restore to compare the live
PostgreSQL 17 catalog with the versioned contract, verify business relations
and fixed configuration, inspect the import marker, and verify migration
ownership. `db-check --runtime` performs the readable business checks and
validates effective runtime grants. The runtime account has no access to
the import marker. Standalone `db-check` uses an account with full read
privileges and omits only the role policy check. Deep verification runs
in a read-only consistent transaction and reports anomalies without
repairing records. Update the catalog contract alongside future schema
migrations using the catalog query against a newly initialized test database.

## PostgreSQL backup and recovery

The UI business ZIP remains available and excludes admin credentials. For a
full PostgreSQL backup, use matching PostgreSQL client tools and a privileged
backup account. Take the dump to protected storage; it includes credential
digests and user data. Environment and credential-file arrangements depend on
the client platform. For example, with protected credential configuration:

```powershell
pg_dump --dbname=chezhi --format=custom --file='D:\protected\chezhi.dump' --no-owner --no-acl
createdb chezhi_restore
pg_restore --dbname=chezhi_restore --exit-on-error --single-transaction --no-owner --no-acl 'D:\protected\chezhi.dump'
```

Verify the restored database with `db-check --migrator`, compare row counts
and data reconciliation results against the source backup baseline, and reapply
the runtime grants. A structurally valid smaller dataset can pass a standalone
integrity check, so baseline comparison is required for completeness. Run
`db-check --runtime`, then test login and device authorization on the isolated
restored service before switching. A backup
has a point-in-time recovery boundary. After PostgreSQL accepts writes, recover
forward on PostgreSQL. Pause writers, preserve the latest accessible database or
logs, and reconcile any later writes before promoting a restored copy. The
pre-cutover JSON files are a rollback source only before the PostgreSQL service
accepts writes. No PostgreSQL-to-JSON downgrade command is supplied. Configure
continuous archiving and retention separately if your recovery requirements
need point-in-time recovery.

## Upstream and driver

Reviewed OpenLicensd at
`3170156f0e527d3e3b14b55a26a0d3ab9fc3ed50` for embedded SQL migration,
PostgreSQL transactions, activation row locks, connection handling and
audit-event storage. This change retains the existing Apache-2.0 license
core in `internal/license` and its NOTICE. The new persistence, SQL schema
and tests are project implementations. No additional OpenLicensd source is
distributed. The project uses lib/pq v1.12.3 through Go's database/sql pool
to retain the Go 1.23 CI baseline and avoid additional transitive driver
dependencies. The dependency version and checksums are committed.

## Verification

Use only disposable test instances with the following command. The test
account needs permission to create and drop its randomly named test databases
and terminate its own test connections.

```powershell
$env:CHEZHI_TEST_DATABASE_URL = $env:CHEZHI_DATABASE_URL
go test -count=1 -v -run '^TestPostgres' ./...
```

GitHub Actions uses an isolated PostgreSQL 17.10 service and runs these tests
with Go Race. It runs five live HTTP scripts under the restricted role, each with its own
database. The native PostgreSQL rehearsal compares nine populated tables and
then starts a fresh restored service to verify inherited credentials,
authorization and new writes.
