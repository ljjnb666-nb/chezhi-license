# Termux ARM64 local staging candidate (P6)

This is an experimental standalone licensing service deployment, not a
production release or a campus-network client. No root, Docker, or Windows
helper is required. The first profile binds HTTPS to 127.0.0.1:18443,
diagnostics to 127.0.0.1:18444 and PostgreSQL to 127.0.0.1:55439.
It intentionally does not expose a LAN or public listener.

## Prerequisites and preparation

Install Termux from its official F-Droid or GitHub distribution; do not mix
app/plugin signing sources. Use the private Termux home, not shared storage.
On the phone:

    pkg update
    pkg install postgresql openssl curl coreutils util-linux unzip
    uname -m
    getprop ro.build.version.sdk
    postgres --version

The architecture must be aarch64. Record Android API level, Termux version,
available disk, PostgreSQL major version and package versions. Existing
server integration evidence covers PostgreSQL 17; the current Termux
package may be PostgreSQL 18. A fresh database must pass both db-check
commands; do not suppress catalog differences, replace system libraries,
downgrade from an untrusted package mirror or migrate an existing database
to make the test pass. Stop and report a version mismatch. Cross-build
success does not establish execution on HarmonyOS.

## Candidate use

Use the exact reviewed CI artifact and compare its SHA256 through an
independently trusted source before copying/extracting it into Termux's
private home. The archive is an unsigned test candidate; a checksum from
the same archive is only a transfer-integrity check. Do not use real
customer cards or credentials. Never share the generated password,
private signing seed, DSN, CSRF key, TLS key, or database dump.

From the extracted candidate directory:

    sha256sum -c SHA256SUMS
    bash migration/termux/staging.sh init ./chezhi-server-android-arm64 "$(sha256sum chezhi-server-android-arm64 | cut -d ' ' -f1)"
    bash migration/termux/staging.sh run

The installer creates a new isolated directory and a dedicated database
cluster; it never overwrites or migrates an existing installation. It
prompts for a separate supervisor password, uses random database credentials,
applies runtime grants, configures V2 signing offline, and checks both roles.
Its test TLS certificate expires after 30 days. Trust only the explicitly
provisioned certificate; never use curl -k or disable certificate checks.
Keep the foreground Termux session running. In another Termux session
(from the extracted candidate directory):

    bash migration/termux/staging.sh status
    bash migration/termux/staging.sh trust-info
    bash migration/termux/staging.sh backup

Stop the foreground service with Ctrl-C, then:

    bash migration/termux/staging.sh stop-db

Restart with run. The service lock prevents concurrent managed starts
or stopping the database through this script while the service owns it.
Do not manually start a second copy or reuse the port for another service.
The same Android app UID controls these files and processes; this does
not protect against a compromised Termux account or rooted device.

If init fails, do not rerun on that directory, delete it automatically,
or disclose its contents. Inspect logs privately, stop its own database
with pg_ctl -D "$HOME/.chezhi-license-staging/pgdata" -m fast stop if
still running, then preserve the failed fixture for diagnosis.

## Backup, background and acceptance

The backup command creates a unique private directory, a native logical
dump, a listability check and SHA256. It does not claim restore success.
A production backup requires encrypted off-device storage of the database
and separately protected signing/configuration material, retention and a
verified logical recovery into a new database per SERVER.md. Never copy
private data to shared storage without protection.

For first phone tests, allow foreground operation with the display off,
exclude Termux from system battery optimization where appropriate, and
observe charging temperature. Do not enable auto-start, continuous wake
locks or auto-restart until the operator approves that lifecycle. Android
may kill app processes even with exemptions; reboot, lock-screen and
24/72-hour measurements remain required.

Acceptance order:
1. Verify actual executable launch, argument handling and database package
   compatibility; startup must pass readiness and both role checks.
2. On the isolated phone, test HTTPS and supervisor login with explicit
   certificate trust. No browser warning bypass. Verify wrong credentials
   and restricted runtime database permissions.
3. Test real V2 activation, renewal, expiry and revocation with synthetic
   cards and an independently provisioned trust configuration. A Windows
   client cannot reach phone loopback; a later, separately approved private
   LAN profile must use an explicit interface, matching TLS SAN and firewall
   policy. Do not expose a wildcard listener or PostgreSQL.
4. Verify controlled shutdown/restart, backup and independent restore, then
   screen-off, reboot and sustained resource measurements. Record actual
   uptime, process kills, peak memory, temperature, disk and recovery time.

No production capacity, public reachability, code signing, APK, automatic
boot or restore is delivered by this candidate. The existing desktop
authorization and privileged-operation gates remain unchanged.

## Owner-reported physical-device acceptance — 2026-11-28

CONDITIONAL_PASS for the original local staging candidate only. The
operator supplied an on-device acceptance report; the repository review
independently checked CI and artifact metadata, not the phone itself.
PR #8 head 763f4c52f6a165db7bf55c206faecafcc5758549, merge checkout
adf44f4, [CI 46043511742](https://github.com/ljjnb666-nb/chezhi-license/actions/runs/46043511742)
12/12 successful. Artifact 15220523183 SHA256
d3290f4d45196390aafc9685f168c103aa7c7146882c63683f1c1e6e8dc3d9e4.

- Honor AQM-AL10, HarmonyOS 3.0.0.165, aarch64, API 29, PostgreSQL 18.7.
- Reported verified transfer, seven internal file hashes, both DB role
  checks, denied excess grants, 0600 secret files and trusted HTTPS.
- 8/8 synthetic card/business checks: bad password, login, issuance,
  activation/independent signature verification, validate, renew,
  legacy downgrade refusal, revoked-card denial. One synthetic revoked
  card retained after controlled process and database restart.
- Reported native dump and restore into a separate database with
  matching row counts; not recovered-service functional acceptance.
- Single post-restart RSS samples: service 12.4 MiB, PostgreSQL
  parent 28.1 MiB; database directory 65 MiB. Not peak or aggregate RSS.
- All listeners remained loopback; temporary SSH authorization and USB
  forwarding removed and denial verified.

Two reported deployment defects: initial password prompt misstated the
minimum character count and rejected input after DB setup; a -h probe
created a local demo instance and emitted temporary demo credentials.
The operator stopped that instance and kept the failed initialization
separate. Never copy its credentials to logs or reuse them. Confirm the
demo directory remains quarantined; do not remove evidence automatically.
Follow-up changes validate password length before initialization and
make option probes non-mutating; their CI and on-device recheck are
separate from the original artifact's acceptance.

Remain HOLD for natural card expiry, complete phone reboot, screen-off
and 24/72-hour stability, service-level recovery, off-device recovery,
resource/thermal limits, certificate renewal and external access.
Do not reinstall the running fixture just to update documentation.
No public listener or tunnel is authorized by this acceptance. A later
external-access candidate must prove strict separation of public V2
API routes from administrator, database and diagnostic interfaces.

## M4 managed staging candidate (runit)

This optional controller adopts the existing initialized database and
existing reviewed binary. It does not replace the binary, rotate keys,
initialize data, expose ports, install global Termux services or start
cloudflared. Validate the new artifact SHA256 and its manifest before use.
The original phone acceptance is not an acceptance of these new scripts.

Prerequisites: Termux private home, runit (runsv, sv, svlogd), coreutils,
util-linux, PostgreSQL, OpenSSL and curl. Termux:Boot must be installed
from the same signing source as Termux and opened once for boot opt-in.
Termux:API is optional and not used by this controller.

From the verified extracted artifact:

    bash migration/termux/supervisor.sh install

Installation creates a new private managed-v1 directory and copies three
reviewed scripts into it. It refuses to overwrite an existing controller.
It does not start or stop the existing instance. Stop the old foreground
application gracefully first; retain the database and original backups.
Then, in a Termux session:

    bash migration/termux/supervisor.sh start

Use a second session for status and controlled shutdown:

    bash migration/termux/supervisor.sh status
    bash migration/termux/supervisor.sh backup-now
    bash migration/termux/supervisor.sh stop
    bash migration/termux/staging.sh stop-db

The foreground controller starts three private runsv processes (application,
backup and health). Each
application launch retains the existing staging service lock, checks the
installed binary digest and DB runtime grants, and starts the existing
PostgreSQL cluster if needed. runit restarts a failed application after
a fixed ten-second finish delay; no tight restart loop. The controller
refuses concurrent starts and refuses to take over a live foreground
service. A runsv failure exits the controller with an error rather than
launching an overlapping child. Controlled stop stops managed children,
leaving PostgreSQL running for explicit shutdown. If stop times out,
inspect the actual process and lock state; never kill arbitrary PIDs.

Application, backup and health logs use svlogd, approximately 1 MiB per
segment and five retained rotated segments for each service. PostgreSQL's original
postgres.log is not rotated by this candidate; monitor disk usage and
plan a separately reviewed DB logging change. Status checks readiness
with the existing TLS certificate and warns when it expires within
seven days. The health watchdog checks certificate-verified readiness every 15 seconds
plus request time. Four consecutive failures can request TERM through the
private runit service, serialized with operator shutdown; the existing
service restart path then checks PostgreSQL. A cooldown of eight probe
cycles limits recovery requests. Invalid local certificate verification
holds recovery rather than retrying TERM. No forced kill is performed;
a child that ignores TERM, other trust failures or a persistent database
fault need operator diagnosis. No Android process-survival guarantee or
forced wake lock.

The backup service waits for trusted HTTPS readiness, polling every five
seconds while unready, then automatically attempts the current UTC day's
backup. A successful check sleeps 15 minutes; a backup failure retries
in 60 seconds. At most one completed logical archive per UTC date is
published in managed-daily. The archive
is checked for listability, complete decode, and SHA256 before publish.
The scheduler retains the newest seven verified daily copies, excluding
all preexisting manual backups and incomplete directories. Unexpected
files, invalid archives and backward dates block pruning. Less than
1 GiB free blocks new backups. Failures remain in local logs; no external
notification is installed. Restore validation and encrypted off-device
copies remain separate. A backup now command is idempotent for today's
completed archive, not a replacement for the manual backup command.

Enable boot only after controlled adoption and explicit operator approval:

    bash migration/termux/supervisor.sh boot-enable

Disable the exact owned boot entry:

    bash migration/termux/supervisor.sh boot-disable

Boot-enable does not start a service or acquire a wake lock. Boot-disable
does not stop the running controller. The generated boot entry uses the
installed Bash path and writes one private boot-attempt timestamp before
invoking the controller. Run supervisor.sh boot-status to inspect whether
the exact entry is installed and the last observed entry invocation. A
manual invocation can also create this marker, so compare its timestamp
against the actual reboot and corroborate with Android broadcast history.
This marker alone is not proof of a successful boot. Android may delay or suppress
boot/background activity; prove actual execution after complete reboot
and unlock on the physical device. The Linux CI fixture exercises real
runit with a synthetic service and synthetic archive utilities; it is
not an Android or PostgreSQL restore test. Field gates: verify installed
script digests, manual-service exclusion, service termination/restart,
controlled stop without relaunch, readiness failure and certificate hold,
backup scheduling and retention,
screen-off/reboot/24h/72h uptime, storage/thermal behavior, and rollback
to the original foreground staging script. External access remains HOLD.

## M4 physical-device follow-up — 2026-11-28

Operator-reported evidence for head 9836d0390278acbf2ed9e96727985527b89c0ef0,
CI 46111041790, artifact 15249777130 (nine manifest checks passed):
HOLD_BOOT, safe rollback to original foreground service at 13:41:56 CST.
Manual-service exclusion, managed startup, duplicate refusal, graceful
stop and application restart within 11 seconds passed. PostgreSQL PID
was unchanged across application restart. Original binary, key, TLS
certificate, manual backup hashes, cluster identity and business row
counts were reportedly preserved. Native daily archive verified with
68 directory entries and full decode, but the scheduler initially ran
before readiness and required a worker restart to generate the archive.
Short unplug/screen-off overlap was 3m13s; process identities unchanged,
observed HTTPS probes successful but with a sampling gap. No 24/72h proof.
Termux 0.118.3, Boot 0.8.1, API 0.53.0 from F-Droid, common UID; battery
exemption and boot permission checked. Android recorded Boot receiver
Skipped after an approved cold reboot; cause not yet established.
Boot entry disabled, original foreground service restored, tunnel off.
No phone access was performed by repository reviewer.

### Boot diagnosis and safe retest

Battery optimization exemption does not imply OEM app-launch permission.
Open Termux:Boot once from its launcher (official instructions:
https://github.com/termux/termux-boot). On HarmonyOS, inspect the normal
Settings/Optimizer App launch controls for Termux and, if listed,
Termux:Boot; operator may allow auto-launch, secondary launch and
background activity. See Huawei guidance:
https://consumer.huawei.com/en/support/content/en-us15850069/
Do not disable system security, force broadcast delivery, spoof the
system boot event, root the phone or force-stop apps as a workaround.
Collect read-only package stopped/enabled state, user-unlock state,
broadcast history and relevant sanitized logcat records. A missing
marker plus skipped broadcast indicates no observed entry invocation;
a fresh marker plus no service indicates a later launch failure.
Do not treat a synthetic/manual boot-entry test as a real reboot.

### Updating the stopped controller without changing data

The previous controller is not an in-place update target. Keep its
logs and scripts as evidence. Verify the new artifact digest/manifest,
confirm the old boot entry is absent using the old reviewed controller,
confirm all old managed children and runsv processes have exited and
the old controller lock is free. Only with operator approval, rename
the exact private managed-v1 directory to a new, unused sibling archive
directory; never overwrite an archive or move the staging root, pgdata,
keys, installed binary, manual backups or managed-daily. Never execute
the archived controller after renaming it. Install the new controller
from the extracted reviewed artifact; then follow the existing graceful
manual-stop/adoption procedure. If setup fails, keep evidence and restore
the original foreground service. For subsequent cold reboot, explicitly
obtain approval, enable boot, confirm readiness, record baseline time,
reboot, unlock and inspect boot-status before manually invoking anything.
If the system still skips delivery, disable the entry and retain a
documented manual-start requirement; do not claim unattended boot.
Natural scheduling across UTC dates, actual watchdog fault injection,
and 24/72h endurance remain physical-device gates. Cloudflare stays off.
