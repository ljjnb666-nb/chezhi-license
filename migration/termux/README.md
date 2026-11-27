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
