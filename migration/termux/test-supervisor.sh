#!/usr/bin/env bash
# Linux CI fixture: real runit, synthetic service and archive commands.
# Device guards are removed only in copied fixture scripts.
set -euo pipefail
umask 077
src="$(cd -- "$(dirname -- "$0")" && pwd -P)"
tmp="$(mktemp -d)"
export HOME="$tmp/home"
mkdir -m 700 "$HOME" "$HOME/.chezhi-license-staging" "$tmp/code" "$tmp/mock"
root="$HOME/.chezhi-license-staging"
printf 'loopback-staging-v1\n' > "$root/initialized"
parent=''
cleanup() {
    if [ -n "$parent" ]; then
        bash "$tmp/code/supervisor.sh" stop >/dev/null 2>&1 || true
        kill -TERM "$parent" 2>/dev/null || true
        wait "$parent" || true
    fi
    rm -rf -- "$tmp"
}
trap cleanup EXIT
for name in supervisor managed-backup; do
    sed -e '/^case "$HOME" in /c\:' -e '/^\[ "$(uname -m)" = aarch64 \]/c\:' "$src/$name.sh" > "$tmp/code/$name.sh"
    if [ "$name" = supervisor ]; then
        sed -i -e 's/^            sleep 15$/            sleep 1/' \
            -e 's/^            sleep "$delay" \& child=\$!$/            sleep 1 \& child=$!/' "$tmp/code/$name.sh"
    fi
    bash -n "$tmp/code/$name.sh"
done
cat > "$tmp/code/staging.sh" <<'FIXTURE'
#!/usr/bin/env bash
set -euo pipefail
root="$HOME/.chezhi-license-staging"
case "$1" in
run)
    exec 9>"$root/service.lock"
    flock -n 9
    printf '%s\n' "$$" > "$root/fixture-pid"
    exec sleep 600
    ;;
status) test -f "$root/fixture-pid";;
*) exit 1;;
esac
FIXTURE
cat > "$tmp/mock/curl" <<'FIXTURE'
#!/bin/bash
[ ! -f "$HOME/fixture-unready" ]
FIXTURE
cat > "$tmp/mock/pg_dump" <<'FIXTURE'
#!/bin/bash
set -e
while [ "$#" -gt 0 ]; do
  if [ "$1" = -f ]; then printf 'synthetic archive\n' > "$2"; exit 0; fi
  shift
done
exit 1
FIXTURE
cat > "$tmp/mock/pg_restore" <<'FIXTURE'
#!/bin/bash
set -e
for last in "$@"; do :; done
grep -qx 'synthetic archive' "$last"
FIXTURE
cat > "$tmp/mock/date" <<'FIXTURE'
#!/bin/bash
cat "$HOME/fixture-date"
FIXTURE
chmod 700 "$tmp/mock/"*
export PATH="$tmp/mock:$PATH"
printf '2026-11-28\n' > "$HOME/fixture-date"
mkdir -m 700 "$root/backups"
touch "$root/backups/manual-preserve"
for day in 21 22 23 24 25 26 27 28; do
    printf '2026-11-%s\n' "$day" > "$HOME/fixture-date"
    bash "$tmp/code/managed-backup.sh"
done
test ! -e "$root/managed-daily/2026-11-21"
test -f "$root/backups/manual-preserve"
test "$(find "$root/managed-daily" -mindepth 1 -maxdepth 1 -type d | wc -l)" -eq 7
bash "$tmp/code/managed-backup.sh"
printf '2026-11-27\n' > "$HOME/fixture-date"
if bash "$tmp/code/managed-backup.sh"; then echo 'clock rollback accepted'; exit 1; fi
printf '2026-11-28\n' > "$HOME/fixture-date"
# A corrupted existing backup must block retention and remain untouched.
printf 'corrupt\n' >> "$root/managed-daily/2026-11-22/database.dump"
if bash "$tmp/code/managed-backup.sh"; then echo 'corrupt backup accepted'; exit 1; fi
test -f "$root/managed-daily/2026-11-22/database.dump"
printf 'synthetic archive\n' > "$root/managed-daily/2026-11-22/database.dump"
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj /CN=127.0.0.1 \
    -addext subjectAltName=IP:127.0.0.1 -keyout "$root/fixture-key" -out "$root/tls-cert" 2>/dev/null
bash "$tmp/code/supervisor.sh" install
if bash "$tmp/code/supervisor.sh" install; then echo 'duplicate install accepted'; exit 1; fi
bash "$tmp/code/supervisor.sh" boot-enable
test -f "$HOME/.termux/boot/90-chezhi-staging"
bash -n "$HOME/.termux/boot/90-chezhi-staging"
bash "$tmp/code/supervisor.sh" boot-status | grep -qx BOOT_ENTRY_NOT_OBSERVED
# Invoke the generated entry under a manual service lock: observe entry
# delivery separately from successful controller startup. This is not a reboot.
(
    flock -n 9
    if bash "$HOME/.termux/boot/90-chezhi-staging" 9>&-; then echo 'boot entry adopted live manual service'; exit 1; fi
) 9>"$root/service.lock"
bash "$tmp/code/supervisor.sh" boot-status | grep -q '^BOOT_ENTRY_STARTED '
bash "$tmp/code/supervisor.sh" boot-disable
test ! -e "$HOME/.termux/boot/90-chezhi-staging"
# Refuse managed adoption while an independent foreground instance owns the lock.
(
    flock -n 9
    if bash "$tmp/code/supervisor.sh" start 9>&-; then echo 'live manual service adopted'; exit 1; fi
) 9>"$root/service.lock"
# New UTC day with readiness initially false. Scheduler must wait and then
# publish without a manual service restart or backup-now invocation.
printf '2026-11-29\n' > "$HOME/fixture-date"
touch "$HOME/fixture-unready"
bash "$tmp/code/supervisor.sh" start & parent=$!
for i in $(seq 1 15); do
    if grep -qs BACKUP_WAIT_READY "$root/managed-v1/log-backup/current"; then break; fi
    sleep 1
done
grep -q BACKUP_WAIT_READY "$root/managed-v1/log-backup/current"
test ! -e "$root/managed-daily/2026-11-29"
rm -- "$HOME/fixture-unready"
for i in $(seq 1 15); do
    if [ -f "$root/managed-daily/2026-11-29/SHA256SUMS" ]; then break; fi
    sleep 1
done
test -f "$root/managed-daily/2026-11-29/SHA256SUMS"
grep -q BACKUP_READY "$root/managed-v1/log-backup/current"
# A further day should be picked up by the running scheduler.
printf '2026-11-30\n' > "$HOME/fixture-date"
for i in $(seq 1 15); do
    if [ -f "$root/managed-daily/2026-11-30/SHA256SUMS" ]; then break; fi
    sleep 1
done
test -f "$root/managed-daily/2026-11-30/SHA256SUMS"
for i in $(seq 1 30); do [ -s "$root/fixture-pid" ] && break; sleep 1; done
old="$(cat "$root/fixture-pid")"
kill -0 "$old"
if bash "$tmp/code/supervisor.sh" start; then echo 'duplicate controller accepted'; exit 1; fi
kill -TERM "$old"
for i in $(seq 1 35); do
    new="$(cat "$root/fixture-pid")"
    if [ "$new" != "$old" ] && kill -0 "$new" 2>/dev/null; then break; fi
    sleep 1
done
test "$new" != "$old"
kill -0 "$new"
# The still-running child becomes unready; watchdog must request graceful
# termination through runit and leave the supervisor responsible for restart.
old="$new"
# Invalid local certificate must hold rather than cause restart churn.
cp -- "$root/tls-cert" "$root/fixture-valid-cert"
printf 'invalid certificate\n' > "$root/tls-cert"
touch "$HOME/fixture-unready"
for i in $(seq 1 15); do
    if grep -qs HEALTH_HOLD "$root/managed-v1/log-health/current"; then break; fi
    sleep 1
done
grep -q 'HEALTH_HOLD invalid local TLS certificate' "$root/managed-v1/log-health/current"
test "$(cat "$root/fixture-pid")" = "$old"
kill -0 "$old"
mv -- "$root/fixture-valid-cert" "$root/tls-cert"
for i in $(seq 1 45); do
    new="$(cat "$root/fixture-pid")"
    if [ "$new" != "$old" ] && kill -0 "$new" 2>/dev/null; then break; fi
    sleep 1
done
rm -- "$HOME/fixture-unready"
test "$new" != "$old"
kill -0 "$new"
grep -q HEALTH_RECOVERY_REQUEST "$root/managed-v1/log-health/current"
bash "$tmp/code/supervisor.sh" stop
wait "$parent"
parent=''
if kill -0 "$new" 2>/dev/null; then echo 'service still alive'; exit 1; fi
(flock -n 9) 9>"$root/service.lock"
printf 'PASS isolated real runit restart, duplicate denial, boot opt-in/out, controlled stop, readiness watchdog recovery, manual exclusion, corrupt backup retention, readiness-gated scheduling, boot entry marker and clock rollback\n'
