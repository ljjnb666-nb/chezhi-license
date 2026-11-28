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
exit 0
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
bash "$tmp/code/supervisor.sh" install
if bash "$tmp/code/supervisor.sh" install; then echo 'duplicate install accepted'; exit 1; fi
bash "$tmp/code/supervisor.sh" boot-enable
test -f "$HOME/.termux/boot/90-chezhi-staging"
bash "$tmp/code/supervisor.sh" boot-disable
test ! -e "$HOME/.termux/boot/90-chezhi-staging"
bash "$tmp/code/supervisor.sh" start & parent=$!
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
bash "$tmp/code/supervisor.sh" stop
wait "$parent"
parent=''
if kill -0 "$new" 2>/dev/null; then echo 'service still alive'; exit 1; fi
(flock -n 9) 9>"$root/service.lock"
printf 'PASS isolated real runit restart, duplicate denial, boot opt-in/out, controlled stop, managed backup retention and clock rollback\n'
