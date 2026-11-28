#!/usr/bin/env bash
# Export a verified daily logical dump as an age-encrypted, unpublished candidate.
# No network, no private decryption identity on the phone, no database writes.
set -euo pipefail
umask 077
export LC_ALL=C
die() { printf '%s\n' "$*" >&2; exit 1; }
case "$HOME" in /data/data/com.termux/files/home|/data/user/0/com.termux/files/home) ;; *) die 'Use Termux private home.';; esac
[ "$(uname -m)" = aarch64 ] || die 'ARM64 required.'
[ "$#" -eq 2 ] || die 'Usage: encrypted-export.sh <UTC backup date> <reviewed age public recipient>'
day="$1"
recipient="$2"
[[ "$day" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]] || die 'Invalid backup date.'
[[ "$recipient" =~ ^age1[0-9a-z]{58}$ ]] || die 'Use one independently verified native age recipient.'
root="$HOME/.chezhi-license-staging"
daily="$root/managed-daily"
out="$HOME/.chezhi-encrypted-exports"
private_dir() { [ -d "$1" ] && [ ! -L "$1" ] && [ "$(stat -c %a "$1")" = 700 ]; }
private_dir "$root" && private_dir "$daily" || die 'Invalid private backup tree.'
[ -f "$root/initialized" ] && [ ! -L "$root/initialized" ] && [ "$(cat "$root/initialized")" = loopback-staging-v1 ] || die 'Not initialized.'
for cmd in age pg_restore flock sha256sum mktemp df stat; do command -v "$cmd" >/dev/null || die "Missing dependency: $cmd"; done
[ -f "$daily/backup.lock" ] && [ ! -L "$daily/backup.lock" ] || die 'Missing managed backup lock.'
exec 9<"$daily/backup.lock"
flock -n -x 9 || die 'Backup or retention active; retry later.'
src="$daily/$day"
private_dir "$src" || die 'Invalid daily backup directory.'
for name in database.dump SHA256SUMS NOTICE; do
    [ -f "$src/$name" ] && [ ! -L "$src/$name" ] || die 'Incomplete archive.'
done
[ "$(cat "$src/NOTICE")" = 'managed daily logical backup; not restore-verified' ] || die 'Unexpected archive marker.'
[[ "$(cat "$src/SHA256SUMS")" =~ ^[0-9a-f]{64}\ \ database\.dump$ ]] || die 'Unexpected archive manifest.'
(cd "$src" && sha256sum -c --status SHA256SUMS) || die 'Source checksum mismatch.'
pg_restore --list "$src/database.dump" >/dev/null
pg_restore -f /dev/null "$src/database.dump"
mkdir -p -m 700 "$out"
private_dir "$out" || die 'Invalid export directory.'
target="$out/$day"
[ ! -e "$target" ] && [ ! -L "$target" ] || die 'Export already exists; never overwrite.'
size="$(stat -c %s "$src/database.dump")"
free="$(df -Pk "$out" | awk 'END {print $4}')"
[[ "$size" =~ ^[0-9]+$ && "$free" =~ ^[0-9]+$ ]] || die 'Invalid storage inventory.'
[ "$free" -ge $((size / 1024 + 1048576 + 1024)) ] || die 'Insufficient free space for export.'
work="$(mktemp -d "$out/.partial.XXXXXXXX")"
trap 'printf "Incomplete encrypted export preserved: %s\n" "$work" >&2' EXIT
# Native age authenticated encryption; no password or secret passed to CLI.
age -r "$recipient" -o "$work/database.dump.age" "$src/database.dump"
(cd "$src" && sha256sum -c --status SHA256SUMS) || die 'Source changed during export.'
(cd "$work" && sha256sum database.dump.age > SHA256SUMS)
printf '%s\n' 'encrypted logical database only; receiver decryption/restore not verified' > "$work/NOTICE"
[ ! -e "$target" ] && [ ! -L "$target" ] || die 'Export target appeared.'
mv -nT -- "$work" "$target"
[ ! -e "$work" ] || die 'Output collision; existing target preserved.'
trap - EXIT
printf 'ENCRYPTED_EXPORT_OK date=%s ciphertext_bytes=%s\n' "$day" "$(stat -c %s "$target/database.dump.age")"
