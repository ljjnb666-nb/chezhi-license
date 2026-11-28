#!/usr/bin/env bash
# Receiver-side archive verification; never connects to PostgreSQL.
set -euo pipefail
umask 077
export LC_ALL=C
die() { printf '%s\n' "$*" >&2; exit 1; }
[ "$#" -eq 4 ] || die 'Usage: encrypted-receive.sh <export dir> <private age identity file> <new private output directory> <independently trusted ciphertext SHA256>'
src="$1"
identity="$2"
target="$3"
expected="$4"
[[ "$expected" =~ ^[0-9a-f]{64}$ ]] || die 'Invalid trusted ciphertext digest.'
for cmd in age pg_restore sha256sum stat mktemp df; do command -v "$cmd" >/dev/null || die "Missing dependency: $cmd"; done
[ -d "$src" ] && [ ! -L "$src" ] || die 'Invalid export directory.'
[ -f "$identity" ] && [ ! -L "$identity" ] && [ "$(stat -c %a "$identity")" = 600 ] || die 'Identity must be a private regular file.'
[ ! -e "$target" ] && [ ! -L "$target" ] || die 'Output already exists.'
parent="$(dirname -- "$target")"
[ -d "$parent" ] && [ ! -L "$parent" ] && [ "$(stat -c %a "$parent")" = 700 ] || die 'Use private output parent.'
for name in database.dump.age SHA256SUMS NOTICE; do
    [ -f "$src/$name" ] && [ ! -L "$src/$name" ] || die 'Incomplete export.'
done
[ "$(cat "$src/NOTICE")" = 'encrypted logical database only; receiver decryption/restore not verified' ] || die 'Unexpected export marker.'
[[ "$(cat "$src/SHA256SUMS")" =~ ^[0-9a-f]{64}\ \ database\.dump\.age$ ]] || die 'Unexpected ciphertext manifest.'
[ "$(cat "$src/SHA256SUMS")" = "$expected  database.dump.age" ] || die 'Manifest differs from independently trusted digest.'
size="$(stat -c %s "$src/database.dump.age")"
free="$(df -Pk "$parent" | awk 'END {print $4}')"
[[ "$size" =~ ^[0-9]+$ && "$free" =~ ^[0-9]+$ ]] || die 'Invalid storage inventory.'
[ "$free" -ge $((2 * (size / 1024 + 1) + 1048576 + 1024)) ] || die 'Insufficient free space.'
work="$(mktemp -d "$parent/.receive.XXXXXXXX")"
# Never leave partially authenticated plaintext published. Unlinking is not
# guaranteed secure erasure; use encrypted receiver storage.
trap 'rm -f -- "$work/database.dump.age" "$work/database.dump" "$work/SHA256SUMS" "$work/NOTICE"; rmdir -- "$work"' EXIT
# Authenticate the exact private copy that will be decrypted, not a
# mutable source path checked before reading.
cp -- "$src/database.dump.age" "$work/database.dump.age"
[ "$(sha256sum "$work/database.dump.age" | cut -d ' ' -f1)" = "$expected" ] || die 'Ciphertext differs from trusted digest.'
age -d -i "$identity" -o "$work/database.dump" "$work/database.dump.age"
rm -- "$work/database.dump.age"
pg_restore --list "$work/database.dump" >/dev/null
pg_restore -f /dev/null "$work/database.dump"
(cd "$work" && sha256sum database.dump > SHA256SUMS)
printf '%s\n' 'decrypted and fully decoded logical archive; actual restore not verified' > "$work/NOTICE"
[ ! -e "$target" ] && [ ! -L "$target" ] || die 'Output appeared.'
mv -nT -- "$work" "$target"
[ ! -e "$work" ] || die 'Output collision; existing target preserved.'
trap - EXIT
printf 'ENCRYPTED_RECEIVE_OK authenticated decryption and full decode; no database restore\n'
