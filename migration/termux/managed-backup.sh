#!/usr/bin/env bash
# Daily logical backups for the private Termux staging cluster only.
set -euo pipefail
umask 077
export LC_ALL=C
die() { printf '%s\n' "$*" >&2; exit 1; }
case "$HOME" in /data/data/com.termux/files/home|/data/user/0/com.termux/files/home) ;; *) die 'Use Termux private home.';; esac
[ "$(uname -m)" = aarch64 ] || die 'ARM64 required.'
root="$HOME/.chezhi-license-staging"
[ -d "$root" ] && [ ! -L "$root" ] && [ "$(stat -c %a "$root")" = 700 ] || die 'Invalid staging root.'
[ "$(cat "$root/initialized")" = loopback-staging-v1 ] || die 'Not initialized.'
for cmd in pg_dump pg_restore curl flock sha256sum mktemp df date; do
    command -v "$cmd" >/dev/null || die "Missing dependency: $cmd"
done
daily="$root/managed-daily"
mkdir -p -m 700 "$daily"
[ ! -L "$daily" ] && [ "$(stat -c %a "$daily")" = 700 ] || die 'Invalid daily backup directory.'
exec 9>"$daily/backup.lock"
flock -n 9 || die 'Managed backup already running.'
today="$(date -u +%F)"
[[ "$today" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]] || die 'Invalid date.'
target="$daily/$today"
verify() {
    local dir="$1" item
    [ -d "$dir" ] && [ ! -L "$dir" ] || return 1
    for item in database.dump SHA256SUMS NOTICE; do
        [ -f "$dir/$item" ] && [ ! -L "$dir/$item" ] || return 1
    done
    [ "$(cat "$dir/NOTICE")" = 'managed daily logical backup; not restore-verified' ] || return 1
    [[ "$(cat "$dir/SHA256SUMS")" =~ ^[0-9a-f]{64}\ \ database\.dump$ ]] || return 1
    (cd "$dir" && sha256sum -c --status SHA256SUMS) || return 1
    pg_restore --list "$dir/database.dump" >/dev/null
}
shopt -s nullglob
for dir in "$daily"/????-??-??; do
    if [ "$(basename "$dir")" \> "$today" ]; then die 'Clock moved backwards; preserve existing backups.'; fi
done
if [ -e "$target" ] || [ -L "$target" ]; then
    verify "$target" || die 'Existing daily backup failed verification; do not overwrite.'
    printf 'Daily backup already verified: %s\n' "$today"
else
    curl --noproxy '*' --fail --silent --show-error --max-time 5 \
        --cacert "$root/tls-cert" https://127.0.0.1:18443/readyz >/dev/null
    free="$(df -Pk "$daily" | awk 'END {print $4}')"
    [[ "$free" =~ ^[0-9]+$ ]] && [ "$free" -ge 1048576 ] || die 'Less than 1 GiB free; backup deferred.'
    for variable in $(compgen -v PG); do unset "$variable"; done
    export PGPASSFILE="$root/pgpass"
    work="$(mktemp -d "$daily/.partial.XXXXXXXX")"
    trap 'printf "Incomplete managed backup preserved: %s\n" "$work" >&2' EXIT
    pg_dump -w -h 127.0.0.1 -p 55439 -U chezhi_migrator -d chezhi \
        -Fc --no-owner --no-acl -f "$work/database.dump"
    pg_restore --list "$work/database.dump" >/dev/null
    pg_restore -f /dev/null "$work/database.dump"
    (cd "$work" && sha256sum database.dump > SHA256SUMS)
    printf '%s\n' 'managed daily logical backup; not restore-verified' > "$work/NOTICE"
    verify "$work" || die 'New backup verification failed.'
    [ ! -e "$target" ] && [ ! -L "$target" ] || die 'Backup target appeared.'
    mv -T -- "$work" "$target"
    trap - EXIT
    printf 'Daily backup created: %s\n' "$today"
fi
# Only complete daily managed archives, never manual or partial backups.
dirs=("$daily"/????-??-??)
for dir in "${dirs[@]}"; do
    [[ "$(basename "$dir")" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]] || die 'Unexpected retention directory.'
    verify "$dir" || die 'Retention blocked by invalid backup; preserve all.'
    [ "$(find "$dir" -mindepth 1 -maxdepth 1 | wc -l)" -eq 3 ] || die 'Unexpected files; preserve all.'
done
while [ "${#dirs[@]}" -gt 7 ]; do
    dir="${dirs[0]}"
    rm -- "$dir/database.dump" "$dir/SHA256SUMS" "$dir/NOTICE"
    rmdir -- "$dir"
    dirs=("${dirs[@]:1}")
done
printf 'MANAGED_BACKUP_OK retained=%s\n' "${#dirs[@]}"
