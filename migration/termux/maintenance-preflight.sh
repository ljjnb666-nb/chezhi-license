#!/usr/bin/env bash
# Read-only inventory of the existing Termux staging cluster.
set -euo pipefail
umask 077
export LC_ALL=C
die() { printf '%s\n' "$*" >&2; exit 1; }
[ "$#" -eq 0 ] || die 'Read-only preflight accepts no arguments.'
case "$HOME" in /data/data/com.termux/files/home|/data/user/0/com.termux/files/home) ;; *) die 'Use Termux private home.';; esac
[ "$(uname -m)" = aarch64 ] || die 'ARM64 required.'
root="$HOME/.chezhi-license-staging"
[ -d "$root" ] && [ ! -L "$root" ] && [ "$(stat -c %a "$root")" = 700 ] || die 'Invalid staging directory.'
[ -f "$root/initialized" ] && [ ! -L "$root/initialized" ] && [ "$(cat "$root/initialized")" = loopback-staging-v1 ] || die 'Not initialized.'
[ -d "$root/pgdata" ] && [ ! -L "$root/pgdata" ] || die 'Invalid database directory.'
for name in tls-cert tls-key pgpass; do
    [ -f "$root/$name" ] && [ ! -L "$root/$name" ] && [ "$(stat -c %a "$root/$name")" = 600 ] || die 'Invalid protected input.'
done
for cmd in openssl psql timeout curl stat df; do command -v "$cmd" >/dev/null || die "Missing dependency: $cmd"; done
openssl verify -CAfile "$root/tls-cert" -verify_ip 127.0.0.1 "$root/tls-cert" >/dev/null || die 'Origin certificate verification failed.'
cert_pub="$(openssl x509 -in "$root/tls-cert" -pubkey -noout | openssl pkey -pubin -outform DER | openssl dgst -sha256)"
key_pub="$(openssl pkey -in "$root/tls-key" -pubout -outform DER | openssl dgst -sha256)"
[ "$cert_pub" = "$key_pub" ] || die 'Certificate and key do not match.'
openssl x509 -in "$root/tls-cert" -noout -enddate -fingerprint -sha256
if ! openssl x509 -in "$root/tls-cert" -checkend 604800 -noout >/dev/null; then
    printf 'WARNING TLS renewal needed within seven days.\n' >&2
fi
curl --noproxy '*' --fail --silent --show-error --max-time 5 --cacert "$root/tls-cert" https://127.0.0.1:18443/readyz >/dev/null || die 'Origin not ready.'
# Query only nonsecret operational settings; no query text, users, cards,
# connection strings, log contents or key material printed.
env -i HOME="$HOME" PATH="$PATH" PGPASSFILE="$root/pgpass" PGCONNECT_TIMEOUT=5 PGOPTIONS='-c default_transaction_read_only=on -c statement_timeout=5000' \
    timeout 15s psql -X -w -h 127.0.0.1 -p 55439 -U chezhi_migrator -d chezhi -A -t -v ON_ERROR_STOP=1 \
    -c "SELECT name || '=' || setting || COALESCE(' ' || unit,'') || ' pending_restart=' || pending_restart FROM pg_settings WHERE name IN ('logging_collector','log_rotation_age','log_rotation_size','log_file_mode','log_statement','log_parameter_max_length','log_parameter_max_length_on_error') ORDER BY name"
if [ -f "$root/postgres.log" ] && [ ! -L "$root/postgres.log" ]; then
    printf 'legacy_postgres_log_bytes=%s\n' "$(stat -c %s "$root/postgres.log")"
fi
df -Pk "$root" | awk 'END {print "free_kib=" $4}'
printf 'MAINTENANCE_PREFLIGHT_OK read-only; no restart or rotation performed\n'
