#!/usr/bin/env bash
# First-stage isolated licensing server on Termux. No root, no public bind.
set -euo pipefail
umask 077
die() { printf '%s\n' "$*" >&2; exit 1; }
[ "$(uname -m)" = aarch64 ] || die 'Requires an ARM64 Termux installation.'
[ -n "$HOME" ] && [ -d "$HOME" ] || die 'Invalid home.'
case "$HOME" in /data/data/com.termux/files/home|/data/user/0/com.termux/files/home) ;; *) die 'Run in the official Termux private home.';; esac
root="$HOME/.chezhi-license-staging"
pg="$root/pgdata"
bin="$root/chezhi-server"
port=55439
origin=https://127.0.0.1:18443
diag=http://127.0.0.1:18444
here="$(cd -- "$(dirname -- "$0")" && pwd -P)"
for cmd in initdb pg_ctl psql pg_dump pg_restore openssl curl flock sha256sum mktemp; do
    command -v "$cmd" >/dev/null || die "Missing dependency: $cmd"
done
# Clear inherited libpq connection settings, use explicit loopback credentials.
for variable in $(compgen -v PG); do unset "$variable"; done
export PGPASSFILE="$root/pgpass"
migrate() {
    env -i PATH="$PATH" HOME="$HOME" CHEZHI_DATABASE_URL_FILE="$root/migration-url" "$bin" "$@"
}
runtime() {
    env -i PATH="$PATH" HOME="$HOME" CHEZHI_DATABASE_URL_FILE="$root/runtime-url" "$bin" "$@"
}
sql() { psql -X -w -h 127.0.0.1 -p "$port" -U chezhi_migrator -v ON_ERROR_STOP=1 "$@"; }
db_start() {
    if pg_ctl -D "$pg" status >/dev/null 2>&1; then return; fi
    pg_ctl -D "$pg" -l "$root/postgres.log" -w -t 30 start
}
db_stop() {
    if pg_ctl -D "$pg" status >/dev/null 2>&1; then
        pg_ctl -D "$pg" -w -t 30 -m fast stop
    fi
}
configured() {
    [ -d "$root" ] && [ ! -L "$root" ] && [ -f "$root/initialized" ] && [ ! -L "$root/initialized" ] || die 'Not initialized; do not reuse an incomplete directory.'
    [ "$(stat -c %a "$root")" = 700 ] || die 'Private staging directory must have mode 700.'
}
[ "$#" -ge 1 ] || die "Usage: init <binary> <SHA256> | run | status | stop-db | trust-info | backup"
case "$1" in
    init)
        [ "$#" -eq 3 ] || die 'Usage: init <reviewed ARM64 binary> <expected SHA256>'
        [ -f "$2" ] && [ ! -L "$2" ] || die 'Binary must be a regular file.'
        [[ "$3" =~ ^[0-9a-f]{64}$ ]] || die 'Expected lowercase SHA256.'
        [ "$(sha256sum "$2" | cut -d ' ' -f1)" = "$3" ] || die 'Binary digest mismatch.'
        [ -f "$here/../postgres_runtime_grants.sql" ] || die 'Missing reviewed runtime grants.'
        # Fresh path only; never overwrite existing credentials or database.
        mkdir -m 700 -- "$root" || die 'Existing staging path; inspect manually.'
        trap 'rm -f -- "$root/owner-once" "$root/init-password"' EXIT
        cp -- "$2" "$bin"
        chmod 700 "$bin"
        [ "$(sha256sum "$bin" | cut -d ' ' -f1)" = "$3" ] || die 'Copied binary digest mismatch.'
        printf '%s\n' "$3" > "$root/binary-sha256"
        admin="$(openssl rand -hex 32)"
        runtime_password="$(openssl rand -hex 32)"
        printf '%s\n' "$admin" > "$root/init-password"
        printf '127.0.0.1:%s:*:chezhi_migrator:%s\n' "$port" "$admin" > "$PGPASSFILE"
        printf 'postgres://chezhi_migrator:%s@127.0.0.1:%s/chezhi?sslmode=disable\n' "$admin" "$port" > "$root/migration-url"
        printf 'postgres://chezhi_runtime:%s@127.0.0.1:%s/chezhi?sslmode=disable\n' "$runtime_password" "$port" > "$root/runtime-url"
        initdb -D "$pg" -U chezhi_migrator --auth=scram-sha-256 --pwfile="$root/init-password" --encoding=UTF8 --no-locale
        rm -f -- "$root/init-password"
        printf "\nlisten_addresses = '127.0.0.1'\nport = %s\nunix_socket_directories = ''\npassword_encryption = 'scram-sha-256'\n" "$port" >> "$pg/postgresql.conf"
        db_start
        trap 'rm -f -- "$root/owner-once" "$root/init-password"; db_stop || true' EXIT
        sql -d postgres -c 'CREATE DATABASE chezhi'
        printf "CREATE ROLE chezhi_runtime LOGIN PASSWORD '%s';\n" "$runtime_password" | sql -d chezhi
        unset admin runtime_password
        migrate db-init
        sql -d chezhi -f "$here/../postgres_runtime_grants.sql"
        migrate db-set-mode chezhi server
        [ -t 0 ] || die "Use an interactive terminal for the supervisor password."
        read -r -s -p 'New supervisor password (14-128 UTF-8 bytes): ' owner
        printf '\n'
        printf '%s' "$owner" > "$root/owner-once"
        unset owner
        env -i PATH="$PATH" HOME="$HOME" CHEZHI_DATABASE_URL_FILE="$root/migration-url" \
            CHEZHI_OWNER_PASSWORD_FILE="$root/owner-once" "$bin" db-owner-init
        rm -f -- "$root/owner-once"
        public="$(migrate license-key-generate "$root/signing-key" | awk 'END {print $NF}')"
        [[ "$public" =~ ^[0-9a-f]{64}$ ]] || die 'Unexpected public signing key output.'
        migrate db-set-signing-key chezhi none "$public"
        openssl rand -hex 32 > "$root/csrf-key"
        openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj /CN=127.0.0.1 \
            -addext subjectAltName=IP:127.0.0.1 \
            -keyout "$root/tls-key" -out "$root/tls-cert"
        migrate db-check --migrator
        runtime db-check --runtime
        migrate db-signing-info
        db_stop
        printf '%s\n' 'loopback-staging-v1' > "$root/initialized"
        trap - EXIT
        printf 'Initialized. Run %s run to start the local HTTPS staging server.\n' "$0"
        ;;
    run)
        configured
        exec 9>"$root/service.lock"
        flock -n 9 || die 'Another managed service operation is active.'
        [ "$(sha256sum "$bin" | cut -d ' ' -f1)" = "$(cat "$root/binary-sha256")" ] || die 'Binary changed.'
        db_start 9>&-
        runtime db-check --runtime
        # Foreground process; use Ctrl-C to stop. Database remains up until stop-db.
        exec env -i PATH="$PATH" HOME="$HOME" \
            CHEZHI_MODE=server CHEZHI_LISTEN=127.0.0.1:18443 \
            CHEZHI_PUBLIC_ORIGIN="$origin" CHEZHI_DIAGNOSTICS=127.0.0.1:18444 \
            CHEZHI_DATABASE_URL_FILE="$root/runtime-url" CHEZHI_CSRF_KEY_FILE="$root/csrf-key" \
            CHEZHI_TLS_CERT="$root/tls-cert" CHEZHI_TLS_KEY="$root/tls-key" \
            CHEZHI_SIGNING_KEY_FILE="$root/signing-key" "$bin"
        ;;
    status)
        configured
        pg_ctl -D "$pg" status || true
        curl --noproxy '*' --fail --silent --show-error --max-time 5 --cacert "$root/tls-cert" "$origin/readyz"
        ;;
    stop-db)
        configured
        exec 9>"$root/service.lock"
        flock -n 9 || die 'Stop the foreground server first (Ctrl-C).'
        db_stop 9>&-
        ;;
    trust-info)
        configured
        migrate db-signing-info
        openssl x509 -in "$root/tls-cert" -noout -fingerprint -sha256
        ;;
    backup)
        configured
        mkdir -p -m 700 "$root/backups"
        # Never publish partial dumps or overwrite an existing backup.
        work="$(mktemp -d "$root/backups/backup.XXXXXXXX")"
        trap 'printf "Incomplete backup directory: %s\n" "$work" >&2' EXIT
        pg_dump -w -h 127.0.0.1 -p "$port" -U chezhi_migrator -d chezhi \
            -Fc --no-owner --no-acl -f "$work/database.partial"
        pg_restore --list "$work/database.partial" >/dev/null
        mv -- "$work/database.partial" "$work/database.dump"
        (cd "$work" && sha256sum database.dump > SHA256SUMS)
        printf '%s\n' 'logical database only; not restore-verified' > "$work/NOTICE"
        trap - EXIT
        printf 'Backup created: %s\n' "$work"
        ;;
    *)
        die 'Usage: init <binary> <SHA256> | run | status | stop-db | trust-info | backup'
        ;;
esac
