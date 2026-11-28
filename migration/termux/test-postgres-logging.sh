#!/usr/bin/env bash
# Dedicated disposable PG18 container, no published port or external network.
set -euo pipefail
umask 077
here="$(cd -- "$(dirname -- "$0")" && pwd -P)"
id="$(docker run -d --network none -e POSTGRES_PASSWORD=ci_ephemeral_only postgres:18.7-alpine)"
trap 'docker rm -f "$id" >/dev/null' EXIT
for i in $(seq 1 30); do
    if docker exec "$id" pg_isready -U postgres -d postgres >/dev/null 2>&1; then break; fi
    sleep 1
done
# Avoid racing the image's temporary initialization server.
docker exec "$id" sh -ec 'test "$(cat /proc/1/comm)" = postgres'
docker exec -i -u postgres "$id" sh -ec 'cat > "$PGDATA/chezhi-logging.conf"; printf "\ninclude = '\''chezhi-logging.conf'\''\n" >> "$PGDATA/postgresql.conf"' < "$here/postgres-logging.candidate.conf"
docker restart -t 15 "$id" >/dev/null
sql() { docker exec -u postgres "$id" psql -X -A -t -v ON_ERROR_STOP=1 -U postgres -d postgres -c "$1"; }
for i in $(seq 1 30); do
    if [ "$(sql 'SHOW logging_collector' 2>/dev/null || true)" = on ]; then break; fi
    sleep 1
done
[ "$(sql 'SHOW logging_collector')" = on ]
[ "$(sql 'SHOW log_rotation_size')" = 10MB ]
[ "$(sql 'SHOW log_statement')" = none ]
[ "$(sql 'SHOW log_parameter_max_length_on_error')" = 0 ]
before="$(sql "SELECT pg_postmaster_start_time()")"
first="$(sql 'SELECT pg_current_logfile()')"
[[ "$first" =~ ^chezhi-pg-log/postgresql-[0-9]{8}-[0-9]{6}\.log$ ]]
sleep 2
[ "$(sql 'SELECT pg_rotate_logfile()')" = t ]
for i in $(seq 1 20); do
    next="$(sql 'SELECT pg_current_logfile()')"
    [ "$next" != "$first" ] && break
    sleep 1
done
[ "$next" != "$first" ]
[[ "$next" =~ ^chezhi-pg-log/postgresql-[0-9]{8}-[0-9]{6}\.log$ ]]
[ "$(sql 'SELECT pg_postmaster_start_time()')" = "$before" ]
docker exec -u postgres "$id" sh -ec 'test -f "$PGDATA/$1"; test -f "$PGDATA/$2"; test "$(stat -c %a "$PGDATA/$2")" = 600' sh "$first" "$next"
[ "$(sql 'SELECT 1')" = 1 ]
printf 'PASS PG_LOG_ROTATION native collector, forced rotation, private files and unchanged postmaster\n'
