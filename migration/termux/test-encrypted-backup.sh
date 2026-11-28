#!/usr/bin/env bash
# Real age and PG18 dump/restore, isolated synthetic data only.
set -euo pipefail
umask 077
src="$(cd -- "$(dirname -- "$0")" && pwd -P)"
tmp="$(mktemp -d)"
id=''
cleanup() {
    if [ -n "$id" ]; then docker rm -f "$id" >/dev/null || true; fi
    rm -rf -- "$tmp"
}
trap cleanup EXIT
export HOME="$tmp/home"
mkdir -m 700 "$HOME" "$HOME/.chezhi-license-staging" "$tmp/receiver" "$tmp/bin"
root="$HOME/.chezhi-license-staging"
daily="$root/managed-daily"
day=2026-11-28
mkdir -m 700 "$daily" "$daily/$day"
printf 'loopback-staging-v1\n' > "$root/initialized"
touch "$daily/backup.lock"
id="$(docker run -d --network none -e POSTGRES_PASSWORD=ci_ephemeral_only postgres:18.7-alpine)"
for i in $(seq 1 30); do
    if docker exec "$id" sh -ec 'test "$(cat /proc/1/comm)" = postgres && pg_isready -U postgres -d postgres' >/dev/null 2>&1; then break; fi
    sleep 1
done
sql() { docker exec -u postgres "$id" psql -X -At -v ON_ERROR_STOP=1 -U postgres -d "$1" -c "$2"; }
sql postgres 'CREATE DATABASE source_fixture'
sql postgres 'CREATE DATABASE restored_fixture'
sql source_fixture "CREATE TABLE fixture (id integer PRIMARY KEY, value text); INSERT INTO fixture VALUES (1,'synthetic-only'),(2,'revoked-fixture');"
docker exec -u postgres "$id" pg_dump -U postgres -d source_fixture -Fc --no-owner --no-acl > "$daily/$day/database.dump"
(cd "$daily/$day" && sha256sum database.dump > SHA256SUMS)
printf '%s\n' 'managed daily logical backup; not restore-verified' > "$daily/$day/NOTICE"
before="$(sha256sum "$daily/$day/database.dump")"
# Use the same native PG18 pg_restore for full decode on the test runner.
# Only the two reviewed offline operations are supported by this fixture.
export FIXTURE_PG_CONTAINER="$id"
cat > "$tmp/bin/pg_restore" <<'FIXTURE'
#!/bin/bash
set -euo pipefail
case "$1" in
    --list) [ "$#" -eq 2 ]; exec docker exec -i -u postgres "$FIXTURE_PG_CONTAINER" pg_restore --list < "$2";;
    -f) [ "$#" -eq 3 ] && [ "$2" = /dev/null ]; exec docker exec -i -u postgres "$FIXTURE_PG_CONTAINER" pg_restore -f /dev/null < "$3";;
    *) exit 1;;
esac
FIXTURE
chmod 700 "$tmp/bin/pg_restore"
export PATH="$tmp/bin:$PATH"
sed -e '/^case "$HOME" in /c\:' -e '/^\[ "$(uname -m)" = aarch64 \]/c\:' "$src/encrypted-export.sh" > "$tmp/export.sh"
age-keygen -o "$tmp/receiver/identity" 2>/dev/null
age-keygen -o "$tmp/receiver/wrong-identity" 2>/dev/null
chmod 600 "$tmp/receiver/"*identity
recipient="$(age-keygen -y "$tmp/receiver/identity")"
# Locked backup cannot be copied or raced against retention.
(
    flock -x 9
    if bash "$tmp/export.sh" "$day" "$recipient" 9>&-; then echo 'locked archive accepted'; exit 1; fi
) 9<"$daily/backup.lock"
bash "$tmp/export.sh" "$day" "$recipient"
exported="$HOME/.chezhi-encrypted-exports/$day"
test -f "$exported/database.dump.age"
test ! -e "$exported/database.dump"
if bash "$tmp/export.sh" "$day" "$recipient"; then echo 'overwrite accepted'; exit 1; fi
trusted="$(sha256sum "$exported/database.dump.age" | cut -d ' ' -f1)"
receive() { bash "$src/encrypted-receive.sh" "$@" "$trusted"; }
if bash "$src/encrypted-receive.sh" "$exported" "$tmp/receiver/identity" "$tmp/receiver/missing"; then echo 'missing trusted digest accepted'; exit 1; fi
if receive "$exported" "$tmp/receiver/wrong-identity" "$tmp/receiver/wrong"; then echo 'wrong identity accepted'; exit 1; fi
test ! -e "$tmp/receiver/wrong"
cp -a "$exported" "$tmp/receiver/tampered"
printf 'tamper' >> "$tmp/receiver/tampered/database.dump.age"
if receive "$tmp/receiver/tampered" "$tmp/receiver/identity" "$tmp/receiver/bad-hash"; then echo 'tamper accepted'; exit 1; fi
(cd "$tmp/receiver/tampered" && sha256sum database.dump.age > SHA256SUMS)
if receive "$tmp/receiver/tampered" "$tmp/receiver/identity" "$tmp/receiver/bad-auth"; then echo 'tamper with rewritten hash accepted'; exit 1; fi
test ! -e "$tmp/receiver/bad-hash" && test ! -e "$tmp/receiver/bad-auth"
# Even a valid new age ciphertext for this recipient must not replace the
# independently authenticated original. Separately test AEAD rejection
# with a trusted digest deliberately set to the damaged ciphertext.
damaged="$(sha256sum "$tmp/receiver/tampered/database.dump.age" | cut -d ' ' -f1)"
if bash "$src/encrypted-receive.sh" "$tmp/receiver/tampered" "$tmp/receiver/identity" "$tmp/receiver/bad-aead" "$damaged"; then echo 'damaged authenticated stream accepted'; exit 1; fi
cp -a "$exported" "$tmp/receiver/substitute"
rm -- "$tmp/receiver/substitute/database.dump.age"
age -r "$recipient" -o "$tmp/receiver/substitute/database.dump.age" "$daily/$day/database.dump"
(cd "$tmp/receiver/substitute" && sha256sum database.dump.age > SHA256SUMS)
if receive "$tmp/receiver/substitute" "$tmp/receiver/identity" "$tmp/receiver/bad-sender"; then echo 'substituted valid ciphertext accepted'; exit 1; fi
test ! -e "$tmp/receiver/bad-aead" && test ! -e "$tmp/receiver/bad-sender"
receive "$exported" "$tmp/receiver/identity" "$tmp/receiver/recovered"
test "$(sha256sum "$tmp/receiver/recovered/database.dump" | cut -d ' ' -f1)" = "$(printf '%s\n' "$before" | cut -d ' ' -f1)"
if receive "$exported" "$tmp/receiver/identity" "$tmp/receiver/recovered"; then echo 'receiver overwrite accepted'; exit 1; fi
docker exec -i -u postgres "$id" pg_restore -U postgres -d restored_fixture --exit-on-error --single-transaction --no-owner --no-acl < "$tmp/receiver/recovered/database.dump"
test "$(sql source_fixture 'SELECT id,value FROM fixture ORDER BY id')" = "$(sql restored_fixture 'SELECT id,value FROM fixture ORDER BY id')"
test "$(sha256sum "$daily/$day/database.dump")" = "$before"
test -z "$(find "$tmp/receiver" -maxdepth 1 -name '.receive.*' -print -quit)"
printf 'PASS ENCRYPTED_BACKUP real age, PG18 restore, wrong identity/tamper/overwrite denial and unchanged source\n'
