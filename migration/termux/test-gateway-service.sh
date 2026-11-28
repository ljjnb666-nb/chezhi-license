#!/usr/bin/env bash
# Linux CI: real runit and svlogd, isolated fake gateway, no phone/network.
set -euo pipefail
umask 077
src="$(cd -- "$(dirname -- "$0")" && pwd -P)"
tmp="$(mktemp -d)"
export HOME="$tmp/home"
mkdir -m 700 "$HOME" "$HOME/.chezhi-license-staging" "$tmp/package"
ctl="$HOME/.chezhi-gateway-local-v1"
parent=''
cleanup() {
    if [ -n "$parent" ]; then
        bash "$tmp/package/gateway-service.sh" stop >/dev/null 2>&1 || true
        wait "$parent" || true
    fi
    rm -rf -- "$tmp"
}
trap cleanup EXIT
sed -e '/^case "$HOME" in /c\:' -e '/^\[ "$(uname -m)" = aarch64 \]/c\:' "$src/gateway-service.sh" > "$tmp/package/gateway-service.sh"
cat > "$tmp/package/chezhi-gateway-android-arm64" <<'FIXTURE'
#!/bin/bash
set -euo pipefail
[ "$CHEZHI_GATEWAY_HOST" = license.example.invalid ]
[ -z "${DATABASE_URL:-}" ] && [ -z "${TUNNEL_TOKEN:-}" ]
printf '%s\n' "$$" > "$HOME/fixture-pid"
for i in $(seq 1 250); do printf 'synthetic log line %s: fixed fixture no secrets\n' "$i"; done
exec sleep 600
FIXTURE
(cd "$tmp/package" && sha256sum chezhi-gateway-android-arm64 gateway-service.sh > SHA256SUMS)
export DATABASE_URL=forbidden-fixture TUNNEL_TOKEN=forbidden-fixture
printf 'preserve M4 fixture\n' > "$HOME/.chezhi-license-staging/tls-cert"
before="$(sha256sum "$HOME/.chezhi-license-staging/tls-cert")"
ctlcmd() { bash "$tmp/package/gateway-service.sh" "$@"; }
ctlcmd install
if ctlcmd install; then echo 'duplicate install accepted'; exit 1; fi
if ctlcmd start; then echo 'missing credentials accepted'; exit 1; fi
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj /CN=127.0.0.1 \
    -addext subjectAltName=IP:127.0.0.1 -keyout "$ctl/credentials/tls-key" \
    -out "$ctl/credentials/tls-cert" 2>/dev/null
chmod 600 "$ctl/credentials/"*
# Scale down the rotation threshold only in the disposable fixture.
printf 's4096\nn2\n' > "$ctl/log/config"
ctlcmd start & parent=$!
for i in $(seq 1 20); do [ -s "$HOME/fixture-pid" ] && break; sleep 1; done
old="$(cat "$HOME/fixture-pid")"
ctlcmd status | grep -q 'run: '
if ctlcmd start; then echo 'duplicate controller accepted'; exit 1; fi
sv term "$ctl/service"
for i in $(seq 1 30); do
    new="$(cat "$HOME/fixture-pid")"
    [ "$old" != "$new" ] && break
    sleep 1
done
[ "$old" != "$new" ]
ctlcmd status | grep -q 'run: '
for i in $(seq 1 10); do
    count="$(find "$ctl/log" -maxdepth 1 -name '@*' -type f | wc -l)"
    [ "$count" -ge 1 ] && [ "$count" -le 2 ] && break
    sleep 1
done
[ "$count" -ge 1 ] && [ "$count" -le 2 ]
ctlcmd stop
wait "$parent"
parent=''
ctlcmd stop
sleep 2
[ "$(cat "$HOME/fixture-pid")" = "$new" ]
if ctlcmd status; then echo 'supervisor still present'; exit 1; fi
[ "$(sha256sum "$HOME/.chezhi-license-staging/tls-cert")" = "$before" ]
[ ! -e "$HOME/.termux" ]
printf 'tamper\n' >> "$ctl/code/chezhi-gateway-android-arm64"
if ctlcmd start; then echo 'tampered code accepted'; exit 1; fi
printf 'PASS GATEWAY_SERVICE isolated runit restart, rotation, duplicate denial, controlled stop, M4 preservation and tamper refusal\n'
