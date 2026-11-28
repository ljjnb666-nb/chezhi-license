#!/usr/bin/env bash
# Linux CI: real runit and svlogd, isolated fake gateway, no phone/network.
set -euo pipefail
umask 077
src="$(cd -- "$(dirname -- "$0")" && pwd -P)"
tmp="$(mktemp -d)"
export HOME="$tmp/home"
mkdir -m 700 "$HOME" "$HOME/.chezhi-license-staging" "$tmp/package"
ctl="$HOME/.chezhi-gateway-local-v2"
parent=''
orphan=''
cleanup() {
    if [ -n "$orphan" ]; then kill "$orphan" 2>/dev/null || true; wait "$orphan" || true; fi
    if [ -n "$parent" ]; then
        bash "$tmp/package/gateway-service.sh" stop >/dev/null 2>&1 || true
        for i in $(seq 1 10); do kill -0 "$parent" 2>/dev/null || break; sleep 1; done
        # The PID was created by this disposable test, never discovered on a device.
        kill "$parent" 2>/dev/null || true
        if ! kill -0 "$parent" 2>/dev/null; then wait "$parent" || true; fi
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
mkdir "$HOME/.chezhi-gateway-local-v1"
if ctlcmd start; then echo 'legacy coexistence accepted'; exit 1; fi
rmdir "$HOME/.chezhi-gateway-local-v1"
if ctlcmd run; then echo 'direct run without controller accepted'; exit 1; fi
# Simulate a surviving service with an independently held lifetime lease.
bash -c 'exec 8>"$1"; flock -n 8; touch "$2"; exec sleep 60' _ "$ctl/service.lock" "$tmp/orphan-ready" & orphan=$!
for i in $(seq 1 10); do [ -f "$tmp/orphan-ready" ] && break; sleep 1; done
test -f "$tmp/orphan-ready"
if ctlcmd start; then echo 'orphan service start accepted'; exit 1; fi
if ctlcmd stop; then echo 'orphan service reported stopped'; exit 1; fi
kill "$orphan"; wait "$orphan" || true; orphan=''
# A surviving logger is independently fenced even when no service lives.
rm -f "$tmp/orphan-ready"
bash -c 'exec 6>"$1"; flock -n 6; touch "$2"; exec sleep 60' _ "$ctl/logger.lock" "$tmp/orphan-ready" & orphan=$!
for i in $(seq 1 10); do [ -f "$tmp/orphan-ready" ] && break; sleep 1; done
test -f "$tmp/orphan-ready"
if ctlcmd start; then echo 'orphan logger start accepted'; exit 1; fi
if ctlcmd stop; then echo 'orphan logger reported stopped'; exit 1; fi
kill "$orphan"; wait "$orphan" || true; orphan=''
bash "$tmp/package/gateway-service.sh" start & parent=$!
for i in $(seq 1 20); do [ -s "$HOME/fixture-pid" ] && break; sleep 1; done
old="$(cat "$HOME/fixture-pid")"
[ "$(cat "/proc/$parent/comm")" = runsv ]
if flock -n "$ctl/controller.lock" true; then echo 'runsv did not retain controller lease'; exit 1; fi
if flock -n "$ctl/service.lock" true; then echo 'gateway did not retain service lease'; exit 1; fi
if flock -n "$ctl/logger.lock" true; then echo 'logger did not retain logger lease'; exit 1; fi
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
# Two stop callers must serialize and both report a safe stop.
ctlcmd stop & stop_a=$!
ctlcmd stop & stop_b=$!
# Preserve both outcomes; a timeout is a failure, not a successful stop.
status_a=0; status_b=0
wait "$stop_a" || status_a=$?
wait "$stop_b" || status_b=$?
printf 'GATEWAY_CONCURRENT_STOP first=%s second=%s\n' "$status_a" "$status_b"
[ "$status_a" -eq 0 ] && [ "$status_b" -eq 0 ]
wait "$parent"
parent=''
flock -n "$ctl/controller.lock" true
flock -n "$ctl/service.lock" true
flock -n "$ctl/logger.lock" true
ctlcmd stop
sleep 2
[ "$(cat "$HOME/fixture-pid")" = "$new" ]
if ctlcmd status; then echo 'supervisor still present'; exit 1; fi
[ "$(sha256sum "$HOME/.chezhi-license-staging/tls-cert")" = "$before" ]
[ ! -e "$HOME/.termux" ]
# Stop immediately after the start lease is acquired, before requiring
# gateway readiness; no newer start may race the shutdown.
bash "$tmp/package/gateway-service.sh" start & parent=$!
for i in $(seq 1 100); do
    if ! flock -n "$ctl/controller.lock" true; then break; fi
    sleep 0.05
done
if flock -n "$ctl/controller.lock" true; then echo 'start lease not observed'; exit 1; fi
ctlcmd stop
wait "$parent"
parent=''
flock -n "$ctl/controller.lock" true
flock -n "$ctl/service.lock" true
flock -n "$ctl/logger.lock" true
printf 'tamper\n' >> "$ctl/code/chezhi-gateway-android-arm64"
if ctlcmd start; then echo 'tampered code accepted'; exit 1; fi
printf 'PASS GATEWAY_SERVICE isolated runit restart, rotation, duplicate denial, controlled stop, direct ownership, simulated orphan hold, concurrent stop, startup stop, M4 preservation and tamper refusal\n'
