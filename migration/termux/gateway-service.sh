#!/usr/bin/env bash
# Opt-in local-only gateway controller. Never modifies the M4 tree.
set -euo pipefail
umask 077
export LC_ALL=C
die() { printf '%s\n' "$*" >&2; exit 1; }
case "$HOME" in /data/data/com.termux/files/home|/data/user/0/com.termux/files/home) ;; *) die 'Use Termux private home.';; esac
[ "$(uname -m)" = aarch64 ] || die 'ARM64 required.'
ctl="$HOME/.chezhi-gateway-local-v2"
origin_cert="$HOME/.chezhi-license-staging/tls-cert"
for cmd in bash runsv sv svlogd flock sha256sum stat openssl env; do
    command -v "$cmd" >/dev/null || die "Missing dependency: $cmd"
done
here="$(cd -- "$(dirname -- "$0")" && pwd -P)"
[ "$#" -eq 1 ] || die 'Usage: install | start | stop | status | run'
private_dir() {
    [ -d "$1" ] && [ ! -L "$1" ] && [ "$(stat -c %a "$1")" = 700 ]
}
private_file() {
    [ -f "$1" ] && [ ! -L "$1" ] && [ "$(stat -c %a "$1")" = 600 ]
}
if [ "$1" = install ]; then
    [ ! -e "$ctl" ] && [ ! -L "$ctl" ] || die 'Local controller already exists; do not overwrite.'
    # Check only the exact expected files; never interpret arbitrary manifest paths.
    for name in chezhi-gateway-android-arm64 gateway-service.sh; do
        [ -f "$here/$name" ] && [ ! -L "$here/$name" ] || die 'Incomplete candidate.'
        (cd "$here" && sha256sum "$name") | grep -Fxq -f - "$here/SHA256SUMS" || die 'Candidate hash mismatch.'
    done
    mkdir -m 700 "$ctl"
    mkdir -m 700 "$ctl/code" "$ctl/credentials" "$ctl/service" "$ctl/service/log" "$ctl/log"
    cp -- "$here/chezhi-gateway-android-arm64" "$here/gateway-service.sh" "$ctl/code/"
    chmod 700 "$ctl/code/chezhi-gateway-android-arm64" "$ctl/code/gateway-service.sh"
    (cd "$ctl/code" && sha256sum chezhi-gateway-android-arm64 gateway-service.sh > SHA256SUMS)
    bash_path="$(command -v bash)"
    printf '#!%s\nexec 9>&-\nexec 2>&1\nexec "%s" "%s/code/gateway-service.sh" run\n' "$bash_path" "$bash_path" "$ctl" > "$ctl/service/run"
    printf '#!%s\nexec 9>&-\nsleep 10\n' "$bash_path" > "$ctl/service/finish"
    printf '#!%s\nexec 9>&-\nexec svlogd -tt "%s/log"\n' "$bash_path" "$ctl" > "$ctl/service/log/run"
    chmod 700 "$ctl/service/run" "$ctl/service/finish" "$ctl/service/log/run"
    printf 's1048576\nn5\n' > "$ctl/log/config"
    printf 'gateway-local-v2\n' > "$ctl/installed"
    printf '%s\n' 'Installed local-only controller. Provision independent test TLS cert/key (0600) in credentials before explicit foreground start.'
    exit 0
fi
private_dir "$ctl" && private_dir "$ctl/code" && private_dir "$ctl/credentials" && private_dir "$ctl/service" && private_dir "$ctl/service/log" && private_dir "$ctl/log" || die 'Invalid private controller tree.'
[ -f "$ctl/installed" ] && [ ! -L "$ctl/installed" ] && [ "$(cat "$ctl/installed")" = gateway-local-v2 ] || die 'Controller not installed.'
verify_code() {
    for name in chezhi-gateway-android-arm64 gateway-service.sh; do
        [ -f "$ctl/code/$name" ] && [ ! -L "$ctl/code/$name" ] || die 'Invalid controller code.'
        (cd "$ctl/code" && sha256sum "$name") | grep -Fxq -f - "$ctl/code/SHA256SUMS" || die 'Controller code changed.'
    done
}
verify_credentials() {
    private_file "$ctl/credentials/tls-cert" && private_file "$ctl/credentials/tls-key" || die 'Missing private gateway TLS files.'
    [ -f "$origin_cert" ] && [ ! -L "$origin_cert" ] || die 'Missing M4 origin certificate.'
    openssl verify -CAfile "$ctl/credentials/tls-cert" -verify_ip 127.0.0.1 "$ctl/credentials/tls-cert" >/dev/null 2>&1 || die 'Invalid gateway TLS certificate.'
}
# Separate controller and service leases; do not guess orphan PIDs.
for lock in operation controller service; do
    file="$ctl/$lock.lock"
    [ ! -L "$file" ] && { [ ! -e "$file" ] || [ -f "$file" ]; } || die 'Invalid lease file.'
done
lease_free() { flock -n "$ctl/$1.lock" true; }
case "$1" in
    start)
        # Both versions use the same fixed loopback port. Never start V2
        # alongside a possibly active V1 tree; operator must review it.
        legacy="$HOME/.chezhi-gateway-local-v1"
        [ ! -e "$legacy" ] && [ ! -L "$legacy" ] || die 'Legacy controller tree present; reviewed maintenance required.'
        verify_code
        verify_credentials
        # The runsv process itself inherits FD 9, not a flock parent.
        exec 7>"$ctl/operation.lock"
        flock -w 10 7 || die 'Controller operation busy.'
        exec 9>"$ctl/controller.lock"
        flock -n 9 || die 'Controller already running.'
        lease_free service || die 'Orphan gateway service lease held; inspect manually.'
        if sv status "$ctl/service" >/dev/null 2>&1; then
            die 'Unexpected native supervisor; inspect manually.'
        fi
        exec 7>&-
        exec runsv "$ctl/service"
        ;;
    stop)
        exec 7>"$ctl/operation.lock"
        flock -w 10 7 || die 'Controller operation busy.'
        # A concurrent start may not have created its control FIFO yet.
        for attempt in $(seq 1 10); do
            if lease_free controller; then
                lease_free service || die 'Orphan gateway service lease held; inspect manually.'
                if sv status "$ctl/service" >/dev/null 2>&1; then
                    die 'Native supervisor without controller lease; inspect manually.'
                fi
                printf 'Gateway controller already stopped.\n'
                exit 0
            fi
            if sv status "$ctl/service" >/dev/null 2>&1; then break; fi
            sleep 1
        done
        sv -w 45 exit "$ctl/service" || die 'Gateway shutdown incomplete; inspect status.'
        flock -w 10 "$ctl/controller.lock" true || die 'Gateway controller still running.'
        lease_free service || die 'Gateway service lease remains held; inspect manually.'
        printf 'Gateway controller stopped; original M4 services untouched.\n'
        ;;
    status)
        sv status "$ctl/service"
        ;;
    run)
        verify_code
        verify_credentials
        if lease_free controller; then die 'No foreground controller lease.'; fi
        exec 8>"$ctl/service.lock"
        flock -n 8 || die 'Gateway service already running.'
        # Keep FD 8 through exec for the actual service lifetime.
        # Fixed local test hostname, sanitized process environment. No
        # signing key, database credentials, tunnel token or public host.
        exec env -i HOME="$HOME" PATH="$PATH" \
            CHEZHI_GATEWAY_HOST=license.example.invalid \
            CHEZHI_GATEWAY_ORIGIN_CA="$origin_cert" \
            CHEZHI_GATEWAY_TLS_CERT="$ctl/credentials/tls-cert" \
            CHEZHI_GATEWAY_TLS_KEY="$ctl/credentials/tls-key" \
            "$ctl/code/chezhi-gateway-android-arm64"
        ;;
    *) die 'Unknown controller command.';;
esac
