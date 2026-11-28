#!/usr/bin/env bash
# Opt-in local-only gateway controller. Never modifies the M4 tree.
set -euo pipefail
umask 077
export LC_ALL=C
die() { printf '%s\n' "$*" >&2; exit 1; }
case "$HOME" in /data/data/com.termux/files/home|/data/user/0/com.termux/files/home) ;; *) die 'Use Termux private home.';; esac
[ "$(uname -m)" = aarch64 ] || die 'ARM64 required.'
ctl="$HOME/.chezhi-gateway-local-v1"
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
    printf '#!%s\nexec 2>&1\nexec "%s" "%s/code/gateway-service.sh" run\n' "$bash_path" "$bash_path" "$ctl" > "$ctl/service/run"
    printf '#!%s\nsleep 10\n' "$bash_path" > "$ctl/service/finish"
    printf '#!%s\nexec svlogd -tt "%s/log"\n' "$bash_path" "$ctl" > "$ctl/service/log/run"
    chmod 700 "$ctl/service/run" "$ctl/service/finish" "$ctl/service/log/run"
    printf 's1048576\nn5\n' > "$ctl/log/config"
    printf 'gateway-local-v1\n' > "$ctl/installed"
    printf '%s\n' 'Installed local-only controller. Provision independent test TLS cert/key (0600) in credentials before explicit foreground start.'
    exit 0
fi
private_dir "$ctl" && private_dir "$ctl/code" && private_dir "$ctl/credentials" && private_dir "$ctl/service" && private_dir "$ctl/service/log" && private_dir "$ctl/log" || die 'Invalid private controller tree.'
[ -f "$ctl/installed" ] && [ ! -L "$ctl/installed" ] && [ "$(cat "$ctl/installed")" = gateway-local-v1 ] || die 'Controller not installed.'
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
case "$1" in
    start)
        verify_code
        verify_credentials
        # Lock held by the flock parent, not inherited by runsv or service.
        # runsv also owns its native supervise lock. Foreground only.
        exec flock -n --close "$ctl/controller.lock" runsv "$ctl/service"
        ;;
    stop)
        # Only the runit control FIFO in this private tree. No PID scanning.
        # If already stopped, report without touching another process.
        if flock -n "$ctl/controller.lock" true; then
            if sv status "$ctl/service" >/dev/null 2>&1; then
                die 'Supervisor present without controller lock; inspect manually.'
            fi
            printf 'Gateway controller already stopped.\n'
            exit 0
        fi
        sv -w 45 exit "$ctl/service" || die 'Gateway shutdown incomplete; inspect status.'
        flock -w 10 "$ctl/controller.lock" true || die 'Gateway controller still running.'
        printf 'Gateway controller stopped; original M4 services untouched.\n'
        ;;
    status)
        sv status "$ctl/service"
        ;;
    run)
        verify_code
        verify_credentials
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
