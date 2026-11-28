#!/usr/bin/env bash
# Foreground runit controller for the already initialized, loopback-only fixture.
# No installation into global Termux services, no tunnel and no implicit boot.
set -euo pipefail
umask 077
export LC_ALL=C
die() { printf '%s\n' "$*" >&2; exit 1; }
case "$HOME" in /data/data/com.termux/files/home|/data/user/0/com.termux/files/home) ;; *) die 'Use Termux private home.';; esac
root="$HOME/.chezhi-license-staging"
ctl="$root/managed-v1"
[ "$(uname -m)" = aarch64 ] || die 'ARM64 required.'
[ -d "$root" ] && [ ! -L "$root" ] && [ "$(stat -c %a "$root")" = 700 ] || die 'Invalid staging root.'
[ "$(cat "$root/initialized")" = loopback-staging-v1 ] || die 'Not initialized.'
for cmd in runsv sv svlogd flock timeout sha256sum openssl curl bash; do
    command -v "$cmd" >/dev/null || die "Missing dependency: $cmd"
done
here="$(cd -- "$(dirname -- "$0")" && pwd -P)"
[ "$#" -eq 1 ] || die 'Usage: install | start | stop | status | backup-now | boot-enable | boot-disable | boot-status | backup-loop | health-loop'
case "$1" in
    install)
        # Install into a new private directory, never overwrite a live controller.
        [ -f "$here/staging.sh" ] && [ -f "$here/managed-backup.sh" ] || die 'Incomplete reviewed candidate.'
        [ ! -e "$ctl" ] && [ ! -L "$ctl" ] || die 'Controller already exists; use existing controller.'
        mkdir -m 700 "$ctl"
        mkdir -m 700 "$ctl/code" "$ctl/service" "$ctl/backup" "$ctl/health" "$ctl/log-service" "$ctl/log-backup" "$ctl/log-health"
        cp -- "$here/staging.sh" "$here/supervisor.sh" "$here/managed-backup.sh" "$ctl/code/"
        chmod 700 "$ctl/code/"*.sh
        (cd "$ctl/code" && sha256sum staging.sh supervisor.sh managed-backup.sh > SHA256SUMS)
        for name in service backup health; do
            mkdir -m 700 "$ctl/$name/log"
            printf 's1048576\nn5\n' > "$ctl/log-$name/config"
            printf '#!%s\nexec svlogd -tt "%s"\n' "$(command -v bash)" "$ctl/log-$name" > "$ctl/$name/log/run"
            chmod 700 "$ctl/$name/log/run"
        done
        printf '#!%s\nexec 2>&1\nexec bash "%s" run\n' "$(command -v bash)" "$ctl/code/staging.sh" > "$ctl/service/run"
        printf '#!%s\nexec 2>&1\nexec bash "%s" backup-loop\n' "$(command -v bash)" "$ctl/code/supervisor.sh" > "$ctl/backup/run"
        printf '#!%s\nexec 2>&1\nexec bash "%s" health-loop\n' "$(command -v bash)" "$ctl/code/supervisor.sh" > "$ctl/health/run"
        # Fixed bounded restart delay. No unbounded tight failure loop.
        printf '#!%s\nsleep 10\n' "$(command -v bash)" > "$ctl/service/finish"
        chmod 700 "$ctl/service/run" "$ctl/service/finish" "$ctl/backup/run" "$ctl/health/run"
        printf 'managed-v1\n' > "$ctl/installed"
        printf 'Installed private controller. Stop the old foreground service before start.\n'
        exit 0
        ;;
esac
[ -d "$ctl" ] && [ ! -L "$ctl" ] && [ -f "$ctl/installed" ] || die 'Controller not installed.'
[ "$(cat "$ctl/installed")" = managed-v1 ] || die 'Invalid controller marker.'
(cd "$ctl/code" && sha256sum -c --status SHA256SUMS) || die 'Controller scripts changed.'
staging="$ctl/code/staging.sh"
backup="$ctl/code/managed-backup.sh"
boot_entry() {
    # Termux:Boot can start with a minimal environment. Use the installed
    # Termux Bash directory rather than relying on an interactive PATH.
    local bash_path
    bash_path="$(command -v bash)"
    printf '#!%s\n' "$bash_path"
    printf 'umask 077\nexport PATH="%s:/system/bin"\n' "$(dirname -- "$bash_path")"
    printf 'cd "%s" || exit 1\n' "$HOME"
    printf 'printf "BOOT_ENTRY_STARTED %%s\\n" "$(date -u +%%FT%%TZ)" > "%s/boot-attempt"\n' "$ctl"
    printf 'exec "%s" "%s/code/supervisor.sh" start\n' "$bash_path" "$ctl"
}
case "$1" in
    start)
        exec 8>"$ctl/controller.lock"
        flock -n 8 || die 'Controller already running.'
        # Refuse to adopt a live manual service. The staging script still
        # owns the actual exclusive service lock for each child lifetime.
        (flock -n 9 || die 'Stop the existing foreground service first.') 9>"$root/service.lock"
        rm -f -- "$ctl/stop-requested"
        main_pid='' backup_pid='' health_pid=''
        cleanup() {
            trap '' INT TERM HUP
            printf 'requested\n' > "$ctl/stop-requested"
            if [ -n "$health_pid" ]; then sv -w 35 exit "$ctl/health" >/dev/null 2>&1 || true; fi
            # Only control runsv instances launched from this private tree.
            if [ -n "$backup_pid" ]; then sv -w 35 exit "$ctl/backup" >/dev/null 2>&1 || true; fi
            if [ -n "$main_pid" ]; then sv -w 45 exit "$ctl/service" >/dev/null 2>&1 || true; fi
            if [ -n "$health_pid" ]; then wait "$health_pid" || true; fi
            if [ -n "$backup_pid" ]; then wait "$backup_pid" || true; fi
            if [ -n "$main_pid" ]; then wait "$main_pid" || true; fi
        }
        trap cleanup EXIT
        trap 'exit 0' INT TERM HUP
        runsv "$ctl/service" 8>&- & main_pid=$!
        runsv "$ctl/backup" 8>&- & backup_pid=$!
        runsv "$ctl/health" 8>&- & health_pid=$!
        # Exit if any supervisor itself dies; its service child may still
        # own the staging lock. Never kill an unrelated PID or restart over it.
        wait -n "$main_pid" "$backup_pid" "$health_pid" || true
        if [ -f "$ctl/stop-requested" ]; then exit 0; fi
        die 'A runsv supervisor exited; inspect controller status before restarting.'
        ;;
    stop)
        # Serialize shutdown with health-triggered restart requests.
        (
            flock -w 10 7 || die 'Health/control operation busy.'
            printf 'requested\n' > "$ctl/stop-requested"
            sv -w 35 down "$ctl/health"
            sv -w 35 down "$ctl/backup"
            sv -w 45 down "$ctl/service"
            sv -w 35 exit "$ctl/backup"
        ) 7>"$ctl/control.lock"
        # The controller owns the remaining supervisor and shutdown sequence.
        (flock -w 60 8 || die 'Controller shutdown incomplete; inspect status.') 8>"$ctl/controller.lock"
        printf 'Managed services stopped; PostgreSQL remains up. Use staging.sh stop-db if desired.\n'
        ;;
    status)
        sv status "$ctl/service" "$ctl/backup" "$ctl/health" || true
        bash "$staging" status
        if openssl x509 -in "$root/tls-cert" -noout -checkend 604800 >/dev/null; then
            printf 'TLS certificate: more than seven days remaining\n'
        else
            printf 'WARNING: TLS certificate expires within seven days or is invalid\n' >&2
        fi
        ;;
    backup-now)
        exec bash "$backup"
        ;;
    backup-loop)
        child=''
        stop_loop() {
            trap '' TERM INT HUP
            if [ -n "$child" ]; then kill -TERM "$child" 2>/dev/null || true; wait "$child" || true; fi
            exit 0
        }
        trap stop_loop TERM INT HUP
        waiting=0
        while true; do
            [ ! -f "$ctl/stop-requested" ] || exit 0
            # Startup and transient outages must not consume a daily slot.
            # Poll readiness first, using the actual trusted origin.
            if ! curl --noproxy '*' --fail --silent --show-error --max-time 5 \
                --cacert "$root/tls-cert" https://127.0.0.1:18443/readyz >/dev/null 2>&1; then
                if [ "$waiting" -eq 0 ]; then printf 'BACKUP_WAIT_READY\n'; fi
                waiting=1
                delay=5
            else
                if [ "$waiting" -eq 1 ]; then printf 'BACKUP_READY\n'; fi
                waiting=0
                timeout -k 5s 20m bash "$backup" & child=$!
                if wait "$child"; then
                    delay=900
                else
                    printf 'BACKUP_RETRY failure; retry in 60 seconds.\n' >&2
                    delay=60
                fi
                child=''
            fi
            sleep "$delay" & child=$!
            wait "$child" || true
            child=''
        done
        ;;
    health-loop)
        # Do not use pid files, kill arbitrary PIDs, or bypass TLS. A TERM
        # request goes only to the runit-owned child. Never force-kill it.
        trap 'exit 0' TERM INT HUP
        failures=0
        cooldown=0
        while true; do
            [ ! -f "$ctl/stop-requested" ] || exit 0
            if [ "$cooldown" -gt 0 ]; then cooldown=$((cooldown - 1)); fi
            if curl --noproxy '*' --fail --silent --show-error --max-time 5 \
                --cacert "$root/tls-cert" https://127.0.0.1:18443/readyz >/dev/null 2>&1; then
                failures=0
            else
                failures=$((failures + 1))
                if [ "$failures" -ge 4 ] && [ "$cooldown" -eq 0 ]; then
                    failures=0
                    cooldown=8
                    (
                        flock -n 7 || exit 0
                        [ ! -f "$ctl/stop-requested" ] || exit 0
                        # Do not loop on certificate expiry or trust errors.
                        if ! openssl verify -CAfile "$root/tls-cert" -verify_ip 127.0.0.1 "$root/tls-cert" >/dev/null 2>&1; then
                            printf 'HEALTH_HOLD invalid local TLS certificate; operator action required\n' >&2
                            exit 0
                        fi
                        state="$(sv status "$ctl/service" 2>/dev/null)" || exit 0
                        case "$state" in
                            'run: '*)
                                printf 'HEALTH_RECOVERY_REQUEST readiness failed four times; requesting TERM from runit\n' >&2
                                sv term "$ctl/service" || printf 'HEALTH_HOLD TERM request failed\n' >&2
                                ;;
                            *) printf 'HEALTH_HOLD service not running; leave existing runit recovery in control\n' >&2;;
                        esac
                    ) 7>"$ctl/control.lock"
                fi
            fi
            sleep 15
        done
        ;;
    boot-enable)
        # Explicit operator opt-in. Termux:Boot must have been opened once.
        boot="$HOME/.termux/boot"
        mkdir -p -m 700 "$boot"
        [ -d "$boot" ] && [ ! -L "$boot" ] || die 'Invalid boot directory.'
        file="$boot/90-chezhi-staging"
        (set -o noclobber; boot_entry > "$file") || die 'Boot entry already exists.'
        chmod 700 "$file"
        printf 'Boot entry installed. No wake lock acquired; actual reboot must be tested.\n'
        ;;
    boot-disable)
        file="$HOME/.termux/boot/90-chezhi-staging"
        [ -f "$file" ] && [ ! -L "$file" ] || die 'No managed boot entry.'
        expected="$(boot_entry)"
        [ "$(cat "$file")" = "$expected" ] || die 'Boot entry differs; inspect manually.'
        rm -- "$file"
        ;;
    boot-status)
        file="$HOME/.termux/boot/90-chezhi-staging"
        if [ -f "$file" ] && [ ! -L "$file" ] && [ "$(cat "$file")" = "$(boot_entry)" ]; then
            printf 'BOOT_ENTRY_INSTALLED\n'
        else
            printf 'BOOT_ENTRY_ABSENT_OR_DIFFERENT\n'
        fi
        if [ -f "$ctl/boot-attempt" ] && [ ! -L "$ctl/boot-attempt" ]; then
            cat "$ctl/boot-attempt"
        else
            printf 'BOOT_ENTRY_NOT_OBSERVED\n'
        fi
        ;;
    *) die 'Unknown controller command.';;
esac
