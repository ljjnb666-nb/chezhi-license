#!/usr/bin/env bash
# Foreground runit controller for the already initialized, loopback-only fixture.
# No installation into global Termux services, no tunnel and no implicit boot.
set -euo pipefail
umask 077
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
[ "$#" -eq 1 ] || die 'Usage: install | start | stop | status | backup-now | boot-enable | boot-disable | backup-loop'
case "$1" in
    install)
        # Install into a new private directory, never overwrite a live controller.
        [ -f "$here/staging.sh" ] && [ -f "$here/managed-backup.sh" ] || die 'Incomplete reviewed candidate.'
        [ ! -e "$ctl" ] && [ ! -L "$ctl" ] || die 'Controller already exists; use existing controller.'
        mkdir -m 700 "$ctl"
        mkdir -m 700 "$ctl/code" "$ctl/service" "$ctl/backup" "$ctl/log-service" "$ctl/log-backup"
        cp -- "$here/staging.sh" "$here/supervisor.sh" "$here/managed-backup.sh" "$ctl/code/"
        chmod 700 "$ctl/code/"*.sh
        (cd "$ctl/code" && sha256sum staging.sh supervisor.sh managed-backup.sh > SHA256SUMS)
        for name in service backup; do
            mkdir -m 700 "$ctl/$name/log"
            printf 's1048576\nn5\n' > "$ctl/log-$name/config"
            printf '#!%s\nexec svlogd -tt "%s"\n' "$(command -v bash)" "$ctl/log-$name" > "$ctl/$name/log/run"
            chmod 700 "$ctl/$name/log/run"
        done
        printf '#!%s\nexec 2>&1\nexec bash "%s" run\n' "$(command -v bash)" "$ctl/code/staging.sh" > "$ctl/service/run"
        printf '#!%s\nexec 2>&1\nexec bash "%s" backup-loop\n' "$(command -v bash)" "$ctl/code/supervisor.sh" > "$ctl/backup/run"
        # Fixed bounded restart delay. No unbounded tight failure loop.
        printf '#!%s\nsleep 10\n' "$(command -v bash)" > "$ctl/service/finish"
        chmod 700 "$ctl/service/run" "$ctl/service/finish" "$ctl/backup/run"
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
case "$1" in
    start)
        exec 8>"$ctl/controller.lock"
        flock -n 8 || die 'Controller already running.'
        # Refuse to adopt a live manual service. The staging script still
        # owns the actual exclusive service lock for each child lifetime.
        (flock -n 9 || die 'Stop the existing foreground service first.') 9>"$root/service.lock"
        main_pid='' backup_pid=''
        cleanup() {
            trap '' INT TERM HUP
            # Only control runsv instances launched from this private tree.
            if [ -n "$backup_pid" ]; then sv -w 35 exit "$ctl/backup" >/dev/null 2>&1 || true; fi
            if [ -n "$main_pid" ]; then sv -w 45 exit "$ctl/service" >/dev/null 2>&1 || true; fi
            if [ -n "$backup_pid" ]; then wait "$backup_pid" || true; fi
            if [ -n "$main_pid" ]; then wait "$main_pid" || true; fi
        }
        trap cleanup EXIT
        trap 'exit 0' INT TERM HUP
        runsv "$ctl/service" 8>&- & main_pid=$!
        runsv "$ctl/backup" 8>&- & backup_pid=$!
        # Exit if either supervisor itself dies; its service child may still
        # own the staging lock. Never kill an unrelated PID or restart over it.
        wait -n "$main_pid" "$backup_pid" || true
        die 'A runsv supervisor exited; inspect controller status before restarting.'
        ;;
    stop)
        # Do not stop a manually launched staging instance.
        sv -w 35 exit "$ctl/backup"
        sv -w 45 exit "$ctl/service"
        printf 'Managed services stopped; PostgreSQL remains up. Use staging.sh stop-db if desired.\n'
        ;;
    status)
        sv status "$ctl/service" "$ctl/backup" || true
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
        while true; do
            # A missed day is not replayed. The first healthy opportunity
            # produces the current UTC day's backup; subsequent checks skip.
            timeout -k 5s 20m bash "$backup" & child=$!
            wait "$child" || printf 'Scheduled backup check failed; retry in 15 minutes.\n' >&2
            child=''
            sleep 900 & child=$!
            wait "$child" || true
            child=''
        done
        ;;
    boot-enable)
        # Explicit operator opt-in. Termux:Boot must have been opened once.
        boot="$HOME/.termux/boot"
        mkdir -p -m 700 "$boot"
        [ -d "$boot" ] && [ ! -L "$boot" ] || die 'Invalid boot directory.'
        file="$boot/90-chezhi-staging"
        (set -o noclobber; printf '#!%s\nexec bash "%s" start\n' "$(command -v bash)" "$ctl/code/supervisor.sh" > "$file") || die 'Boot entry already exists.'
        chmod 700 "$file"
        printf 'Boot entry installed. No wake lock acquired; actual reboot must be tested.\n'
        ;;
    boot-disable)
        file="$HOME/.termux/boot/90-chezhi-staging"
        [ -f "$file" ] && [ ! -L "$file" ] || die 'No managed boot entry.'
        expected="$(printf '#!%s\nexec bash "%s" start\n' "$(command -v bash)" "$ctl/code/supervisor.sh")"
        [ "$(cat "$file")" = "$expected" ] || die 'Boot entry differs; inspect manually.'
        rm -- "$file"
        ;;
    *) die 'Unknown controller command.';;
esac
