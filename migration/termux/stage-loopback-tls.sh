#!/usr/bin/env bash
# Generate independent loopback test credentials only; never replace live files.
set -euo pipefail
umask 077
export LC_ALL=C
die() { printf '%s\n' "$*" >&2; exit 1; }
[ "$#" -eq 1 ] || die 'Usage: stage-loopback-tls.sh <new directory inside private parent>'
target="$1"
parent="$(dirname -- "$target")"
[ -d "$parent" ] && [ ! -L "$parent" ] && [ "$(stat -c %a "$parent")" = 700 ] || die 'Use private output parent.'
[ ! -e "$target" ] && [ ! -L "$target" ] || die 'Candidate destination already exists.'
for cmd in openssl sha256sum stat mktemp; do command -v "$cmd" >/dev/null || die "Missing dependency: $cmd"; done
work="$(mktemp -d "$parent/.tls-candidate.XXXXXXXX")"
trap 'rm -f -- "$work/tls-cert" "$work/tls-key" "$work/NOTICE"; rmdir -- "$work"' EXIT
openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj /CN=127.0.0.1 \
    -addext subjectAltName=IP:127.0.0.1 \
    -addext extendedKeyUsage=serverAuth \
    -keyout "$work/tls-key" -out "$work/tls-cert" 2>/dev/null
chmod 600 "$work/tls-cert" "$work/tls-key"
openssl verify -CAfile "$work/tls-cert" -purpose sslserver -verify_ip 127.0.0.1 "$work/tls-cert" >/dev/null
openssl x509 -in "$work/tls-cert" -checkend 604800 -noout >/dev/null
cert_pub="$(openssl x509 -in "$work/tls-cert" -pubkey -noout | openssl pkey -pubin -outform DER | openssl dgst -sha256)"
key_pub="$(openssl pkey -in "$work/tls-key" -pubout -outform DER | openssl dgst -sha256)"
[ "$cert_pub" = "$key_pub" ] || die 'Candidate key mismatch.'
printf '%s\n' 'UNAPPLIED LOOPBACK TLS CANDIDATE; no automatic activation or trust distribution' > "$work/NOTICE"
mv -nT -- "$work" "$target"
[ ! -e "$work" ] || die 'Candidate destination collision.'
trap - EXIT
openssl x509 -in "$target/tls-cert" -noout -fingerprint -sha256 -enddate
printf 'TLS_CANDIDATE_READY no live files changed\n'
