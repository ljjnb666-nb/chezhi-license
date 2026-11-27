# P4.1 Windows authorization SDK — development boundary

P3 merged baseline: c783a63e58efd5cf1a1826904707852af698b723.
The campus desktop source inspected is C#/WinForms on .NET Framework 4.x
with an independent C authentication core (BUILD.md, ARCHITECTURE.md,
Build.ps1 in campus-network-auth). P4.1 deliberately does not edit that
repository or its connection state machine.

Architecture decision: reuse the audited Go V2 client at source level and
export a narrow x64 C ABI from a cgo DLL; the current desktop compiler can
call it via P/Invoke without a new .NET runtime or third-party crypto package.
No separate network authentication helper or listening service is introduced.
The SDK must run in the desktop process, not in the campus core. Device signing
is a callback, so P4.2 can supply an NCrypt CNG/TPM implementation without
exporting private keys or reimplementing the V2 wire format.

## ABI v1 (development, not released)

Build with Windows x64 MinGW gcc and Go:
    go build -trimpath -buildmode=c-shared -o bin/chezhi_license_sdk.dll ./cmd/windows-license-sdk

CGO_ENABLED=1, GOOS=windows, GOARCH=amd64. Generated header is the source
of truth for the C calling convention. ABI version function returns 1.
Authorize accepts UTF-8 HTTPS origin (1..2048 bytes), 32-byte deployment,
32-byte pinned Ed25519 public key, UTF-8 card (1..100 bytes), 65-byte
uncompressed device public key, callback pointer and context, operation
1 activate / 2 validate / 3 renew, and an exact 32-byte output buffer.

Caller-owned fixed-size pointers must be readable; output must be writable,
nonoverlapping and exactly 32 bytes. All pointers/delegates must remain live
until the synchronous call completes. Callback receives a 32-byte SHA-256
digest and a writable 64-byte P1363 signature buffer; returns zero on success.
It must not retain pointers, block indefinitely, re-enter SDK, or throw
across the native boundary. No private key bytes cross the ABI. The adapter
checks callback signature against supplied public point before P3 normalizes
low-S and sends it. No Go pointers are passed to the callback. DLL has Go
runtime lifetime: load once per process, do not unload dynamically.

Status values: 0 verified success; 1 invalid input or provider failure;
2 unavailable/transport/configuration; 3 generic authorization denied;
4 retry later (429/503); 5 untrusted or malformed response; 6 internal failure;
7 cancelled (Go caller). Only 0 returns metadata (big-endian uint64 revision,
int64 issued_at, expires_at, license_expires_at; zero license expiry means
perpetual). Failures with a valid output buffer clear it. Metadata is not an
offline credential. No claim that native pointer misuse can be made safe.

Every call uses a fresh online proof and independent TLS and signing trust,
20-second overall network deadline, no automatic retry, no cached success,
no offline bypass. External synchronous callback itself must be bounded by
its owner. The UI must call off the UI thread and retain the same device key
on uncertain activation. Do not treat unavailable as revoked/invalid.
P4.3 owns the application state machine and cancellation/single-flight
policy; this ABI currently has no native cancel handle.

P4.2 must implement protected persistent key open/create, TPM policy, ACL,
no silent replacement/fallback, and real Windows tests. P4.3 must solve
pre-campus-network reachability via already authorized network access
(e.g. official login or hotspot) and explicit state; no unconditional bypass.
No offline grace policy approved. P4.4 desktop integration is separate.
P5 gates from P3 (capacity, rollback, key compromise, cross-user ACL) remain.

Tests: pure Go callback adapter/status tests; Windows c-shared build and
.NET Framework P/Invoke smoke are CI gates. No claim of TPM, GUI or actual
campus authorization test. Native successful online interop and full SDK
application acceptance still required before shipping.
