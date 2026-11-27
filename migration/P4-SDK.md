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

## P4.2 CNG key lifecycle candidate

Use Windows CNG via .NET Framework CngKey/ECDsaCng, with the Microsoft
Software Key Storage Provider or the Microsoft Platform Crypto Provider
(selected explicitly, TPM required). No automatic provider fallback.
References: https://learn.microsoft.com/en-us/windows/win32/seccertenroll/cng-key-storage-providers
and https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.cngkeycreationparameters .

A random nonempty enrollment GUID determines a namespaced current-user
persistent key name. Enrollment is an explicit create-only operation
without overwrite. Opening is a separate operation requiring the previously
pinned SHA-256 fingerprint of the SEC1 public point, and verifies provider,
user scope, persisted key name, algorithm, size, signing-only use and
nonexport policy. Missing key, malformed metadata, mismatch or provider
failure never generates a replacement. The only private operation is
signing a SHA-256 digest; the P3/SDK boundary verifies the signature and
normalizes its encoding. No private key export is part of the application
interface. Disposal releases handles, not the persisted key.

The enrollment coordinator (next increment) must persist its intent before
creation, pin the returned fingerprint before first server activation,
use atomic protected metadata, and refuse unattended repair or fallback
after interrupted enrollment. The current provider class does not implement
that persistent metadata transaction. The caller chooses the provider;
a successful TPM-provider call is not remote attestation. Software KSP
nonexport policy does not imply protection against an administrator or
malicious code running as the same user. TPM hardware, cross-user ACL
and key-loss recovery are not yet accepted. DeviceKeySmoke exercises
software keys in two independent Windows processes with a random fixture
name, checks signatures, nonexport, duplicate/missing/fingerprint/provider
mismatch, callback failure zeroing, and explicit fixture cleanup.
Do not report TPM success from the software-KSP CI fixture.

P4.1 run 46004757745: 8/10; Windows DLL build and Go tests succeeded,
.NET Framework csc relative-path compile failed (absolute path fix in
this increment); PostgreSQL SDK integration passed. Benchmark failed on
mixed workload with no successful issue, so the P5 capacity gate remains
open and its assertions are unchanged.

### Durable enrollment coordinator (software CNG CI passed)

DeviceEnrollment stores one fixed current-user record in HKCU under
Software\\CheZhiTech\\LicenseIdentity\\v1. Registry single-value replacement
and Flush are used instead of a separate filesystem journal. The record
contains only version, pending/ready state, selected provider, random slot
GUID and SHA-256 public fingerprint, protected with DPAPI CurrentUser and
domain-separated entropy including SID and registry path. No card or private
key is stored there. Protected per-user/SYSTEM DACL and user ownership
are checked; unexpected ACLs fail closed rather than being repaired.

A SID/profile-specific Global mutex serializes cooperating processes,
including separate sessions. Explicit EnrollFirst requires an absent record,
writes and flushes pending before creating the CNG key, then writes and
flushes ready with the fingerprint before returning. OpenExisting never
creates a key or repairs missing, damaged, pending or mismatched data.
An abandoned mutex alone does not authorize enrollment. Pending state is
intentionally terminal until an operator reconciles it; no automatic key
adoption, deletion, new identity or provider fallback. A crash after ready
but before caller return can reopen the pinned key. If all registry metadata
is deleted, normal startup still refuses; only an explicit first-enrollment
action can create a new slot. P4.3 must not turn missing metadata into
automatic enrollment or authorized recovery. Existing server binding
cannot be bypassed by enrolling a different local key.

DPAPI/DACL do not defend against a privileged administrator or malicious
same-user code; registry flush is not a guarantee against disk/OS rollback.
No remote attestation, hardware TPM, cross-user isolation test, real reboot
or production migration policy is claimed. EnrollmentSmoke uses random
test-only profiles, actual concurrent processes, tampered DPAPI data, missing
CNG key and forced termination at both intent and key-created boundaries.
Test hooks are conditional on CHEZHI_SDK_TEST; do not define for distribution.
No campus-network-auth code is changed. CI 46005517973 did not run jobs:
an accidental duplicate YAML section was removed in 476031a. Run 46006858825 subsequently passed all 10 jobs, including actual .NET
Framework ABI smoke, software CNG and registry DPAPI crash tests.

## P4.3 authorization state machine (development candidate)

AuthorizationState is UI-independent and belongs to exactly one fixed
card/device/trust scope. The integration must not reuse it for another
identity. The only admission predicate is CanStartProtectedOperation;
it checks current monotonic and UTC expiry, no native request in flight,
and current verified success. A new check clears the previous grant.
The conservative monotonic deadline is anchored at request start, bounded
by signed lifetime and remaining UTC time. No persisted cache, offline
authorization, or trusted clock across restart is claimed. In-process
highest revision rejects rollback; persistent rollback defense is separate.

Single-flight tickets are reference identities, never reused. Cancellation,
network loss, identity recovery and shutdown invalidate any outstanding
result but retain the physical in-flight slot until the native call returns.
The coordinator must always complete an issued ticket, including exceptions.
Late/duplicate results cannot grant authorization. Network reachability is
a negative hint only; recovery requires a new online exchange. A 403 is
generic denial, not proof of revocation. Unavailable and retry-later are
distinct states; provisional minimum retry delays are 5 and 60 seconds,
using monotonic time. No automatic retry timer or native cancellation
handle is included yet. No automatic re-enrollment after identity loss.

Before first authorization the user must use already authorized connectivity,
e.g. the official client or hotspot. No unconditional startup bypass or
offline grace is approved. Cleanup (stop/disconnect/exit/restore official
client) must not be gated by this predicate. Exact lifecycle policy for
an already running authenticated campus session when authorization expires
must be validated in P4.4, with safe cleanup available at all times.
The controller does not start/stop network processes or modify campus code.
The UI must marshal asynchronous results to its own thread and gate actual
commands, not just button colors. This is not an atomic guarantee across
a long-running external operation. Native interop, physical TPM, cross-user
ACL, actual reboot and real campus connectivity remain acceptance gates.

Run 46006858825: 10/10, actual software CNG/DPAPI and ABI tests passed.
Optimized dashboard median P95 targets passed but mixed 100k read 503
15/320, issue 503 8/9; P5 capacity remains open.

### Managed native bridge and online interop candidate

Run 46007582154: 10/10; actual Windows authorization-state test passed.
Optimized 100k mixed read 503 16/320, issue 503 14/15; P5 remains open.

NativeLicenseClient uses an absolute DLL path, rejects reparse attributes,
holds the file against writes/deletion during SHA-256 checking/loading,
uses LoadLibraryEx with DLL-directory/System32 search and checks ABI v1.
The expected digest must come from independently authenticated release
configuration, and the installation directory and all parents must be
protected against untrusted writes/rename. This is not full filesystem
race protection or Authenticode verification. Go DLL stays loaded.
LicenseCoordinator owns one fixed card/device/trust context, starts native
work on the default task scheduler, retains the device through completion,
invalidates late results on cancel/network/shutdown, and clears its card
byte buffer and releases CNG handles after the final native call. There is
no immediate native cancellation; same-user memory/administrators are out
of scope. UI must marshal results, enforce admission at actual commands,
and never gate cleanup. No card persistence or automatic enrollment added.

OnlineSmoke uses an actual x64 C# executable, hash-checked Go DLL, persistent
software CNG key and real loopback TLS exchange against a disposable
protocol fixture. A fresh test-only CA is passed as an independently configured DER trust
anchor to the additive ChezhiLicenseAuthorizeWithCA ABI export. No system
certificate store is modified. Default Authorize still uses system roots.
The explicit CA uses an isolated root pool, with normal TLS hostname and
certificate verification; invalid or absent CA bytes are rejected by the
explicit entry point. The fixture checks that system roots alone reject
its certificate. No TLS verification bypass is provided. Fixture has no database and no
production data, and is built only with sdkfixture. It verifies the device
proof, signs nonce-bound credentials, and supplies denied and wrong-nonce
responses. Tests cover activate/validate/renew, wrong signing trust, wrong
nonce, wrong DLL hash and network/shutdown state. The Go SDK real
PostgreSQL/TLS tests remain mandatory; successful Windows fixture testing
does not constitute native-to-production-server or actual campus acceptance.
Full online chain with actual deployed server and physical TPM remains P4.5.
Exact new head CI pending.

Run 46008652523: nine jobs succeeded; Windows online step timed out without
stage output after prior ABI/CNG/DPAPI/state tests passed. Root import was a
suspected interactive blocker, not confirmed. Remove it entirely, add stage
logs and a 90-second child deadline plus four-minute step timeout. Additive
ABI export requires independently authenticated CA configuration, not a CA
obtained from the server response. Both exports are development-only.
