# P4.4 desktop integration acceptance contract (preparation only)

Inspected campus-network-auth main bf7eb8aaf523c953a6b232290eb1adaa546d9ec8,
not the old RC draft. Program.cs and Build.ps1 read at that exact SHA.
No changes to that repository. Reconfirm all anchors at implementation HEAD.

## Mandatory gate before integration

The prior Windows interop run 46008652523 was cancelled on timeout,
after the ABI, CNG, DPAPI and state tests passed. Require actual online
smoke success at the corrected SDK head before vendoring it.
Use an isolated campus integration branch/PR; never modify its stable main
or the C authentication core as part of SDK plumbing.

## Admission map

- Program.cs:3701 ConnectCommandAsync: check actual authorization before
  creating AuthTask, not just button state. Require fresh online proof at
  user intent; use existing task generation and cancellation discipline.
- Program.cs:3759 vicinity CheckAndStartAsync: shared manual/automatic
  preflight; recheck permission before preparation and before core launch
  after awaited handoff or user confirmation. A stale UI check is not enough.
- Program.cs:3886 RetryTimerTick: automatically scheduled retry must pass
  the same admission path; no retry-only bypass.
- Program.cs:4413 RunServiceAction: distinguish preparation from restore.
  Preparation must be guarded before service side effects and after prompts.
  Restore, interrupted-journal reconciliation, stop and exit must remain
  independent of license validity.
- Program.cs:4293 OnClosing: hide-to-tray is not exit; dispose license
  coordinator only on actual exit, retain CNG handle until native work
  returns, never block OS shutdown on licensing.
- Review all tray, command-line, self-test, recovery, power and network
  event paths. Self-tests must remain offline and cannot enable production
  authorization. Do not weaken service identity/journal checks.

## Bootstrap constraint

User may use already authorized connectivity (official client/hotspot)
before preparation. Do not disable official service before checking online.
A planned handoff can interrupt network, so an authorization check just
before switching is not sufficient to guarantee that the later core launch
is online-authorized. Current policy fails closed; restore official access
when necessary. This may make the third-party workflow unusable on some
campus network configurations. Do not implement silent offline bypass or
claim that captive-network bootstrap has been solved. Real connectivity
and a user-approved bounded policy are explicit integration gates.

## Packaging and trust

Current Build.ps1 uses Framework64 csc, /platform:anycpu and embeds the
authentication core. Native SDK is x64; use an explicit x64 licensed build,
with versioned source provenance, pinned release DLL digest and authenticated
server origin/deployment/Ed25519 key, optional independently provisioned CA.
No production secrets or fabricated trust values. Do not load a DLL from
a writable search path; protect installation directory and all ancestors.
SDK digest alone is not a trusted release manifest or complete TOCTOU defense.
Keep old build and offline self-test baseline available as non-release test
fixtures, not an authorization bypass in the licensed application.

Card storage: explicit consent, separate DPAPI CurrentUser record linked to
pinned enrolled identity and deployment; no card in command line, logs or
campus account record. Do not auto-enroll on missing/corrupt identity or
erase card on transport failure. Separate identity recovery from card
replacement. No persistent offline grant.

## Acceptance

Verify UI/command consistency, denied/expired/security/network states,
manual and tray entrypoints, delayed confirmation/late completion,
automatic retry, suspend/resume, close-to-tray/exit, recovery availability,
same-device retry and no secret leakage. Require all existing campus
offline self-tests, x64 build and SDK integrity evidence. Real TPM, reboot,
cross-user ACL, actual PostgreSQL server and real campus handoff remain
P4.5/production gates. Policy for an already running session on renewal
failure requires explicit decision; do not abruptly stop user's network
without validated recovery path. No production deployment in P4.4.
