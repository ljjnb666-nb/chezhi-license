# P3 device identity and licensing security — implementation in progress

## Scope and release gates

P2.3.1 audited head 66f4b2bd22445787f5d30368ac99cc99327be359,
CI 45985031081 (10/10), merged as d3b537a155e90cd3cfa990eef2d8e887afa59be7.
This is a development baseline, not production acceptance.

P5 mandatory release blockers (carry forward, do not mark complete):
- At 100k cards, 16 readers, Linux HTTPS median trial P95: overview 541.4 ms,
  orders 522.4 ms; target <=500 ms for each page.
- Mixed read load: 298/320 successes, 22 HTTP 503 (6.875%). Classify admission
  overload, database failures and view failures, then test bounded admission
  and sustained mixed load. Do not assume all 503s are admission rejections.
- Restore security currently covers newly named logical recovery targets;
  reconcile post-backup revocations, credentials and business writes.
  Same-identity physical rollback remains outside supported recovery.
- Retire pre-V4 binaries; their code does not observe deployment leases.
- Real production capacity, Windows device keystore and UI remain unverified.

## Threat model

Clients and client-controlled identifiers are untrusted. TLS authenticates the
server transport, not a hardware device. An attacker can observe or alter
client-side state, copy a card or a software private key, replay traffic,
and manipulate the client clock. No promise of uncrackable software or
hardware attestation. A valid signature proves possession of a key only.

Preserve the attributed OpenLicensd card generation and normalization code in
internal/license. The new cryptographic primitives use Go standard library
ECDSA P-256 (compatible in principle with Windows CNG/TPM), SHA-256, secure
randomness and Ed25519. Ed25519 device keys are a viable alternative but
P-256 is preferred for the future hardware-backed implementation. Actual
CNG/TPM provider support is a P4 verification item. No new third-party code
or dependency in this first increment. Further candidate/source evaluation
is required before declaring the P3 integration complete.

## Canonical protocol primitives (implemented in internal/proof)

This is not yet an HTTP API. The byte-level format is specified before
persistence and transport integration. All numbers are big-endian. Times
are positive Unix seconds; expires_at is exclusive. Product is 1–64
lowercase ASCII letters, digits, hyphens or underscores. Digests are 32
raw bytes; license ID is the 12 raw bytes of the existing 24 hex characters.

Challenge transcript:
- ASCII CHEZHI/PROOF/V2 followed by NUL.
- 32-byte deployment ID; 1-byte product length; product bytes.
- One-byte operation (1 activate, 2 validate, 3 renew).
- 32-byte random nonce, 32-byte normalized-card SHA-256, 32-byte device fingerprint.
- 8-byte positive card authorization epoch, 8-byte issue time, 8-byte
  expiry time (maximum 120 seconds). The prior 169-byte fixture is retired;
  the new fixed fixture is 177 bytes. V7 discards all pending V5/V6 challenges.
- Device public key: 65-byte SEC1 uncompressed P-256 point. Fingerprint =
  SHA-256 of that exact point. Signature = SHA-256 transcript then ECDSA
  P1363 r||s (64 bytes), canonical low-S. Reject other encodings.

Credential transcript:
- ASCII CHEZHI/CREDENTIAL/V2 followed by NUL.
- Deployment and product as above.
- 12-byte license ID, 32-byte device fingerprint, 32-byte signing-key ID
  (SHA-256 of raw Ed25519 public key), 8-byte positive authorization revision.
- 8-byte issue time, 8-byte credential expiry, 8-byte license expiry (0
  for perpetual). Credential lifetime <=24 hours and no later than the
  finite license expiry (conservative floor to whole seconds).
- Signature = Ed25519 over the entire transcript, 64 bytes.

The verifier takes the expected scope, license and device, and a public key
from a trusted keyring. Untrusted credentials cannot choose their own trust
root. Signature validation is not proof of current authorization: the
caller must establish device-key possession and use trusted time. An offline
credential cannot learn about a revocation before renewal or expiry. The
24h ceiling is provisional, pending product policy; default to online
verification until the full policy and P4 storage/time boundary are validated.

A deterministic challenge transcript hash fixture is included in proof_test.go.
No live signing keys or device credentials are committed.

## V5 challenge persistence (CI 45990141404 passed)

V5 adds a dedicated `chezhi_challenges` table with bounded canonical payloads,
nonce primary key and expiry index. The database clock determines validity.
A deployment-wide advisory transaction lock serializes issuance and the
4096-row capacity check. Consumption uses DELETE RETURNING on the nonce,
verifies the authoritative challenge after acquiring the row lock, and calls
an internal authorization callback on the same transaction. A failed proof
or callback rolls back the deletion. A committed consumption cannot be
replayed. A caller must never emit a credential from the callback, and must
not treat an uncertain commit as a confirmed authorization. The HTTP caller
will have to consume the shared licensing budget before challenge issuance.

Expiry cleanup is integrated with shared-state maintenance. Mode switches
and supported logical recovery clear challenges atomically with sessions
and rate buckets. Runtime grants and deep catalog/data checks include the
new table. Run db-init offline and reapply runtime grants before starting
V5 binaries. No historical SQL migration was edited. V5 does not yet bind
any card to a device public key or expose any proof route.

`TestPostgresProofChallenge` covers competing consumers on two independent
pools, invalid proof, rollback of a fixture business write, replay, expiry,
capacity, corrupt payload rejection, deep checks and mode-switch invalidation.
Actual license mutations, multiple HTTP processes and restore replay tests
remain part of the later integration gate.

## V6 secure binding foundation (CI 45990141404 passed)

A permanent row in `chezhi_secure_bindings` marks a card as requiring
cryptographic proof. It stores the canonical public point and a monotonic
revision; the existing card device field holds the public point fingerprint.
First secure activation requires an unbound card. Existing legacy bindings
require an explicit administrator unbind before enrollment. Administrator
unbind/revoke clears the secure public key and advances its revision, but
never removes the marker. A subsequent secure rebind preserves the original
activation and expiry. All existing v1/browser/demo licensing paths use a
shared legacy guard; protected cards return `secure_protocol_required`,
including after unbind. Authorization writes lock the card before changing
security metadata. Read-only legacy decisions use one consistent snapshot.

Business ZIP backup is refused if secure markers exist: the old JSON format
cannot faithfully restore the marker and revision. Use native PostgreSQL
backup and reconcile post-backup security changes. Existing CSV remains a
report, not a recoverable authorization store. V6 checks schema, grants and
public-key/fingerprint consistency. Reapply runtime grants offline.

The internal `lockSecureCard` primitive is not an HTTP route. Its caller
must consume a valid challenge on the same transaction and check that the
challenge's authorization epoch is still current. V7 now enforces this in the shared challenge consumer. Do not expose the
primitive separately from that consumer. A deployment-wide signing keyring
and an explicit secure-only issuance policy remain necessary before V2
HTTP integration.

## V7 authorization epoch and confirmed signing (PostgreSQL tests passed; full CI 9/10)

V7 adds `chezhi_cards.auth_epoch`, initialized to 1 for every historical
card, and advances it in the shared application write paths whenever
activation, binding, unbinding or revocation changes card state. All these
writes hold the same card row lock. Direct SQL modifications outside these
paths and old binaries are unsupported; the deployment must retire old
binaries and use documented runtime grants. A challenge is issued only
for an existing card. The epoch is captured under the card lock and is
part of the signed transcript. The consume transaction locks the challenge
first, then locks the card and verifies both epoch and DB-clock expiry
again after waiting. Administrative writes do not acquire challenge locks.
This prevents ABA reuse across legacy bind/unbind, secure rebind, and revoke.
V7 migration clears pending challenges without altering historical card
entitlements or secure binding rows. Offline upgrade and grant refresh
are mandatory. The V7 catalog includes the new column and constraint.

`authorizeProof` combines challenge consumption, secure binding or
validation, post-write epoch, DB-clock claims and Ed25519 signing in one
transaction. Its return value is published only after confirmed commit;
a failed signer rolls back the card mutation and challenge deletion, and
an ambiguous commit returns no credential. The credential revision is the
post-write card epoch, not the separate V6 binding revision. Credential
TTL is bounded by both the configured internal duration and card expiry;
perpetual cards still have expiring credentials. Clients cannot choose
the signing key or the TTL. This is an internal entry point only: the
trusted keyring and deployment scope policy are not implemented yet.

`TestPostgresAuthorizationEpoch` covers legacy and secure ABA transitions,
old challenges after unbind/rebind, revoke and integrity checks.
`TestPostgresCommittedCredential` covers signing failure rollback,
commit-confirmed claims, signature verification, replay, renewal and revoke.
CI 45990141404 established the V6 baseline (10/10, including Docker and
real PostgreSQL). V7 exact run 45991509773 passed the new PostgreSQL tests, Docker and eight other checks; the dashboard benchmark failed before tests due to a host port collision (55432). No benchmark result is inferred.

## V8 signing policy and opt-in V2 API (implementation; CI pending)

The database signing policy stores only a public key and random deployment
scope. Existing deployments without a policy remain in legacy/demo mode.
Once initialized, new cards issued through the application are atomically
marked secure-only, even before activation. Existing cards are not silently
reclassified. The runtime role can read but cannot change the policy.
Independent HTTPS service startup refuses missing or mismatched signing
keys when the policy exists; V2 is unavailable without that policy.

Generate a new private seed file outside the repository:

    chezhi-license license-key-generate <new-protected-file>

The command prints only the public key and refuses an existing path. Protect
the file with owner-only access (0600/0400 on Unix; restricted ACL on Windows).
After offline db-init and grant refresh, initialize the policy as migrator:

    chezhi-license db-set-signing-key <database-name> none <public-key-hex>

For rotation, replace `none` with the expected current public-key SHA-256
hex digest and provide the new public key. Stop every instance first.
The change clears pending challenges, advances deployment generation, and
replaces the scope; clients require explicit updated trust configuration.
Keep the same key file on each instance, set CHEZHI_SIGNING_KEY_FILE to
its protected path. Runtime reads the seed, reconstructs Ed25519 key and
matches the database public key before listening. Do not send the seed over
HTTP or commit it. Windows ACL verification, key compromise audit history,
explicit trust distribution and rollback-safe operational procedures remain
required before release. Logical recovery changes the deployment scope;
reconcile post-backup key rotations and revocations before reopening traffic.
Previously signed offline credentials cannot be recalled from offline clients.

The opt-in native HTTPS API is defined in LICENSE-API-V2.md. Its current
internal credential lifetime is five minutes, provisional for online-first
validation; this does not approve offline use. Proof and credential handling
are subject to the existing shared licensing rate budget. Current tests use
real TLS and PostgreSQL with an injected trusted request context; complete
process-level and Caddy acceptance are still required.

## Required integration work (not yet implemented)
- Apply shared HTTP rate limits to challenge issuance, malformed and failed
  requests; avoid secrets and replayable material in logs.
- Verify V2 wire decoding, native HTTPS activation/validation/renewal and secure-only
  issuance across real processes and proxy transport; test all
  algorithm confusion and all v1/browser/demo downgrade paths for protected
  licenses. Preserve legacy bindings pending explicit authorized migration;
  never silently rebind or reset first activation/expiry/revocation.
- Finish signing-key lifecycle: persistent rotation audit, historical key
  trust/retirement policy, compromise response, restore acceptance, protected
  file/ACL verification, and explicit client trust updates.
- Verify ambiguous commit and response-loss recovery through fresh challenges
  and DB reconciliation in actual HTTP processes.
- Reference client, cross-language vectors, real two-process PostgreSQL
  HTTPS negative tests, restore and compatibility tests. P4 integrates
  Windows protected storage and trustworthy time policy.
- HTTP 503 classification and P5 capacity gates remain open.

Do not deploy to production until full integration and independent acceptance
are complete. V2 routes are opt-in only; this increment is not final P3 acceptance.
