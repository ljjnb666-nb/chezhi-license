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
- 8-byte issue time, 8-byte expiry time (maximum 120 seconds).
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

## V5 challenge persistence (real PostgreSQL test passed; full container revalidation pending)

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

## V6 secure binding foundation (implementation; CI pending)

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
challenge's authorization epoch is still current. This epoch fencing is
NOT yet implemented. The existing V5 challenge does not bind the revision.
Do not expose this primitive via HTTP until revision fencing, keyring and
commit-confirmed credential issuance are complete. The lifecycle fixture
uses fresh proofs and tests the storage boundary only.

## Required integration work (not yet implemented)

- V7+ migration: bind pending challenges to the authoritative card epoch,
  including previously legacy/unbound cards, and implement signing keyring policy.
- Integrate the V5 atomic consumption callback with the V6 card/identity
  mutation and enforce authorization epoch fencing across admin mutations. Repeated signatures alone are
  intentionally NOT rejected by the pure verifier.
- Apply shared HTTP rate limits to challenge issuance, malformed and failed
  requests; avoid secrets and replayable material in logs.
- Strict v2 wire decoding, native HTTPS activation/validation/renewal, deny
  algorithm confusion and all v1/browser/demo downgrade paths for protected
  licenses. Preserve legacy bindings pending explicit authorized migration;
  never silently rebind or reset first activation/expiry/revocation.
- Server keyring loading, offline rotation, multi-instance consistency,
  compromise response and recovery fencing; no plaintext private keys in DB.
- Sign only confirmed authorized claims, no uncommitted credentials; recover
  uncertain commits through fresh challenges and DB reconciliation.
- Reference client, cross-language vectors, real two-process PostgreSQL
  HTTPS negative tests, restore and compatibility tests. P4 integrates
  Windows protected storage and trustworthy time policy.
- HTTP 503 classification and P5 capacity gates remain open.

Do not deploy or enable v2 until the integration and independent acceptance
are complete. Existing legacy licenses retain their behavior; V6 rejects legacy requests
for secure-marked cards and does not enable any V2 endpoint.
