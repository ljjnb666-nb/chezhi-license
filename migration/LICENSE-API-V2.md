# Native software license API V2 (development contract)

Opt-in only: independent HTTPS server with an initialized database signing
policy and matching protected signing seed. No browser, administrator session
or plain HTTP authorization. Existing V1 and demo routes cannot authorize
secure-marked cards. New application-issued cards are secure-marked atomically
when the policy is configured. Existing legacy bindings require administrator
unbind before migration.

POST application/json, maximum 4096 bytes. Exactly the listed fields are
required, all strings, no duplicate/unknown/null fields. Lowercase hex only
for binary encodings. All requests share the licensing source/global budget.

1. POST /api/v2/licenses/challenge
   Body: key, public_key (65-byte uncompressed P-256 point in hex),
   operation (activate, validate or renew).
   Result: nonce (32-byte hex), epoch, issued_at, expires_at (Unix seconds),
   deployment (32-byte hex), product (chezhi), transcript (canonical hex).
2. POST /api/v2/licenses/activate, /validate or /renew
   Body: key, public_key, nonce, signature (64-byte P1363 low-S ECDSA signature
   over SHA-256 of challenge transcript). Operation must match the challenge.
   Successful activation binds a previously unbound card; validation and
   renewal require the existing public-key binding.
   Result: valid=true, license_id, device, key_id, nonce, deployment, product,
   revision, issued_at, expires_at, license_expires_at (0 for perpetual),
   transcript and signature (Ed25519 hex).

Response envelope: version=v2, request_id, data or error={code}. HTTP 200
is success only if the entire expected response verifies. 400 invalid input,
403 authorization_denied or browser_origin_forbidden, 404 not_found,
405 method_not_allowed, 413 body_too_large, 415 json_required,
429 rate_limited, 503 busy/unavailable. Observe Retry-After and bounded
backoff. Obtain a fresh challenge after uncertain delivery; do not reuse
a consumed nonce. Retain the same device key. For uncertain first activation,
a fresh activation with the same key is safe; do not generate a replacement
key or reset the original activation time. A failed response does not establish
that the database transaction failed.

Clients MUST reconstruct the transcripts from independently expected scope,
operation, card hash, public-key fingerprint and server-provided nonce/time
and epoch. Compare to supplied transcript exactly before signing; do not
blindly sign opaque server bytes. Verify credential transcript and claims
against locally provisioned trusted public key, scope and device identity,
not a trust root learned from an untrusted response. Check time, product,
license ID and revision. The signed credential includes the consumed challenge
nonce immediately after the key ID in the binary transcript; it must exactly
match this request's outstanding nonce. Earlier development credentials without
this field are not accepted. The current credential lifetime is at most five
minutes and never later than finite card expiry. Online-first is the
provisional policy; offline authorization is not yet approved. Key rotation
and logical recovery change scope; secure distribution of new trust settings
and P4 protected device-key storage remain outstanding.

See P3-SECURITY.md for binary field layout and threat model. This contract
is under development, not a production API or SDK compatibility promise.

## Reference client and trust provisioning

Use `db-signing-info` against the intended database to obtain public trust
settings, then distribute through an independently authenticated channel.
`internal/licenseclient.New` accepts the HTTPS origin, expected scope,
trusted Ed25519 public key and optional private CA roots. `Authorize` takes
a context, operation, card and P-256 `crypto.Signer`. It always performs
an online exchange and returns verified claims on success only. It does not
persist keys, perform offline authorization or establish hardware identity.
The caller must fail closed on unsuccessful refresh. P4 will supply protected
key storage and application state integration. Never print card values or
private keys in logs. The client is internal, not a stable public SDK yet.
