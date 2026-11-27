# Native software licensing API v1

Use HTTPS with the configured service hostname. These endpoints authorize
software using an issued license card and the caller-supplied device
identifier. They do not grant administrator permissions.

| Method and path | Behavior |
| --- | --- |
| POST `/api/v1/licenses/activate` | Bind and first activate, or verify the same already-bound device. Rebinding still requires an administrator to unbind the previous device. |
| POST `/api/v1/licenses/validate` | Verify an existing device binding without changing license state. Unactivated and unbound cards require the activate endpoint. |

## Request and result

Send `Content-Type: application/json` and one UTF-8 JSON object, at most
4 KiB. The supported fields are `key` (1 to 100 bytes) and `device` (1 to 200
bytes, nonempty after trimming). Duplicate and unknown fields are rejected.
The service generates a fresh `X-Request-ID`. Native requests carry no
browser Origin, Referer, or Fetch Metadata headers. Never send keys in URLs.

```json
{"key":"<issued-card>","device":"<stable-client-device-id>"}
```

HTTP 200 means the authorization decision was evaluated. Clients must check
`data.valid` and `data.status`.

```json
{"version":"v1","request_id":"<server-id>","data":{"valid":true,"status":"valid","expires_at":"2026-12-27T10:00:00Z"}}
```

`expires_at` is a UTC RFC 3339 timestamp or null for an unlimited or unset
expiry. Authorization status values include `valid`, `not_found`,
`activation_required`, `device_mismatch`, `expired` and `revoked`.
Activation is idempotent for the same card and device. The device identifier
is a caller assertion. Device-key proof, challenge-response, anti-copying
and signed authorizations are reserved for P3.

```json
{"version":"v1","request_id":"<server-id>","error":{"code":"rate_limited"}}
```

| HTTP status | Code |
| --- | --- |
| 400 | `invalid_host`, `invalid_json`, `invalid_input` |
| 403 | `invalid_transport`, `browser_origin_forbidden` |
| 404 | `not_found` (unknown route) |
| 405 | `method_not_allowed` |
| 413 | `body_too_large` |
| 415 | `json_required` |
| 429 | `rate_limited`; honor Retry-After. Native authorization and browser activation share the deployment licensing budget. |
| 503 | `busy`, `unavailable`; retry with bounded backoff |

Additional response fields may be added to v1; clients should ignore fields
they do not recognize and fail closed on unknown authorization statuses.
Incompatible semantics use a new URL version. Local/test modes retain the
existing `/api/demo/activate` contract for the demo client.

In standalone mode the licensing budget uses the socket peer for direct
TLS or the single source overwritten by the approved proxy. It is shared
across instances and independent of the administrator login and password
re-verification budgets. A database or shared-state outage returns 503.
