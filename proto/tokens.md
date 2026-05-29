# tokens

The two long-lived JWTs that authorize a side to establish a WebSocket with `spl-relay` are the service token and device token. A third JWT, the pair ticket, is short-lived and one-use; it authorizes only the off-LAN pairing dial. All are issued by `spl-relay`'s control plane and signed by an Ed25519 key held only by sol pbc (or by the self-host operator, for self-hosted deployments). All authorize **rendezvous only** — none confers data access. Data access is gated by the TLS handshake inside the tunnel, against `authorized_clients.json` on the home.

This document specifies the token shape, claims, validation, and the JWKS-based rotation model. The signing-key lifecycle (generation, vault storage, provisioning, rotation cadence, compromise response) is out of scope here — see [`../docs/signing-keys.md`](../docs/signing-keys.md) for the public-facing playbook, and (for sol pbc internal operators only) `cso/playbooks/spl-signing-key-lifecycle.md`.

## algorithm

**Ed25519 / EdDSA**, per the CSO playbook.

Choosing Ed25519 over ECDSA-P256 here, even though the mTLS layer uses ECDSA-P256, is a deliberate split — *do not conflate the two layers*:

- **JWT signing layer (this document):** Ed25519 / EdDSA. Deterministic signatures (no nonce-reuse foot-gun), 32-byte keys, 64-byte signatures, first-class on Cloudflare Workers via Web Crypto's `Ed25519` algorithm.
- **mTLS layer (see [`pairing.md`](pairing.md), [`session.md`](session.md)):** ECDSA-P256. Required because Node/Bun TLS defaults don't advertise Ed25519 in signature schemes (prototype finding §11.7).

Different standards (JOSE vs. X.509/TLS), different ecosystems, different optimal choices.

## token types

There are two long-lived rendezvous credentials, plus one short-lived pair ticket.

### service token

Authorizes a home to open a `/session/listen` WebSocket to `spl-relay`. Long-lived. One per home install.

### device token

Authorizes a paired mobile device to open a `/session/dial` WebSocket to `spl-relay`, naming a specific home `instance_id`. Bound to (`instance_id`, client cert fingerprint). One per paired device.

### pair ticket

Authorizes a mobile device in the off-LAN pairing flow to open one `/session/pair-dial` WebSocket to `spl-relay`, naming a specific home `instance_id`. Short-lived (60s), one-use, and instance-bound. Minted per pairing attempt after a TOTP check. It confers no data access and is consumed exactly once.

The service and device tokens are JWTs with the same shell; the differences are in claims and TTL. The pair ticket is also a JWT, but it is intentionally short-lived and one-use.

## claim shape

JOSE header:

```json
{
  "alg": "EdDSA",
  "typ": "JWT",
  "kid": "<UUIDv7 of the signing key>"
}
```

`kid` is required. It is how rotation works without disruption — see *rotation* below.

JWT payload, service token:

```json
{
  "iss": "spl.solpbc.org",
  "sub": "home:<instance_id>",
  "aud": "spl-relay",
  "scope": "session.listen",
  "instance_id": "<uuidv7>",
  "ca_fp": "sha256:<64 lowercase hex>",
  "iat": 1745006400,
  "exp": 1776542400,
  "jti": "<uuidv7>"
}
```

JWT payload, device token:

```json
{
  "iss": "spl.solpbc.org",
  "sub": "device:<device_id>",
  "aud": "spl-relay",
  "scope": "session.dial",
  "instance_id": "<paired home instance_id>",
  "device_fp": "sha256:<64 lowercase hex>",
  "iat": 1745006400,
  "exp": 1750190400,
  "jti": "<uuidv7>"
}
```

JWT payload, pair ticket:

```json
{
  "iss": "spl.solpbc.org",
  "sub": "pair:<instance_id>",
  "aud": "spl-relay",
  "scope": "session.pair",
  "instance_id": "<uuidv7>",
  "iat": 1745006400,
  "exp": 1745006460,
  "jti": "<uuidv7>"
}
```

The pair ticket carries no `ca_fp` and no `device_fp`.

| claim | required | meaning |
|---|---|---|
| `iss` | yes | issuer hostname; for sol pbc deployments, `spl.solpbc.org`. Self-hosters use their own. |
| `sub` | yes | subject; must be `home:<instance_id>` for `session.listen`, `device:<device_id>` for `session.dial`, and `pair:<instance_id>` for `session.pair`. |
| `aud` | yes | audience; always `spl-relay`. |
| `scope` | yes | one of `session.listen` (service token), `session.dial` (device token), or `session.pair` (pair ticket). Workers reject mismatched scope at the route level. |
| `instance_id` | yes | which home this token authorizes the bearer to act on. For service tokens, the home's own id. For device tokens, the paired home. For pair tickets, the pairing target home. |
| `ca_fp` | service only | SHA-256 of the home's local CA public key, registered at home enrollment. Required for `session.listen`, must match `^sha256:[0-9a-f]{64}$`, and corresponds to the `ca_pubkey_pem` used to verify `home_attestation` signatures at `/enroll/device`; the relay never receives or recomputes a client cert. |
| `device_fp` | device only | SHA-256 of the mobile client cert. Required for `session.dial`, must match `^sha256:[0-9a-f]{64}$`, and is bound to a specific paired device. |
| `iat` | yes | issued-at, seconds since epoch. |
| `exp` | yes | expiration, seconds since epoch. |
| `jti` | yes | unique token id; UUIDv7. Used for revocation lookups and replay defense. Pair-ticket `jti`s are consumed in Durable Object storage. |

For `session.pair`, `sub` MUST exactly equal `pair:<instance_id>`, tighter than the prefix checks on `session.listen` and `session.dial`.

Workers MUST reject any token missing a required claim or carrying an unexpected `scope` for the requested route.

## TTLs

| token | TTL | rotation |
|---|---|---|
| service token | 365 days | re-issued automatically by the home on token age > 80% of TTL via the control-plane re-issue endpoint |
| device token | 60 days | re-issued automatically by the mobile on next dial after age > 80% of TTL |
| pair ticket | 60 seconds | one-use, consumed on first successful pair-dial attach; minted per pairing attempt, no rotation |

Long TTLs are deliberate for the service and device tokens. Both authorize the **rendezvous** only; they confer no data access. The TLS layer is the data-plane authoritative point. A leaked token grants only the right to open a WebSocket to `spl-relay`, which is useless without the matching mTLS material that lives only on the device.

A pair ticket also authorizes rendezvous only. The home's pairing window plus the home-side nonce is the actual pairing gate.

Rotation matters less than the signing-key rotation underneath (see *rotation* below). Token rotation is hygienic, not protective.

### why not 5-minute access tokens?

A short-TTL bearer model would force a control-plane round-trip on every dial. That trades one kind of operational friction (token expiry) for another (control-plane availability) without any real security gain — the data plane is mTLS, and the rendezvous bearer is intentionally low-stakes.

## issuance

Three control-plane endpoints, all POST, all JSON.

### POST `/enroll/home`

Called once at solstone first run. Body:

```json
{
  "instance_id": "<freshly generated UUIDv7>",
  "ca_pubkey": "<PEM>",
  "home_label": "<user-named home>",
  "totp_secret": "<base32, optional>"
}
```

`totp_secret` is optional, unpadded uppercase RFC-4648 base32 (`^[A-Z2-7]{16,128}$`). It is stored at rest for `/session/pair-ticket` validation. On same-instance re-enroll, omitting `totp_secret` preserves the stored value; providing it overwrites the stored value.

Bodies over 32 KiB are rejected with 413 before parsing. A `ca_fp` backs at most one instance: a new enroll whose `ca_fp` matches a different instance is rejected with 409, distinct from the `ca_mismatch` 409 for an `instance_id` trying to change its own CA.

`spl-relay` records (`instance_id`, `ca_fp = sha256(ca_pubkey)`, `home_label`, `totp_secret`, `created_at`) in D1 and issues a service token. Response:

```json
{
  "service_token": "<JWT>",
  "expires_at": "<ISO8601>"
}
```

In v1, `/enroll/home` is **rate-limited but not gated** — there's no waitlist, no payment gate. Self-hosted deployments will replace this endpoint or its policy as appropriate.

### POST `/enroll/device`

Called by the mobile app after LAN pairing completes. Body:

```json
{
  "instance_id": "<paired home>",
  "home_attestation": "<compact JWS, ES256>"
}
```

Bodies over 16 KiB are rejected with 413 before parsing.

**`home_attestation`** is a short-lived JWT signed by the home's local CA private key during the pair ceremony (see [`pairing.md`](pairing.md) §7). Its role is to prove to `spl-relay` that the paired home intentionally authorized *this specific* device fingerprint in *this specific* pair ceremony — chain validity alone would only prove the home issued the cert at some point, which is a weaker claim.

Header:

```json
{ "alg": "ES256", "typ": "home-attest" }
```

Claims:

```json
{
  "iss": "home:<instance_id>",
  "aud": "spl-relay",
  "scope": "device.enroll",
  "instance_id": "<uuidv7>",
  "device_fp": "sha256:<lowercase hex>",
  "iat": 1745006400,
  "exp": 1745006700,
  "jti": "<uuidv7>"
}
```

| claim | required | meaning |
|---|---|---|
| `iss` | yes | literal `home:<instance_id>`. Binds the attestation to a specific home identity. |
| `aud` | yes | literal `spl-relay`. |
| `scope` | yes | literal `device.enroll`. |
| `instance_id` | yes | home's instance_id; must match the request body's `instance_id`. |
| `device_fp` | yes | `sha256:<64 lowercase hex>` fingerprint of the mobile client cert, asserted by the home in the attestation. `spl-relay` validates the claim's shape (`^sha256:[0-9a-f]{64}$`) and treats the verified claim as the device identity — it never receives or recomputes the client cert. |
| `iat` | yes | issued-at, seconds since epoch. |
| `exp` | yes | expiration, seconds since epoch. Must satisfy `exp > now` and `exp - iat ≤ 300` (5 min, matching the LAN pair nonce TTL). |
| `jti` | yes | unique id (UUIDv7). Stored in D1 as `devices.attestation_jti UNIQUE`; a repeated still-valid attestation can re-mint only if the stored row matches `(instance_id, device_fp)` and has `device_id`, otherwise it is rejected as replay. |

Signature algorithm is ES256 (ECDSA-P256 / SHA-256), in either JOSE raw (r||s, 64 bytes, preferred) or DER-encoded form. `spl-relay` accepts both — home implementations may differ in whichever their local library emits, and the cost of supporting both is trivial.

**Validation (by `spl-relay`) on every `/enroll/device`:**

1. Load the home's `ca_pubkey_pem` from D1 for the named `instance_id`. If absent → 404.
2. Parse the `home_attestation` header; reject if `alg ≠ ES256` or `typ ≠ home-attest`.
3. Verify the ECDSA signature against the home's CA public key.
4. Check claims per the table above, including the 5-minute lifetime cap and the `device_fp` shape (`^sha256:[0-9a-f]{64}$`).
5. Attempt to INSERT the attestation's `jti` into `devices.attestation_jti`. A UNIQUE collision means the attestation was already consumed: if the stored row matches this request's `(instance_id, device_fp)` and carries a `device_id`, re-mint the **byte-identical** device token (idempotent retry, 200); otherwise reject as replay (409).
6. On success, mint a device token (see below).

**Why this shape (design O1):** CPO's open question O1 asked what proves a client cert was legitimately paired with a specific home before `spl-relay` will mint a device token. The alternatives considered:

- *Chain validity alone.* Too weak: chain validity proves the home issued the cert at some point, not that it did so recently or intentionally for this mobile. Anyone who later captures a stale client cert could mint new device tokens.
- *Bootstrap-token-plus-nonce.* Similar security, extra endpoint. The proposed home-signed JWT carries the same signal — fresh signature, scoped to `(instance_id, device_fp)`, short-lived — in a single compact blob on an existing endpoint.
- *mTLS from the home to `spl-relay` at `/enroll/device`.* Would require threading the home's CA private key through the enrollment path, which it isn't on otherwise. Bigger attack surface on the control plane with no marginal benefit over a signed JWT.

The home-signed JWT is the minimal shape that closes the trust gap. The relay never gains decrypt capability; the home never ships the CA private key off-box; the attestation is consumed exactly once via D1's UNIQUE constraint.

Response (on success):

```json
{
  "device_token": "<JWT>",
  "expires_at": "<ISO8601>"
}
```

Re-issuance: a fresh `home_attestation` per pair ceremony mints a new device token; its `jti` is consumed once via `devices.attestation_jti UNIQUE`. Idempotency: if a successful enroll's HTTP response is lost and the mobile retries with the **same still-valid** attestation, `spl-relay` re-mints the **byte-identical** device token from the stored row rather than rejecting. A consumed `jti` re-presented with a different `(instance_id, device_fp)` — or one whose stored row predates the `device_id` column — is rejected as replay (409). The old device token's `jti` becomes eligible for the D1 revocation list if the home or operator wants defense-in-depth.

### POST `/session/pair-ticket`

Called by the mobile app during off-LAN pairing. The `?instance=<id>` query parameter routes the request to the per-instance Durable Object. Body:

```json
{
  "instance_id": "<same id as the query parameter>",
  "totp": "<6 digits>"
}
```

`body.instance_id` must match the query parameter. Bodies over 2 KiB are rejected with 413 before parsing.

The relay validates `totp` against the instance's stored `totp_secret` using RFC 6238: HMAC-SHA1, 30s step, 6 digits, and ±1 step skew. Successful issuance is rate-limited to at most one ticket per (`instance_id`, 30s step). On success:

```json
{
  "pair_ticket": "<JWT>",
  "expires_at": "<ISO8601>"
}
```

Unknown instance, no stored TOTP secret, wrong code, and revoked instance all return the same client-visible `401` response. The relay performs the same HMAC work even when there is no usable secret, so the absence of a usable secret is not exposed as a timing oracle.

The relay reads only `instance_id` and `totp` from the body. Any other field, including a `nonce`, is ignored and never logged. The relay never sees the home-side pairing nonce.

The pair ticket's `jti` is one-use. The one-use consume record and the per-step issuance rate counter live in the per-instance Durable Object's SQLite storage, not D1, and survive hibernation and eviction. There is no new D1 table for pair tickets.

## validation in `spl-relay`

On every WebSocket upgrade request to `/session/listen`, `/session/dial`, or `/session/pair-dial`, the Worker:

1. Reads the `Authorization: Bearer <jwt>` header. Reject with 401 if absent or malformed.
2. Parses the JOSE header, extracts `kid`.
3. Looks `kid` up in the JWKS loaded from `env.JWKS_PUBLIC` (a JSON array of JWK public keys; see *JWKS publication* below). Reject with 401 if `kid` is unknown.
4. Verifies the Ed25519 signature using the matched public key.
5. Verifies the standard claims:
   - `aud == "spl-relay"`
   - `iss == <expected issuer for this deployment>` (`spl.solpbc.org` for sol pbc; configurable per self-host)
   - `exp > now`
   - `iat ≤ now + 60s` (allow 60s clock skew on the issued-at side)
   - `scope` matches the route (`session.listen` for `/session/listen`; `session.dial` for `/session/dial`; `session.pair` for `/session/pair-dial`)
   - for `session.listen`, `sub` starts with `home:` and `ca_fp` is present and matches `^sha256:[0-9a-f]{64}$`
   - for `session.dial`, `sub` starts with `device:` and `device_fp` is present and matches `^sha256:[0-9a-f]{64}$`
   - for `session.pair`, `sub` exactly equals `pair:<instance_id>` and no fingerprint claim is required
6. Verifies the `instance_id` exists in D1 and is not in the (D1) service-revocation table.
7. For device tokens, verifies the `device_fp` is not in the (D1) device-revocation table for that instance_id.

For pair tickets, `/session/pair-dial` consumes the ticket `jti` exactly once after a listening home is present and before the mobile WS is attached. Replay returns unauthorized. Pair-vs-dial selection is by request path, never by reading an unverified `scope`.

If any check fails, the Worker closes the WebSocket with a clean close code (`4401` "unauthorized") and logs the failure with `tunnel_id` (none yet — pre-pair), token `jti`, route, and reason. **Never the token bytes, never claims-as-payload.**

`spl-relay` does **not** issue or refresh tokens on the WebSocket path. Issuance is HTTPS-only via the control-plane endpoints.

## rotation

The signing key has a 12-month rotation cadence with a 30-day overlap window. The rotation mechanism is `kid`-keyed lookup into a multi-entry JWKS:

1. Generate the new keypair (new `kid` = fresh UUIDv7). See `../docs/signing-keys.md` for the generator script.
2. Push the **new JWKS** containing both old and new public keys: `wrangler secret put JWKS_PUBLIC --env production`.
3. Push the **new private key**: `wrangler secret put SIGNING_JWK --env production`. Issuance immediately switches to the new `kid`.
4. After the 30-day overlap window, push a **trimmed JWKS** containing only the new key: `wrangler secret put JWKS_PUBLIC --env production`. The old key is no longer accepted; any token still bearing its `kid` will fail validation cleanly (the home or device re-issues automatically, having long since hit the 80%-of-TTL re-issue trigger).

During the overlap window:

- Tokens minted under the old `kid` continue to verify against the old public key.
- Tokens minted under the new `kid` verify against the new public key.
- Live tunnels are not disrupted; in-flight tokens are not invalidated by the rotation itself.

The compromise runbook collapses this — see `../docs/signing-keys.md` for the kill-switch shape (publish a JWKS containing only the new public key, no overlap window). That invalidates every existing token instantly.

## JWKS publication

`spl-relay` publishes the **public** JWKS at:

```
GET https://spl.solpbc.org/.well-known/jwks.json
```

(Self-hosters serve from their own `spl-relay` deployment's hostname.)

The endpoint returns the JSON content of `env.JWKS_PUBLIC` directly:

```json
{
  "keys": [
    {
      "kty": "OKP",
      "crv": "Ed25519",
      "kid": "<UUIDv7>",
      "x": "<base64url>",
      "alg": "EdDSA",
      "use": "sig"
    }
  ]
}
```

This is for **transparency**: external auditors and self-hosters can verify what key sol pbc is currently signing tokens with. The Worker does not consume the endpoint — it reads `env.JWKS_PUBLIC` directly. The endpoint exists so that humans, scripts, and external monitors don't have to rely on internal knowledge.

The endpoint is unauthenticated, served `Cache-Control: max-age=300` (5 minutes — short enough that a JWKS update propagates quickly during rotation, long enough to avoid hammering the Worker on every check). It contains no private material.

## storage

Workers store no token bytes. Token validation is stateless (signature + claim checks); revocation is via `jti` lookup against D1.

The D1 schema (informative — owned by `relay/migrations/`):

```sql
CREATE TABLE instances (
  instance_id TEXT PRIMARY KEY,
  ca_fp TEXT NOT NULL,
  home_label TEXT,
  totp_secret TEXT,
  created_at INTEGER NOT NULL,
  service_token_jti TEXT NOT NULL,
  revoked_at INTEGER
);

CREATE UNIQUE INDEX idx_instances_ca_fp ON instances(ca_fp);

CREATE TABLE devices (
  device_jti TEXT PRIMARY KEY,
  instance_id TEXT NOT NULL,
  device_fp TEXT NOT NULL,
  device_label TEXT,
  created_at INTEGER NOT NULL,
  revoked_at INTEGER,
  FOREIGN KEY (instance_id) REFERENCES instances(instance_id)
);
```

D1 is for non-payload metadata only — never for tunnel bytes, never for keys, never for `authorized_clients.json` content (that lives only on the home).

Pair-ticket one-use consumption and issuance rate limiting use the per-instance Durable Object's SQLite storage (`pair_jti_consumed`, `pair_rate`), cleaned opportunistically past expiry. These tables store only token metadata and counters — never token bytes, never tunnel payload.

## what tokens do not authorize

Stated to make the trust boundary unambiguous:

- **Tokens do not decrypt anything.** TLS material lives only on the home and the mobile device.
- **Tokens do not name a fingerprint that the TLS layer trusts.** Adding a fingerprint to `authorized_clients.json` happens during pairing on the home, not via any token operation.
- **Tokens do not bind a session to a user.** They bind a WebSocket to an `instance_id` for `spl-relay`'s rendezvous purposes. There is no concept of a "user" in `spl-relay`.
- **Possession of a token is not possession of access.** A device token without the matching client cert is useless. A leaked service token without the home's CA private key cannot be turned into a working home install.

This is the load-bearing trust statement: tokens are the rendezvous, not the data.

## related

- [`../docs/signing-keys.md`](../docs/signing-keys.md) — the signing-key lifecycle (generation, vault storage, provisioning, rotation cadence, compromise response).
- [`session.md`](session.md) — the WebSocket lifecycle these tokens authorize.
- [`pairing.md`](pairing.md) — how a device first becomes eligible to be issued a device token.
- [`framing.md`](framing.md) — the multiplex inside the tunnel that token validation makes reachable.
