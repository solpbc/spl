# tokens

The two long-lived JWTs that authorize a side to establish a WebSocket with `spl-relay` are the service token and device token. Both are issued by `spl-relay`'s control plane and signed by an Ed25519 key held only by sol pbc (or by the self-host operator, for self-hosted deployments). Both authorize **rendezvous only** — neither confers data access. Data access is gated by the TLS handshake inside the tunnel, against `authorized_clients.json` on the home.

This document specifies the token shape, claims, validation, and the JWKS-based rotation model. The signing-key lifecycle (generation, vault storage, provisioning, rotation cadence, compromise response) is out of scope here — see [`../docs/signing-keys.md`](../docs/signing-keys.md) for the public-facing playbook. sol pbc internal operators additionally follow their own operational playbook.

## algorithm

**Ed25519 / EdDSA**, per sol pbc's signing-key policy.

Choosing Ed25519 over ECDSA-P256 here, even though the mTLS layer uses ECDSA-P256, is a deliberate split — *do not conflate the two layers*:

- **JWT signing layer (this document):** Ed25519 / EdDSA. Deterministic signatures (no nonce-reuse foot-gun), 32-byte keys, 64-byte signatures, first-class on Cloudflare Workers via Web Crypto's `Ed25519` algorithm.
- **mTLS layer (see [`pairing.md`](pairing.md), [`session.md`](session.md)):** ECDSA-P256. Required because Node/Bun TLS defaults don't advertise Ed25519 in signature schemes (a prototype finding, notes §11.7, meaning sol pbc's internal engineering notes, which are not published). Every other `§` citation in this document resolves to a heading you can open, here or in a sibling document.

Different standards (JOSE vs. X.509/TLS), different ecosystems, different optimal choices.

## token types

There are two long-lived rendezvous credentials. Off-LAN pairing admission is specified in [`pair-window.md`](pair-window.md); it does not mint a JWT credential.

### service token

Authorizes a home to open a `/session/listen` WebSocket to `spl-relay`. Long-lived. One per home install.

### device token

Authorizes a paired mobile device to open a `/session/dial` WebSocket to `spl-relay`, naming a specific home `instance_id`. Bound to (`instance_id`, client cert fingerprint). One per paired device.

The service and device tokens are JWTs with the same shell; the differences are in claims and TTL.

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
  "iss": "link.solstone.app",
  "sub": "home:<instance_id>",
  "aud": "spl-relay",
  "scope": "session.listen",
  "instance_id": "<the home's jid>",
  "ca_fp": "sha256:<64 lowercase hex>",
  "iat": 1745006400,
  "exp": 1776542400,
  "jti": "<uuidv7>"
}
```

JWT payload, device token:

```json
{
  "iss": "link.solstone.app",
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

| claim | required | meaning |
|---|---|---|
| `iss` | yes | issuer hostname; for sol pbc deployments, `link.solstone.app`. Self-hosters use their own. |
| `sub` | yes | subject; must be `home:<instance_id>` for `session.listen` and `device:<device_id>` for `session.dial`. |
| `aud` | yes | audience; always `spl-relay`. |
| `scope` | yes | one of `session.listen` (service token) or `session.dial` (device token). Workers reject mismatched scope at the route level. |
| `instance_id` | yes | which home this token authorizes the bearer to act on. For service tokens, the home's own id. For device tokens, the paired home. **This is the home's jid, derived from its CA public key per [`identity.md`](identity.md) — a UUIDv8, not a freshly generated identifier.** The home derives it and registers it at enrollment; `spl-relay` records what it is given and never computes it. |
| `ca_fp` | service only | SHA-256 of the home's local CA public key, registered at home enrollment. Required for `session.listen`, must match `^sha256:[0-9a-f]{64}$`, and corresponds to the `ca_pubkey_pem` used to verify `home_attestation` signatures at `/enroll/device`; the relay never receives or recomputes a client cert. |
| `device_fp` | device only | SHA-256 of the mobile client cert. Required for `session.dial`, must match `^sha256:[0-9a-f]{64}$`, and is bound to a specific paired device. |
| `iat` | yes | issued-at, seconds since epoch. |
| `exp` | yes | expiration, seconds since epoch. |
| `jti` | yes | unique token id; UUIDv7. Recorded at issuance so a future revocation list would have something to key on. Nothing looks it up today — see *storage*. Attestation replay defense is separate and keys on `devices.attestation_jti`. |

Workers MUST reject any token missing a required claim or carrying an unexpected `scope` for the requested route.

## TTLs

| token | TTL | rotation |
|---|---|---|
| service token | 365 days | no automatic re-issue. The token is replaced when **the home** calls `POST /enroll/home` again, carrying its existing `instance_id`, `ca_pubkey` and `home_label` |
| device token | 60 days | re-issued by the mobile via `POST /token/refresh` (presenting the current token) when age > 80% of TTL, with a 30-day post-expiry grace |

**The two rows are not symmetric, and the difference is load-bearing.** A device carries itself: `POST /token/refresh` exists and the mobile calls it. A home does not. `spl-relay` publishes no endpoint that re-issues a service token, mints one in exactly one place (`POST /enroll/home`), and runs no timer that touches token lifetime. A service token is therefore rotated only when something outside the protocol makes that call: an owner re-enabling the tunnel, or an operator running it. Nothing here notices that a service token is nearing expiry.

Plan for that. A home whose service token expires cannot open `/session/listen`, so it is unreachable off-LAN until it enrolls again, and triggering that call in time is the deployment's own responsibility.

Long TTLs are deliberate for the service and device tokens. Both authorize the **rendezvous** only; they confer no data access. The TLS layer is the data-plane authoritative point. A leaked token grants only the right to open a WebSocket to `spl-relay`, which is useless without the matching mTLS material that lives only on the device.

Rotation matters less than the signing-key rotation underneath (see *rotation* below). Token rotation is hygienic, not protective.

### why not 5-minute access tokens?

A short-TTL bearer model would force a control-plane round-trip on every dial. That trades one kind of operational friction (token expiry) for another (control-plane availability) without any real security gain — the data plane is mTLS, and the rendezvous bearer is intentionally low-stakes.

## issuance

Three control-plane endpoints, all POST, all JSON.

### POST `/enroll/home`

Called once at solstone first run. Body:

```json
{
  "instance_id": "<the home's jid, derived from its CA>",
  "ca_pubkey": "<PEM>",
  "home_label": "<owner-named home>"
}
```

Bodies over 32 KiB are rejected with 413 before parsing. A `ca_fp` backs at most one instance: a new enroll whose `ca_fp` matches a different instance is rejected with 409, distinct from the `ca_mismatch` 409 for an `instance_id` trying to change its own CA.

`spl-relay` records (`instance_id`, `ca_fp`, the `ca_pubkey` PEM itself, `home_label`, `created_at`) in D1 and issues a service token.

`ca_fp` is **SHA-256 over the DER `SubjectPublicKeyInfo`**: the bytes carried inside the PEM armor, not the armored text, and not a certificate. `spl-relay` strips the BEGIN/END lines and all whitespace, base64-decodes the body, and digests exactly the bytes it then imports as an ECDSA-P256 SPKI public key. The result is rendered `sha256:<64 lowercase hex>`. Every fingerprint in this protocol is taken over DER; [`identity.md`](identity.md) enumerates them and says which input each one covers.

Response:

```json
{
  "service_token": "<JWT>",
  "expires_at": "<ISO8601>"
}
```

**A repeat call is the rotation path.** `/enroll/home` is idempotent on `instance_id`: a second call carrying the same `ca_pubkey`, compared as text after trimming surrounding whitespace, mints a fresh 365-day service token with a new `jti`, replaces the recorded `service_token_jti`, stamps `rotated_at`, and returns the new token. No paired device has to re-pair. This is the only path by which a service token is ever replaced.

⚠ **A home re-enrolling must send its stored `home_label` along with the other two fields.** The re-enroll branch writes the label from the request body and the field is optional, so a call that omits it stores `NULL` and the instance silently loses its label in `GET /admin/instances`. This is a home-implementation requirement: only the home holds both the `ca_pubkey` this call must match and the label it should preserve.

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

**`home_attestation`** is a short-lived JWT signed by the home's local CA private key during the pair ceremony (see [`pairing.md`](pairing.md) §7 *home returns cert + chain + home attestation*). Its role is to prove to `spl-relay` that the paired home intentionally authorized *this specific* device fingerprint in *this specific* pair ceremony — chain validity alone would only prove the home issued the cert at some point, which is a weaker claim.

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
  "instance_id": "<the home's jid>",
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

**Why this shape.** An open design question asked what proves a client cert was legitimately paired with a specific home before `spl-relay` will mint a device token. The alternatives considered:

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

Re-issuance: a fresh `home_attestation` per pair ceremony mints a new device token; its `jti` is consumed once via `devices.attestation_jti UNIQUE`. Idempotency: if a successful enroll's HTTP response is lost and the mobile retries with the **same still-valid** attestation, `spl-relay` re-mints the **byte-identical** device token from the stored row rather than rejecting. A consumed `jti` re-presented with a different `(instance_id, device_fp)` — or one whose stored row predates the `device_id` column — is rejected as replay (409). The old device token's `jti` is what a revocation list would key on, if one existed; none does today.

### POST `/token/refresh`

Called by the mobile app to re-issue its device token without re-pairing. Body:

```json
{
  "device_token": "<current device token JWT>"
}
```

The presented token may be still-valid or recently expired within the 30-day refresh grace. `spl-relay` verifies its own prior Ed25519 signature and the normal `session.dial` claims, then mints a fresh 60-day device token with a new `jti`, `iat`, and `exp`, preserving the same `instance_id`, `device_id`/`sub`, and `device_fp`.

No attestation, client cert, or QR code is involved. Prior enrollment is proven by the relay's own signature on the device token; the relay still never sees the client cert and never sees tunnel payload. Refresh is stateless: it does not write to `devices`, because dial authentication is by signature alone.

A token expired beyond the 30-day grace is rejected with 401 and `reason: "expired"`; that is the mobile's signal to fall back to re-pair. An unknown `instance_id` is rejected with 404, and a revoked instance is rejected with 403.

Response (on success):

```json
{
  "device_token": "<JWT>",
  "expires_at": "<ISO8601>"
}
```

## validation in `spl-relay`

On every token-authenticated WebSocket upgrade request to `/session/listen` or `/session/dial`, the Worker:

1. Reads the `Authorization: Bearer <jwt>` header. For DATA dials to `/session/dial`, WebSocket clients that cannot set headers MAY present the same token as `?token=<jwt>`; the relay accepts this fallback and never logs the token value. Reject with 401 if absent or malformed.
2. Parses the JOSE header, extracts `kid`.
3. Looks `kid` up in the JWKS loaded from `env.JWKS_PUBLIC` (a JSON array of JWK public keys; see *JWKS publication* below). Reject with 401 if `kid` is unknown.
4. Verifies the Ed25519 signature using the matched public key.
5. Verifies the standard claims:
   - `aud == "spl-relay"`
   - `iss == <expected issuer for this deployment>` (`link.solstone.app` for sol pbc; configurable per self-host)
   - `exp > now`
   - `iat ≤ now + 60s` (allow 60s clock skew on the issued-at side)
   - `scope` matches the route (`session.listen` for `/session/listen`; `session.dial` for `/session/dial`)
   - for `session.listen`, `sub` starts with `home:` and `ca_fp` is present and matches `^sha256:[0-9a-f]{64}$`
   - for `session.dial`, `sub` starts with `device:` and `device_fp` is present and matches `^sha256:[0-9a-f]{64}$`
6. Applies the session entitlement gate, when the deployment sets `ENTITLEMENT_REQUIRED` to exactly `"true"`. That is the only D1 read on these two routes: it resolves the instance row and refuses an instance that is unknown, revoked, or holding no live grant. With the gate off, `/session/listen` and `/session/dial` complete on the token alone. ⚠ **Do not assume a fresh self-host has it off.** The variable is unset in `relay/wrangler.toml`'s top-level `[vars]`, but the committed `[env.production]` block sets it to `"true"`, and the documented self-host deploy (`make deploy`) runs `wrangler deploy --env production`. A self-host that follows those steps has the gate **on**, and those two routes answer `402` until it either clears the variable or pushes an entitlement grant.

⚠ **The gate covers exactly those two routes.** `/session/pair-window`, `/session/pair-dial` and `/tunnel/<id>` never consult it, so a gate-on relay holding no grants still completes a full off-LAN pair ceremony and brokers the tunnel it produces. Entitlement gates the data session, not pairing.

`/session/pair-window` always reads D1, gate or no gate: it refuses a token whose `instance_id` has no row, and one whose row carries `revoked_at`. With the gate off that makes it the stricter of the two paths; with the gate on it is the weaker, since it never checks entitlement.

**What this does not do is enforce revocation.** There is no revocation table and no `jti` lookup. Revoking an *instance* sets `instances.revoked_at`. `/enroll/device`, `/token/refresh` and `/session/pair-window` all honor it; it reaches `/session/listen` and `/session/dial` only through the entitlement gate above; and ⚠ **`/enroll/home` does not check it at all**, so a revoked instance that re-enrolls is issued a fresh 365-day service token and gets `rotated_at` stamped. It cannot use that token — every route that would carry it refuses the instance — but it is why a rotation sweep counts only non-revoked instances. Revoking a *device* does not reach `spl-relay` at all: `devices.revoked_at` exists as a column and nothing in the relay writes or reads it. A revoked device keeps a working rendezvous until its device token expires; what stops it is the home refusing its client cert inside the inner TLS handshake, which is where [`pairing.md`](pairing.md) § revocation puts the authoritative check. That placement is deliberate: the inner TLS session terminates on the home, so the relay only ever forwards bytes it holds no key for. What that bounds is content. The relay still sees which instance, when, and how much, and a revoked device holding a live token still gets a working rendezvous. So the relay is not a second line of defense here, and this document should not be read as promising one.

Off-LAN pair-window admission, including the anonymous `/session/pair-dial`, is specified in [`pair-window.md`](pair-window.md). Pair-vs-dial selection is by request path, never by reading an unverified `scope`.

If any check fails, the Worker refuses the upgrade rather than accepting a socket. Checks 1–5 answer `401` with an `x-close-code: 4401` header; **check 6 answers `402` with `x-close-code: 4402`**, and a client that treats only 401/4401 as a refusal will mis-handle every entitlement rejection. ⚠ In both cases the upgrade never completes, so no WebSocket is accepted and **no close frame is sent** — a client waiting for a 4401 or 4402 close code will wait forever, and must read the header on the failed upgrade response instead. The Worker logs `event`, `route`, `reason`, `instance_id`, and `tunnel_id` when available. It does not log `jti` or any other token claim on failed authorization. **Never the token bytes, never claims-as-payload.**

`spl-relay` does **not** issue or refresh tokens on the WebSocket path. Issuance is HTTPS-only via the control-plane endpoints.

## rotation

The signing key has a 12-month rotation cadence. The overlap window has to outlast the device refresh interval, which is 48 days (see step 4), so it is **60 days**. The rotation mechanism is `kid`-keyed lookup into a multi-entry JWKS:

1. Generate the new keypair (new `kid` = fresh UUIDv7). See `../docs/signing-keys.md` for the generator script.
2. Push the **new JWKS** containing both old and new public keys: `wrangler secret put JWKS_PUBLIC --env production`.
3. Push the **new private key**: `wrangler secret put SIGNING_JWK --env production`. Issuance immediately switches to the new `kid`.
4. **Let the window outlast the device refresh interval, and move every home onto the new key inside it.**

   A device re-issues its own token when it passes 80% of its 60-day TTL, which is a token age of 48 days. For a device whose token was fresh on the day of the push, that is **48 days after the push**; a device already holding an older token moves sooner. You cannot count on sooner, and 48 days is a floor rather than a guarantee: it assumes a client that implements the trigger, and one that does not never moves on its own at all. ⚠ **An overlap window shorter than 48 days does not move every device.** A device whose token was fresh at the push has not attempted a refresh when a 30-day window closes, and the 30-day post-expiry grace does not rescue it: after the trim the refusal is an unknown `kid`, not an expiry, so refresh fails on the same check either way. Anything trimmed before 48 days is paid for in re-pairs.

   **Homes do not move on their own at all.** A service token minted under the old `kid` stays valid to the relay for up to 365 days, and is replaced only by another `POST /enroll/home`.

   🔴 **That call has to come from the home, and an operator cannot make it on the home's behalf.** The response carries the new token back to whoever sent the request, and nothing pushes it anywhere else — so a call made from an admin console rotates the D1 row while the home goes on holding its old, soon-to-be-unverifiable token. That is the whole of the argument: it is about where the answer lands, not about who can reach the endpoint. The operator's job is to *trigger* the home-side action that re-enrolls, then confirm it landed.

   Confirm with `GET /admin/instances`, which reports `created_at` and `rotated_at` per instance. The sweep is done when every non-revoked instance carries one of the two later than the moment the new key went live. Both are needed: a re-enroll stamps `rotated_at`, while an instance enrolling for the first time after the key push has a null `rotated_at` and is already on the new `kid`. ⚠ A fresh `rotated_at` proves only that *some* caller holding that instance's CA completed the call. It is evidence the home moved only if the home was the caller, which is why the trigger matters more than the check.

5. After the overlap window **and** that sweep, push a **trimmed JWKS** containing only the new key: `wrangler secret put JWKS_PUBLIC --env production`. The old key is no longer accepted and any token still bearing its `kid` fails validation cleanly.

⚠ **Trimming early costs a device an owner action; it costs a home its reachability until someone re-enrolls it.** Inside the window, a device holding an old-`kid` token repairs itself by refreshing. Once the key is trimmed it cannot, and re-pairing is the only route back. An owner can do that. A home has no equivalent move at all: it will fail every `/session/listen` open, holding a token that still looks valid to it, until someone enrolls it again. Its pairing material survives either way. Do not run step 5 on the calendar alone.

During the overlap window:

- Tokens minted under the old `kid` continue to verify against the old public key.
- Tokens minted under the new `kid` verify against the new public key.
- Live tunnels are not disrupted; in-flight tokens are not invalidated by the rotation itself.

The compromise runbook collapses this — see `../docs/signing-keys.md` for the kill-switch shape (publish a JWKS containing only the new public key, no overlap window). That invalidates every existing token instantly.

## JWKS publication

`spl-relay` publishes the **public** JWKS at:

```
GET https://link.solstone.app/.well-known/jwks.json
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

Workers store no token bytes. Token validation is stateless: signature and claim checks, with no D1 read of the token itself. A `jti` minted at `/enroll/home` or `/enroll/device` is recorded, so that token can be traced and a future revocation list would have something to key on. ⚠ **`POST /token/refresh` records nothing**, deliberately — it mints a new `jti` and writes no row, so once devices have refreshed, the `devices` table holds original `jti`s that match no token in circulation. Nothing looks any of them up today (see *validation in `spl-relay`* above).

The D1 shape, after every migration in `relay/migrations/` has been applied (informative; that directory owns it):

```sql
CREATE TABLE instances (
  instance_id       TEXT    PRIMARY KEY,
  ca_fp             TEXT    NOT NULL,
  ca_pubkey_pem     TEXT    NOT NULL,
  home_label        TEXT,
  created_at        INTEGER NOT NULL,
  service_token_jti TEXT    NOT NULL,
  rotated_at        INTEGER,
  revoked_at        INTEGER,
  entitled_until    INTEGER
);

CREATE UNIQUE INDEX idx_instances_ca_fp ON instances(ca_fp);

CREATE TABLE devices (
  device_jti      TEXT    PRIMARY KEY,
  instance_id     TEXT    NOT NULL,
  device_fp       TEXT    NOT NULL,
  device_label    TEXT,
  created_at      INTEGER NOT NULL,
  revoked_at      INTEGER,
  attestation_jti TEXT    NOT NULL UNIQUE,
  device_id       TEXT,
  FOREIGN KEY (instance_id) REFERENCES instances(instance_id)
);

CREATE INDEX idx_devices_instance ON devices(instance_id);
CREATE INDEX idx_devices_fp ON devices(instance_id, device_fp);
```

`attestation_jti` is what consumes a `home_attestation` exactly once. `device_id` is nullable only because it was added after the first deployment: a row written before that migration reads back `NULL` and cannot be re-minted idempotently, which is the case `/enroll/device` rejects as replay.

`relay/migrations/` also creates a small `pending_grants` holding table so an entitlement grant can arrive before its home enrolls. It carries an instance id and a grant expiry, holds no token material, and is not part of this contract.

D1 is for non-payload metadata only — never for tunnel bytes, never for keys, never for `authorized_clients.json` content (that lives only on the home).

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
