# tokens

The two long-lived JWTs that authorize a side to establish a WebSocket with `spl-relay` are the service token and device token. Both are issued by `spl-relay`'s control plane and signed by an Ed25519 key held only by sol pbc (or by the self-host operator, for self-hosted deployments). Both authorize **rendezvous only** — neither confers data access. Data access is gated by the TLS handshake inside the tunnel, against `authorized_clients.json` on the home.

This document specifies the token shape, claims, validation, and the JWKS-based rotation model. The signing-key lifecycle (generation, vault storage, provisioning, compromise response) is out of scope here — see [`../docs/signing-keys.md`](../docs/signing-keys.md) for the public-facing playbook. The rotation cadence and the overlap window are the exception: they are derived in § rotation below, and that playbook references them from here. sol pbc internal operators additionally follow their own operational playbook.

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

Authorizes a paired mobile device to open a `/session/dial` WebSocket to `spl-relay`, naming a specific home `instance_id`. V2 is scoped to the instance alone. The home shares an instance capability with its authenticated clients; it contains no device identity. Legacy unversioned tokens retain a device subject and certificate fingerprint during rollout.

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

JWT payload, legacy unversioned device token:

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
| `jti` | yes | token id; UUIDv7. Device enrollment derives it deterministically for retries; refresh replaces it. No device issuance or replay record is retained. Service-token issuance metadata remains instance-scoped. |

Workers MUST reject any token missing a required claim or carrying an unexpected `scope` for the requested route.

## Instance capability v2

A v2 dial capability has exactly these claims:

```json
{
  "iss": "link.solstone.app",
  "sub": "instance:<instance_id>",
  "aud": "spl-relay",
  "scope": "session.dial",
  "ver": 2,
  "instance_id": "<paired home instance_id>",
  "iat": 1745006400,
  "exp": 1750190400,
  "jti": "<uuidv7>"
}
```

V2 admits the bearer to the named instance; the home still authorizes the device inside mTLS. The relay rejects unknown token versions, an inconsistent subject, or extra v2 claims, including device fingerprints and predecessor identifiers. Service tokens remain unversioned. Timestamps are integer epoch seconds, and v2 expiration must follow issue time. An instance capability cannot listen or acquire service-authorized access.

### POST `/token/access`

The configured home sends exactly `{ "service_token": "<JWT>" }` over HTTPS, within 16 KiB. The relay verifies its `session.listen` signature, expiry, exact `home:<instance_id>` subject and matching enrolled CA. Missing instances return 404, revoked instances 403, invalid service credentials 401, and unavailable signing or verification configuration 503. Request fields cannot choose a different instance. This endpoint neither enrolls nor enables a home and does not apply entitlement; the actual session routes retain that gate.

Success returns `{ "protocol_version": 2, "device_token": "<JWT>", "expires_at": "<RFC3339>" }`. The legacy field name contains the instance capability. Each normal issuance and renewal has an independent fresh token ID; no issuance history or old/new-token mapping is stored. The home caches only the latest capability at service-configuration level and supplies it to authenticated paired clients.

### Upgrade and compatibility

`POST /token/refresh` accepts optional `protocol_version: 2`. With a valid legacy token this explicitly upgrades to v2, dropping the device subject and fingerprint. A v2 input always renews as v2, even without the request discriminator. Omitted version on a legacy input preserves legacy behavior. Unsupported requested versions return 400. The existing 60-day TTL and 30-day refresh grace apply to both forms.

Transitional `POST /enroll/device` also accepts `protocol_version: 2` and returns v2. It still receives the older home's fingerprint attestation transiently. Retry derivation uses `spl-enroll-token-v2`; the v1 derivation stays unchanged. V2 uses the instance subject, never the derived device ID. Same verified attestation and version yields the same response under the fixed signing configuration.

Every v2 success explicitly returns `protocol_version: 2` and an expiry matching the JWT. Clients must check that discriminator, decoded `ver`, exact subject, paired instance, absent device fields and usable expiry before recording v2 readiness. Decoding is not signature verification: response authenticity comes from relay HTTPS or home mTLS, and the relay checks the signature when the capability is used. An older relay may ignore the request version and return v1; clients may preserve compatible access but must not record a successful upgrade.

Legacy acceptance is a rollout choice, not an expiry timer: legacy refresh can perpetuate old claims. Retire it only after checking maintained-client compatibility. Reusing a bearer remains correlatable, and the relay still sees the instance and network connection metadata.

## TTLs

| token | TTL | rotation |
|---|---|---|
| service token | 365 days | no automatic re-issue. The token is replaced when **the home** calls `POST /enroll/home` again, carrying its existing `instance_id` and `ca_pubkey` |
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
  "ca_pubkey": "<PEM>"
}
```

Bodies over 32 KiB are rejected with 413 before parsing. A `ca_fp` backs at most one instance: a new enroll whose `ca_fp` matches a different instance is rejected with 409, distinct from the `ca_mismatch` 409 for an `instance_id` trying to change its own CA.

`spl-relay` records (`instance_id`, `ca_fp`, the `ca_pubkey` PEM itself, `created_at`) in D1 and issues a service token.

`ca_fp` is **SHA-256 over the DER `SubjectPublicKeyInfo`**: the bytes carried inside the PEM armor, not the armored text, and not a certificate. `spl-relay` strips the BEGIN/END lines and all whitespace, base64-decodes the body, and digests exactly the bytes it then imports as an ECDSA-P256 SPKI public key. The result is rendered `sha256:<64 lowercase hex>`. Every fingerprint in this protocol is taken over DER; [`identity.md`](identity.md) enumerates them and says which input each one covers.

Response:

```json
{
  "service_token": "<JWT>",
  "expires_at": "<ISO8601>"
}
```

**A repeat call is the rotation path.** `/enroll/home` is idempotent on `instance_id`: a second call carrying the same `ca_pubkey`, compared as text after trimming surrounding whitespace, mints a fresh 365-day service token with a new `jti`, replaces the recorded `service_token_jti`, stamps `rotated_at`, and returns the new token. No paired device has to re-pair. This is the only path by which a service token is ever replaced.

Home labels remain local to the home. Legacy `home_label` request fields are ignored and are absent from storage and admin projections.

In v1, `/enroll/home` is **neither gated nor rate-limited**: no waitlist, no payment gate, and no per-endpoint request limit anywhere in the Worker. ⚠ A deployment that needs one has to put it in front of the Worker, because nothing in this repository provides it. Self-hosted deployments will replace this endpoint or its policy as appropriate.

### POST `/enroll/device`

Legacy enrollment and transitional off-LAN pairing with older homes use this endpoint. New direct pairing does not call it. Body:

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
| `jti` | yes | home-issued request identifier. It participates in deterministic issuance but is never stored. Different verified claims sharing this identifier are independent authorizations. |

Signature algorithm is ES256 (ECDSA-P256 / SHA-256), in either JOSE raw (r||s, 64 bytes, preferred) or DER-encoded form. `spl-relay` accepts both — home implementations may differ in whichever their local library emits, and the cost of supporting both is trivial.

**Validation (by `spl-relay`) on every `/enroll/device`:**

1. Load the home's `ca_pubkey_pem` from D1 for the named `instance_id`. If absent → 404.
2. Parse the `home_attestation` header; reject if `alg ≠ ES256` or `typ ≠ home-attest`.
3. Verify the ECDSA signature against the home's CA public key.
4. Check claims per the table above, including the 5-minute lifetime cap and the `device_fp` shape (`^sha256:[0-9a-f]{64}$`).
5. Derive the device subject and token ID from canonical verified claims, using the attestation issue time for the token issue time, and sign the response deterministically. Write no device or replay state.
6. On success, mint a device token (see below).

**Why this shape.** An open design question asked what proves a client cert was legitimately paired with a specific home before `spl-relay` will mint a device token. The alternatives considered:

- *Chain validity alone.* Too weak: chain validity proves the home issued the cert at some point, not that it did so recently or intentionally for this mobile. Anyone who later captures a stale client cert could mint new device tokens.
- *Bootstrap-token-plus-nonce.* Similar security, extra endpoint. The proposed home-signed JWT carries the same signal — fresh signature, scoped to `(instance_id, device_fp)`, short-lived — in a single compact blob on an existing endpoint.
- *mTLS from the home to `spl-relay` at `/enroll/device`.* Would require threading the home's CA private key through the enrollment path, which it isn't on otherwise. Bigger attack surface on the control plane with no marginal benefit over a signed JWT.

The compatibility attestation proves home authorization without transferring the CA private key. Its replay behavior is stateless deterministic issuance, specified below. New homes deliver an instance capability through the encrypted pairing response or authenticated application API instead.

Response (on success):

```json
{
  "device_token": "<JWT>",
  "expires_at": "<ISO8601>"
}
```

Retries of the same still-valid verified attestation produce byte-identical responses while the issuer and signing key remain fixed. Canonical input is the JSON array `[iss, aud, scope, instance_id, device_fp, iat, exp, jti]`, encoded as UTF-8. For each identifier, hash a domain string, a zero byte and that array with SHA-256: `spl-enroll-device-v1` for the subject and `spl-enroll-token-v1` for the token ID. Take the first 16 digest bytes, replace bytes 0–5 with the attestation's `iat * 1000` as a big-endian timestamp, and set UUIDv7 version/variant bits. Token `iat` is attestation `iat`; TTL and JSON claim ordering are fixed by this implementation. ES256 signature randomness, JSON property order and unrecognized extensions do not affect issuance.

This deliberately replaces the former cross-payload `jti` collision ledger. Another validly home-signed claim set sharing a `jti` gets a different response; the home already has authority to authorize devices. This identifier is not the owner's one-shot pairing nonce. Expired or invalid attestations still reject on every attempt.

### POST `/token/refresh`

Called by the mobile app to re-issue its device token without re-pairing. Body:

```json
{
  "device_token": "<current device token JWT>"
}
```

The presented token may be still-valid or recently expired within the 30-day refresh grace. `spl-relay` verifies its own prior Ed25519 signature and the normal `session.dial` claims, then mints a fresh 60-day device token with a new `jti`, `iat`, and `exp`, preserving the same `instance_id`. An unversioned legacy request preserves `device_id`/`sub` and `device_fp`; explicit v2 upgrade and all v2 renewals use only the instance claims described below.

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
   - for legacy `session.dial`, `sub` starts with `device:` and `device_fp` is present and matches `^sha256:[0-9a-f]{64}$`; v2 uses the exact claim shape below
6. Applies the session entitlement gate, when the deployment sets `ENTITLEMENT_REQUIRED` to exactly `"true"`. That is the only D1 read on these two routes: it resolves the instance row and refuses an instance that is unknown, revoked, or holding no live grant. With the gate off, `/session/listen` and `/session/dial` complete on the token alone. ⚠ **Do not assume a fresh self-host has it off.** The variable is unset in `relay/wrangler.toml`'s top-level `[vars]`, but the committed `[env.production]` block sets it to `"true"`, and the documented self-host deploy (`make deploy`) runs `wrangler deploy --env production`. A self-host that follows those steps has the gate **on**, and those two routes answer `402` until it either clears the variable or pushes an entitlement grant.

⚠ **The gate covers exactly those two routes.** `/session/pair-window`, `/session/pair-dial` and `/tunnel/<id>` never consult it, so a gate-on relay holding no grants still completes a full off-LAN pair ceremony and brokers the tunnel it produces. Entitlement gates the data session, not pairing.

`/session/pair-window` always reads D1, gate or no gate: it refuses a token whose `instance_id` has no row, and one whose row carries `revoked_at`. With the gate off that makes it the stricter of the two paths; with the gate on it is the weaker, since it never checks entitlement.

**What this does not do is enforce revocation.** There is no revocation table and no `jti` lookup. Revoking an *instance* sets `instances.revoked_at`. `/enroll/device`, `/token/refresh` and `/session/pair-window` all honor it; it reaches `/session/listen` and `/session/dial` only through the entitlement gate above; and ⚠ **`/enroll/home` does not check it at all**, so a revoked instance that re-enrolls is issued a fresh 365-day service token and gets `rotated_at` stamped. It cannot use that token — every route that would carry it refuses the instance — but it is why a rotation sweep counts only non-revoked instances. Revoking a device is enforced by the home; the relay holds no per-device revocation row. A revoked device keeps a working rendezvous until its device token expires; what stops it is the home refusing its client cert inside the inner TLS handshake, which is where [`pairing.md`](pairing.md) § revocation puts the authoritative check. That placement is deliberate: the inner TLS session terminates on the home, so the relay only ever forwards bytes it holds no key for. What that bounds is content. The relay still sees which instance, when, and how much, and a revoked device holding a live token still gets a working rendezvous. So the relay is not a second line of defense here, and this document should not be read as promising one.

Off-LAN pair-window admission, including the anonymous `/session/pair-dial`, is specified in [`pair-window.md`](pair-window.md). Pair-vs-dial selection is by request path, never by reading an unverified `scope`.

If any check fails, the Worker refuses the upgrade rather than accepting a socket. Checks 1–5 answer `401` with an `x-close-code: 4401` header; **check 6 answers `402` with `x-close-code: 4402`**, and a client that treats only 401/4401 as a refusal will mis-handle every entitlement rejection. ⚠ In both cases the upgrade never completes, so no WebSocket is accepted and **no close frame is sent** — a client waiting for a 4401 or 4402 close code will wait forever, and must read the header on the failed upgrade response instead. The Worker emits only fixed `event`, `route` and `reason` classifications for authorization failures. It does not log `jti` or any other token claim on failed authorization. **Never the token bytes, never claims-as-payload.**

`spl-relay` does **not** issue or refresh tokens on the WebSocket path. Issuance is HTTPS-only via the control-plane endpoints.

## rotation

The signing key has a 12-month rotation cadence with a **90-day overlap window**, measured from the step 3 push below. This section is where that number is derived; other documents reference it rather than restating it.

**Where 90 comes from.** A device token is refreshable for its first 90 days and no longer: a 60-day TTL plus the 30-day post-expiry grace. Issuance switches to the new `kid` at step 3, so the newest token still bearing the old `kid` is minted exactly as the window opens, and 90 days later it is past refreshing whatever anyone does. Hold the old key that long and every device that could have moved itself has; trim sooner and you strand devices that were merely switched off.

⚠ **That bounds devices, and only devices.** A service token has a 365-day TTL and no refresh path at all, so no window length moves a home. This is why step 5 is released by the home sweep in step 4 and never by the calendar.

The rotation mechanism is `kid`-keyed lookup into a multi-entry JWKS. ⚠ The steps below are that mechanism, not the operator procedure: [`../docs/signing-keys.md`](../docs/signing-keys.md) § rotation is the runbook to execute, and it carries the generator invocation and the key-archival step that this list does not.

1. Generate the new keypair (new `kid` = fresh UUIDv7). See `../docs/signing-keys.md` for the generator script.
2. Push the **new JWKS** containing both old and new public keys: `wrangler secret put JWKS_PUBLIC --env production`.
3. Push the **new private key**: `wrangler secret put SIGNING_JWK --env production`. Issuance immediately switches to the new `kid`.
4. **Hold the old key 90 days from the step 3 push, and move every home onto the new key inside that window.**

   A running device re-issues its own token when it passes 80% of its 60-day TTL, a token age of 48 days. For a device whose token was fresh on the day of the push that is **48 days after the push**; one already holding an older token moves sooner. So 48 days is the floor for a device that is *awake the whole time*, and it is not the number to size the window on.

   ⚠ **The device that decides the window is the one that was switched off.** It comes back inside its 30-day grace still able to refresh, but only while the old `kid` is published. Trim before then and it cannot use the grace at all, because the refusal it meets is an unknown `kid` rather than an expiry. It re-pairs instead, which costs its owner a physical QR ceremony for nothing.

   ⚠ 90 days bounds what the *protocol* can do, not what a fleet will do. It assumes a client that implements the refresh trigger; one that does not never moves on its own at all, whatever the window.

   **Homes do not move on their own at all.** A service token minted under the old `kid` stays valid to the relay for up to 365 days, and is replaced only by another `POST /enroll/home`.

   🔴 **That call has to come from the home, and an operator cannot make it on the home's behalf.** The response carries the new token back to whoever sent the request, and nothing pushes it anywhere else — so a call made from an admin console rotates the D1 row while the home goes on holding its old, soon-to-be-unverifiable token. That is the whole of the argument: it is about where the answer lands, not about who can reach the endpoint. The operator's job is to *trigger* the home-side action that re-enrolls, then confirm it landed.

   Confirm with `GET /admin/instances` — bearer-gated on the deployment's `GRANT_SECRET`, like every admin route — which reports `created_at` and `rotated_at` per instance. The sweep is done when every non-revoked instance carries one of the two later than the moment the new key went live. Both are needed: a re-enroll stamps `rotated_at`, while an instance enrolling for the first time after the key push has a null `rotated_at` and is already on the new `kid`. ⚠ A fresh `rotated_at` proves only that *some* caller holding that instance's CA completed the call. It is evidence the home moved only if the home was the caller, which is why the trigger matters more than the check.

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

The relay stores instance admission state: ID, CA public key/fingerprint, service-token issuance metadata, revocation and entitlement. It also holds bounded purge-operation receipts and pending instance grants. The authoritative schema is `relay/migrations/`.

There is no device table, device label, home label, certificate-fingerprint history or attestation replay ledger. Enrollment and refresh write no per-device state. Legacy bearer tokens still reveal their device subject and fingerprint transiently when presented; v2 issuance omits those claims, while legacy acceptance remains available during client rollout. Socket routing attachments survive Durable Object hibernation for live connections, and the instance listener-generation counter is persistent.

### Stateless enrollment transition

1. Deploy row-free writers with `ENROLLMENT_PAUSED=true`. Confirm every serving version has stopped device enrollment; do not mix it with the old writer. Dial and refresh continue, although a Durable Object deployment may disconnect sockets and require reconnect.
2. Wait at least 360 seconds after the last old writer can serve, covering the maximum accepted attestation lifetime and clock skew. Existing randomly issued credentials remain valid; interrupted enrollment attempts may need fresh ceremony material after expiry.
3. Apply migration 0011 to drop `devices` and the `instances.home_label` column. Do not create a device-table export for rollback. Verify schema absence and test old credential dial/refresh with the remaining instance state.
4. Unpause enrollment. Rollback may use only versions compatible with the minimized schema and logging policy; never restore the old writers or identifying logs.

Use the same enrollment pause and 360-second drain before routine changes to the signing key, issuer, TTL or canonical issuance algorithm. Publish new verification keys before switching the signing key and retain verification overlap as described in [signing keys](../docs/signing-keys.md). Emergency key retirement takes precedence over byte-identical retries: retire compromised keys immediately and record that exception.

Active-store deletion is not historical-copy erasure. D1 Time Travel, provider log retention and any prior exports have separate lifetimes. Verify those copies and their expiry/deletion before making a no-retention claim; deployment or database recreation alone does not establish provider erasure.
