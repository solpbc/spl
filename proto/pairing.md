# pairing

How a mobile device first becomes able to dial a particular home solstone through `spl-relay`.

The end state of a successful pairing:

- The mobile device holds a **client cert** signed by the home's local CA, with the matching private key in the platform keychain. The **iOS** client stores it with `kSecAttrAccessibleAfterFirstUnlock` — **deliberately backup-migratable** (a researched UX choice so pairing survives a device restore/migration); device-instance identity is anchored by the device-local observer ingest keys rather than by making the pairing bundle non-migratable. The **macOS** client stores it in the Data Protection keychain with `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` (device-bound). Both are `AfterFirstUnlock` so background delivery keeps working while the device is locked.
- The home holds the device's cert **fingerprint** in `authorized_clients.json`, alongside the device label and pair date.
- When relay access is available, the mobile holds an instance capability delivered by the home, or a compatible legacy device token. Successful direct pairing does not require relay access.
- Future connections authenticate at the data plane with the TLS client certificate. Relay connections also present their admission capability to the rendezvous.

This is a one-time ceremony per device. Re-pairing is identical (revoke first, pair again).

v1 supports a LAN-direct pairing form and an off-LAN **relay-addressed** pairing form. The LAN-direct QR wire contract is specified below; the off-LAN relay form is the `0x06` home-opened pairing window specified in [`pair-window.md`](pair-window.md). The inner certificate ceremony remains the same. Off-LAN use additionally requires relay access as described in step 8.

> **Pair-link and relay hosts have separate roles:**
> - **`go.solstone.app`** is the **pair-link / universal-link host** — every QR encodes `https://go.solstone.app/p#…`, which opens the app (or the install-fallback page). It serves only the app-association files and the landing page; it holds no keys and relays nothing.
> - **`link.solstone.app`** is the **`spl-relay` endpoint** — the JWT issuer and session endpoint (`/session/*`, `/tunnel/*`). Device enrollment remains a legacy compatibility path. Self-hosters substitute their own relay origin (carried in the QR's `relay_origin`); the pair-link host stays `go.solstone.app`.
>
> Direct pairing does not require a device request to the relay. A self-hosted relay uses its configured origin.

## actors

- **home** — the python `spl.pair` server inside solstone, plus the local CA. Generates the QR. Signs the CSR. Updates `authorized_clients.json`.
- **convey** — the home's HTTPS UI. Surfaces the "Pair a phone" button and displays the QR.
- **mobile** — the solstone iOS app. Scans the QR. Generates an on-device keypair. Posts the CSR. Stores the resulting cert and device token in Keychain.
- **spl-relay** — Cloudflare-hosted relay. Issues instance capabilities to the configured home; legacy clients enroll separately after pairing. Does not see the inner encrypted pairing exchange. Legacy enrollment sends a signed fingerprint attestation separately.

## the local CA

On first run, solstone generates a self-signed CA on the home machine:

- **Algorithm:** ECDSA-P256 (per spec decision log 2026-04-18 — Node/Bun TLS defaults don't advertise Ed25519 in signature schemes; ECDSA-P256 is the cross-stack baseline).
- **Validity:** 10 years.
- **Key storage:** the CA private key lives on disk, encrypted at rest under a key derived from the owner's existing solstone unlock secret. Never transmitted, never escrowed.
- **Certs issued by this CA** are the mobile client certs signed during pairing.

The CA is per-home. Two solstone installs have two unrelated CAs; mobile devices paired with one cannot speak to the other.

## the ceremony

Step by step. Times are typical, not specified — the only enforced TTL is the nonce.

### 1. owner taps "Pair a phone" in convey

Convey calls into the local `spl.pair` HTTPS server (loopback, port chosen at solstone startup). The pair server:

- For direct (LAN) form: generates a 128-bit (16-byte) random **nonce**.
- For relay form: generates the pair-window nonce specified in [`pair-window.md`](pair-window.md).
- Records `(nonce, expires_at, used = false)` in an in-memory single-use table. Direct nonce TTL is 5 minutes.
- Returns a **pair link** of the shape `https://go.solstone.app/p#<uppercase Crockford base32 blob>`.

In the direct form, the decoded blob carries `<lan-ip>` (the home's address on the local subnet), `<port>`, and the nonce. The nonce is the only sensitive material in the link — without a valid nonce, the `/pair` endpoint refuses to enroll.

### 2. convey displays the QR

Convey renders a QR code encoding a link of the form:

```text
https://go.solstone.app/p#<uppercase Crockford base32 blob>
```

The form is discriminated by the first decoded byte (`version`), never by URL path.

Direct form, version `0x04` (40 bytes):

| Offset | Len | Field | Encoding |
|--------|-----|-------|----------|
| 0 | 1 | version | `0x04` |
| 1 | 1 | addr_type | `0x01` = IPv4 |
| 2 | 4 | ipv4 | raw IPv4 bytes |
| 6 | 2 | port | unsigned big-endian |
| 8 | 16 | nonce | 128-bit single-use nonce |
| 24 | 16 | ca_fp | first 16 bytes of SHA-256 over the CA cert DER |

**CA pin note:** direct form pins SHA-256(cert DER), first 16 bytes. The off-LAN `0x06` form's SPKI pin is specified in [`pair-window.md`](pair-window.md). A parser MUST key the pin algorithm off version and tag so future native clients stay forward-compatible. The home's HTTP `pair-start` response also carries a human-facing `ca_fingerprint` field; that value stays the full cert-DER SHA-256 in both postures.

Direct form conformance vector uses fixed inputs: `addr_type=0x01`, `address=192.0.2.42`, `port=7070`, `nonce=a1b2c3d4e5f607181122334455667788`, `ca_fp=deadbeefcafebabe0123456789abcdef`.

```
https://go.solstone.app/p#0G0W000258DSX8DJRFAEBXG7308J4CT4ANK7F26YNPZEZJQYQAZ028T5CY4TQKFF
```

Multi-candidate direct form, version `0x05` (variable length): the same LAN-direct ceremony, but the home advertises several of its own addresses in one link (multiple NICs / addresses on the subnet), and the client races them. All candidates share one port.

| Offset | Len | Field | Encoding |
|--------|-----|-------|----------|
| 0 | 1 | version | `0x05` |
| 1 | 1 | addr_type | `0x01` = IPv4 |
| 2 | 1 | count | number of candidate addresses, 1–4 |
| 3 | 2 | port | unsigned big-endian, shared by all candidates |
| 5 | 4 × count | ipv4[] | `count` raw IPv4 addresses, 4 bytes each |
| 5 + 4·count | 16 | nonce | 128-bit single-use nonce |
| 5 + 4·count + 16 | 16 | ca_fp | first 16 bytes of SHA-256 over the CA cert DER |

Total length is `5 + 4·count + 32`. A `0x05` link whose count is outside `1...4` is malformed and MUST be refused before key generation or dialing. The `0x05` form carries the same single nonce and single `ca_fp` as `0x04`; only the address list differs. The client may race or stagger connection establishment across a bounded candidate set (own-subnet proximity first), coalescing exact duplicate host/port endpoints. Across the whole candidate set it MUST begin at most one nonce-bearing pair request. It may advance to another candidate only while it knows that no request bytes were sent. The ceremony becomes committed immediately before invoking the request write; any error returned by or after that invocation — including a timeout, reset, lost or malformed response, or later verification or persistence failure — is terminal for that code and MUST NOT be retried on another candidate. The LAN-only refusal in step 3 applies to **every** candidate — a link with any public-address candidate is refused as a whole.

Candidate-count conformance cases:

| Encoded `0x05` count | Required result |
|----------------------|-----------------|
| `0` | refuse as malformed before key generation or dialing |
| `1` through `4` | continue to address admission |
| `5` through `255` | refuse as malformed before key generation or dialing |

The rest of this ceremony describes the direct LAN completion path (identical for `0x04` and `0x05`).

Owner-visible strings (per spec):

- `LITERAL: "Scan this code with sol on your phone over the same wi-fi or your own vpn."`
- `LITERAL: "This code expires in 5 minutes and only works once."`

### 3. mobile scans

The mobile app parses the QR payload and:

- Verifies every candidate address is in the explicit direct-pair allow-list (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, IPv4 link-local `169.254.0.0/16`, RFC 6598 shared address space `100.64.0.0/10`, IPv6 ULA `fc00::/7`, loopback). v1 refuses every other address at this step, including public addresses — the direct-pair constraint is enforced client-side, not just by the address the QR happens to contain. For the `0x05` multi form the whole link is refused unless **all** candidates satisfy this.
- Confirms with the owner: `LITERAL: "Pair with your journal over this local network?"` (showing the device label only after the next step).

Address-admission conformance cases (normative policy vectors):

| Candidate address or set | Required result |
|--------------------------|-----------------|
| `100.63.255.255` | refuse |
| `100.64.0.0` | admit |
| `100.127.255.255` | admit |
| `100.128.0.0` | refuse |
| `169.254.0.1` | admit as IPv4 link-local |
| `fd7a:115c:a1e0::1` | admit as IPv6 ULA |
| canonical direct vector `192.0.2.42` | decode successfully, then refuse before any dial |
| `0x05`: `192.168.1.10`, `100.64.0.5` | admit the whole link |
| `0x05`: `192.168.1.10`, `192.0.2.42` | refuse the whole link before any dial |

The `0x04` and `0x05` forms currently encode IPv4 only. The IPv6 row pins address-classification policy for an address-bearing form that supports IPv6; it does not define a new wire encoding.

### 4. mobile generates an on-device keypair

In the platform keychain (see the end-state note above for accessibility — iOS `AfterFirstUnlock`, macOS `AfterFirstUnlockThisDeviceOnly`):

- **Algorithm:** ECDSA-P256 (matches the home CA's signature algorithm).
- The private key never leaves the device; the public key is encoded into a **CSR** along with a device label (default: the iOS device name; owner-editable).

### 5. mobile posts the CSR to the pair URL

The mobile opens a **cert-less, CA-pinned TLS 1.3** connection to the candidate's `<lan-ip>:<port>` (the client presents no client cert — it does not have one yet; it pins the home's self-signed CA cert against the `ca_fp` from the QR), establishes the frame multiplexer over it, and over that connection makes the pair request:

```
POST /app/network/pair?token=<nonce hex>
Content-Type: application/json

{
  "csr": "<PEM-encoded CSR>",
  "device_label": "iPhone"
}
```

The single-use **nonce travels as the `token` query parameter (lowercase hex)**, not in the JSON body; the body carries only the CSR and device label. TLS verification uses the **CA fingerprint pin from the QR** (`ca_fp`), not the system trust store — the home presents its self-signed CA cert and the mobile rejects unless the SHA-256 of the presented cert matches the pinned fingerprint. This is the trust-on-first-use moment, but it is gated by a fresh QR scan, so there is no leap of faith — the owner has just held the phone in front of the home. (The pair request rides the same inner-TLS + mux transport as everyday tunnel traffic; see [`framing.md`](framing.md). Requests are minimal HTTP/1.1; chunked transfer-encoding is not used.)

### 6. home validates and signs

The pair server checks the nonce:

- Exists in the in-memory table → continue.
- Not yet used → mark `used = true` immediately (single-use enforcement, before any further work).
- `expires_at > now` → continue.
- Otherwise → 410 Gone, no body. The mobile sees `LITERAL: "This pairing code has expired. Generate a new one on your solstone."`.

If the nonce passes, the home signs the CSR with the local CA → a mobile **client cert** with:

- Subject CN = the device label (free-form, used only for human display).
- Validity = 10 years (matches CA validity; revocation is via fingerprint file, not expiry).
- Extensions: `keyUsage = digitalSignature`, `extendedKeyUsage = clientAuth`.

The home computes the SHA-256 fingerprint of the new cert and writes a new entry to `authorized_clients.json`:

```json
{
  "fingerprint": "sha256:<hex>",
  "device_label": "iPhone",
  "paired_at": "2026-04-19T17:42:13Z",
  "instance_id": "<home_instance_id>"
}
```

`authorized_clients.json` is the source of truth for revocation. The TLS layer reloads it on mtime change (polled at 0.5 s). See [`session.md`](session.md) for the runtime check.

### 7. home returns cert + chain + home attestation

Response body:

```json
{
  "client_cert": "<PEM>",
  "ca_chain": ["<home CA PEM>"],
  "instance_id": "<home_instance_id>",
  "home_label": "<owner-named home, e.g. 'living room mac'>",
  "home_attestation": "<compact JWS, ES256>"
}
```

`home_attestation` is a short-lived JWT signed by the local CA private key and scoped to this particular pair ceremony. Shape, claims, and validation are specified in [`tokens.md`](tokens.md) §"POST /enroll/device". Legacy clients forward it verbatim to `/enroll/device` in step 8; the home never stores it and never signs a second one for the same device without a fresh pair ceremony.

The mobile stores `client_cert`, the matching private key (already in Keychain from step 4), and `ca_chain` (used to validate the home's TLS server cert during everyday tunnel use). It also stores `instance_id` — this is the address it will dial through `spl-relay`.

### 8. relay access after pairing

New clients finish direct pairing without contacting the relay. On an authenticated home connection they request GET `/app/network/api/relay/access`. An enabled home obtains and caches an instance capability using its own service token at [`/token/access`](tokens.md#post-tokenaccess); it never exposes that service token to devices. Optional acquisition failure leaves direct pairing and local use intact.

For off-LAN pairing, a new home obtains a valid capability before opening the pairing window, with sufficient lifetime for that window. The window is bound to the current relay configuration; changing or disabling the service cancels it. A failed acquisition refuses window start before consuming pairing consent state, and the owner can retry starting it.

The successful encrypted pair response includes an additive `relay_access` object:

```json
{
  "protocol_version": 2,
  "status": "ready",
  "relay_origin": "https://link.solstone.app",
  "instance_id": "<paired home instance_id>",
  "device_token": "<instance capability JWT>",
  "expires_at": "<RFC3339>"
}
```

Existing required pair-response fields remain present. Direct pairing may omit `relay_access` when unavailable; it must never be null. No capability acquisition is awaited after the pair is committed. Existing clients ignore the added object.

The authenticated access API returns the same ready object, or `{ "protocol_version": 2, "status": "not_configured" }` without relay contact when disabled, or a bounded 503 when configured access is unavailable. Only currently authorized linked clients can call it. Pairing peers cannot. Clients validate the paired instance, allowed relay origin, explicit version, decoded v2 claims and matching usable expiry before replacing their cache. Optional failures preserve usable access; an authenticated `not_configured` clears it. Asynchronous writes must belong to the current pairing/configuration generation.

New clients pairing off-LAN with an older home may use `/enroll/device` with its attestation and `protocol_version: 2`. An older relay may return unversioned legacy credentials; that is compatible access, not a completed v2 upgrade. New direct pairing to an older home remains locally usable until the home provides the access API; it does not silently enroll the device with the relay.

Legacy clients can still enroll with a valid home attestation. Issuance is deterministic for retries and retains no device or replay row, as specified in [`tokens.md`](tokens.md). Device names, labels and app versions belong to the authenticated home API and must not be sent in relay request headers.

## revocation

Revoking a device is a one-step operation **on the home, not on `spl-relay`.**

1. Owner taps `LITERAL: "Unpair device"` in convey.
2. Convey edits `authorized_clients.json`, removing the matching fingerprint entry.
3. The TLS layer's mtime poller reloads the file within ~500 ms.
4. The next dial from the revoked device opens the tunnel WS through `spl-relay` (rendezvous still works — the device token is still valid), but the home refuses the client cert inside the TLS handshake. Which alert it sends, and what the mobile shows the owner, are specified in [`session.md`](session.md) § 7.

This is the authoritative revocation point. The device token at `spl-relay` may remain valid; it confers no data access without the TLS handshake succeeding. v1 does not propagate revocation to `spl-relay`. Instance capabilities deliberately do not provide a per-device relay revocation mechanism.

The TLS-layer rejection is **not** an app-layer post-handshake drop. The prototype found (notes §8 + §11.3, meaning sol pbc's internal engineering notes, which are not published — ⚠ **not** this document's own step 8) that app-layer fingerprint checks produce silent disconnects with no clean error semantics, so the check runs inside the handshake, where a refusal has an alert to travel on and the mobile can tell one refusal from another.

⚠ Enforcing in the handshake only makes a specific alert *possible*; a home still has to choose one deliberately. A home that refuses without choosing is refusing correctly and telling the mobile nothing about which case it hit.

## why a nonce, not a long-lived secret

The nonce in the QR is short-lived, single-use, and exists only to bind a specific mobile-to-home conversation to a specific owner-initiated moment. It is not a credential — it grants nothing beyond the right to submit one CSR for one signing.

This means a leaked QR (over the owner's shoulder, in a video call, accidental screenshot) is harmless after 5 minutes or after a successful pair, whichever comes first. There is no long-lived "pairing secret" in the system that an attacker could capture.

## why on-device keypair generation, not server-issued

The mobile generates its own keypair so that the home (and `spl-relay`) never possess the device's private key. The home only ever sees the public key in the CSR. This is a structural property: even a compromised home cannot impersonate a paired device elsewhere; even a compromised `spl-relay` cannot mint a usable mobile identity (it can only mint device tokens, which are useless without the TLS-handshake-required client cert).

## off-lan: relay-addressed form

Off-LAN pairing is the `0x06` home-opened pairing window specified in [`pair-window.md`](pair-window.md). It lets a phone pair from anywhere without putting `instance_id` in the pair link; the relay routes by `RK` and learns `instance_id` only from the home's service token.

The blind-by-construction posture is preserved: `spl-relay` sees `instance_id` and `RK`, but never `S`, the home-side nonce, the CSR, the client cert, or pairing payload. LAN pairing remains the shortest trust-on-first-use path when the phone is near the home; relay-addressed pairing exists for the off-LAN posture.

## related

- [`tokens.md`](tokens.md) — the device token issued in step 8, and the service token the home uses to register its CA fingerprint with `spl-relay`.
- [`session.md`](session.md) — what the mobile does with the cert + token after pairing completes (dial, tunnel, TLS handshake).
- [`framing.md`](framing.md) — the multiplex inside the tunnel that pairing makes reachable.
- [`../docs/architecture.md`](../docs/architecture.md) — trust boundaries that explain why pairing has the shape it does.
