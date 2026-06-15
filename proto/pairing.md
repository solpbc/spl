# pairing

How a mobile device first becomes able to dial a particular home solstone through `spl-relay`.

The end state of a successful pairing:

- The mobile device holds a **client cert** signed by the home's local CA, with the matching private key in iOS Keychain (`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`).
- The home holds the device's cert **fingerprint** in `authorized_clients.json`, alongside the device label and pair date.
- The mobile device holds a **device token** issued by `spl-relay`'s control plane, scoped to (`home_instance_id`, this device).
- Future dial attempts from this device authenticate at the rendezvous (device token) and at the data plane (TLS client cert verified inside the handshake against the fingerprint file).

This is a one-time ceremony per device. Re-pairing is identical (revoke first, pair again).

v1 supports a LAN-direct pairing form and an off-LAN **relay-addressed** pairing form. The QR wire contract for both is specified below; see *off-lan: relay-addressed form* for the relay posture. Once paired, everyday use works from any network.

> **Two hosts, by design.** This ceremony deliberately touches two different domains, and they are not interchangeable:
> - **`link.solpbc.org`** is the **pair-link / universal-link host** — every QR encodes `https://link.solpbc.org/p#…`, which opens the app (or the install-fallback page). It serves only the app-association files and the landing page; it holds no keys and relays nothing.
> - **`link.solstone.app`** is the **`spl-relay` endpoint** — where the device enrolls and dials (`/enroll/device`, `/session/*`, `/tunnel/*`) and the JWT issuer. Self-hosters substitute their own relay origin (carried in the QR's `relay_origin`); the pair-link host stays `link.solpbc.org`.
>
> Seeing both in this doc is correct. A QR host is always `link.solpbc.org`; an enroll/session/token host is always `link.solstone.app`.

## actors

- **home** — the python `spl.pair` server inside solstone, plus the local CA. Generates the QR. Signs the CSR. Updates `authorized_clients.json`.
- **convey** — the home's HTTPS UI. Surfaces the "Pair a phone" button and displays the QR.
- **mobile** — the solstone iOS app. Scans the QR. Generates an on-device keypair. Posts the CSR. Stores the resulting cert and device token in Keychain.
- **spl-relay** — Cloudflare-hosted relay. Issues the device token after the mobile completes pairing with the home. Does not see any pairing payload.

## the local CA

On first run, solstone generates a self-signed CA on the home machine:

- **Algorithm:** ECDSA-P256 (per spec decision log 2026-04-18 — Node/Bun TLS defaults don't advertise Ed25519 in signature schemes; ECDSA-P256 is the cross-stack baseline).
- **Validity:** 10 years.
- **Key storage:** the CA private key lives on disk, encrypted at rest under a key derived from the user's existing solstone unlock secret. Never transmitted, never escrowed.
- **Certs issued by this CA** are the mobile client certs signed during pairing.

The CA is per-home. Two solstone installs have two unrelated CAs; mobile devices paired with one cannot speak to the other.

## the ceremony

Step by step. Times are typical, not specified — the only enforced TTL is the nonce.

### 1. user taps "Pair a phone" in convey

Convey calls into the local `spl.pair` HTTPS server (loopback, port chosen at solstone startup). The pair server:

- For direct (LAN) form: generates a 128-bit (16-byte) random **nonce**.
- For relay form: generates a fresh 128-bit (16-byte) random **nonce**.
- Records `(nonce, expires_at, used = false)` in an in-memory single-use table. Direct nonce TTL is 5 minutes; relay nonce TTL is approximately 30 seconds, one TOTP step.
- Returns a **pair link** of the shape `https://link.solpbc.org/p#<uppercase Crockford base32 blob>`.

In the direct form, the decoded blob carries `<lan-ip>` (the home's address on the local subnet), `<port>`, and the nonce. The nonce is the only sensitive material in the link — without a valid nonce, the `/pair` endpoint refuses to enroll.

### 2. convey displays the QR

Convey renders a QR code encoding a link of the form:

```text
https://link.solpbc.org/p#<uppercase Crockford base32 blob>
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

Relay form, version `0x03` (54 bytes + optional origin):

| Offset | Len | Field | Encoding |
|--------|-----|-------|----------|
| 0 | 1 | version | `0x03` |
| 1 | 16 | instance_id | raw UUID bytes |
| 17 | 3 | current_totp | unsigned big-endian integer, value `0..999999` |
| 20 | 16 | rotating_nonce | 128-bit single-use nonce |
| 36 | 1 | ca_fp_tag | `0x01` = SHA-256 over DER SPKI, first 16 bytes |
| 37 | 16 | ca_fp | first 16 bytes of SHA-256 over the CA DER SubjectPublicKeyInfo (SPKI) |
| 53 | 1 | relay_origin_selector | `0x00` = well-known default relay; `N` (`1..255`) = custom origin byte length |
| 54 | N | relay_origin | UTF-8 bytes of the custom origin string; omitted when selector is `0x00` |

For relay form, `ca_fp` is exactly the `ca_fp` the relay stores at `/enroll/home`: SHA-256 over the DER SPKI produced from the submitted `ca_pubkey`. `current_totp` is the home-computed RFC 6238 TOTP (HMAC-SHA1, 30s step, 6 digits) that the phone forwards to the relay along with `instance_id`.

**CA pin note:** direct and relay forms pin different CA hashes, disambiguated by version and, for relay, `ca_fp_tag`. Direct = SHA-256(cert DER) first 16 bytes, no tag. Relay = `0x01`-tagged SHA-256(SPKI DER) first 16 bytes. A parser MUST key the pin algorithm off version and tag so future native clients stay forward-compatible. The home's HTTP `pair-start` response also carries a human-facing `ca_fingerprint` field; that value stays the full cert-DER SHA-256 in both postures and is NOT the relay QR's SPKI pin.

Conformance vectors use these fixed inputs: `instance_id=12345678-1234-5678-1234-567812345678`, `totp=123456`, `nonce=0123456789abcdef0123456789abcdef`, `ca_fp_spki=deadbeefcafebabe0123456789abcdef0123456789abcdef0123456789abcdef`.

Well-known relay origin (`relay_origin=None`):

```
https://link.solpbc.org/p#0C938NKR28T5CY0J6HB7G4HMASW03RJ004HMASW9NF6YY0938NKRKAYDXW0XXBDYXZ5FXENY04HMASW9NF6YY00
```

Custom relay origin (`relay_origin=https://relay.example`):

```
https://link.solpbc.org/p#0C938NKR28T5CY0J6HB7G4HMASW03RJ004HMASW9NF6YY0938NKRKAYDXW0XXBDYXZ5FXENY04HMASW9NF6YY5B8EHT70WST5WQQ4SBCC5WJWSBRC5PQ0V35
```

Direct form conformance vector uses fixed inputs: `addr_type=0x01`, `address=192.0.2.42`, `port=7070`, `nonce=a1b2c3d4e5f607181122334455667788`, `ca_fp=deadbeefcafebabe0123456789abcdef`.

```
https://link.solpbc.org/p#0G0W000258DSX8DJRFAEBXG7308J4CT4ANK7F26YNPZEZJQYQAZ028T5CY4TQKFF
```

The rest of this ceremony describes the direct LAN completion path. The phone-side completion ceremony for relay form is specified separately; this section fixes the QR wire contract.

User-visible strings (per spec):

- `LITERAL: "Scan this code with solstone mobile on the same wifi."`
- `LITERAL: "This code expires in 5 minutes and only works once."`

### 3. mobile scans

The mobile app parses the QR payload and:

- Verifies the URL points to a private/link-local IP (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, IPv6 ULA `fc00::/7`). v1 refuses public IPs at this step — the LAN-only constraint is enforced client-side, not just by the URL the QR happens to contain.
- Confirms with the user: `LITERAL: "Pair with solstone on this wifi?"` (showing the device label only after the next step).

### 4. mobile generates an on-device keypair

In iOS Keychain, with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`:

- **Algorithm:** ECDSA-P256 (matches the home CA's signature algorithm).
- The private key never leaves the device; the public key is encoded into a **CSR** along with a device label (default: the iOS device name; user-editable).

### 5. mobile posts the CSR to the pair URL

The mobile makes an HTTPS POST to the pair URL with body:

```json
{
  "nonce": "<from QR>",
  "csr": "<PEM-encoded CSR>",
  "device_label": "Jer's iPhone"
}
```

TLS verification at this step uses the **CA fingerprint pin from the QR**, not the system trust store. The home's TLS server presents its self-signed CA cert; the mobile rejects unless the SHA-256 of the presented cert matches the pinned fingerprint. This is the trust-on-first-use moment, but it is gated by a fresh QR scan, so there is no leap of faith — the user has just held the phone in front of the home.

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
  "device_label": "Jer's iPhone",
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
  "home_label": "<user-named home, e.g. 'living room mac'>",
  "home_attestation": "<compact JWS, ES256>"
}
```

`home_attestation` is a short-lived JWT signed by the local CA private key and scoped to this particular pair ceremony. Shape, claims, and validation are specified in [`tokens.md`](tokens.md) §"POST /enroll/device". The mobile forwards it verbatim to `/enroll/device` in step 8; the home never stores it and never signs a second one for the same device without a fresh pair ceremony.

The mobile stores `client_cert`, the matching private key (already in Keychain from step 4), and `ca_chain` (used to validate the home's TLS server cert during everyday tunnel use). It also stores `instance_id` — this is the address it will dial through `spl-relay`.

### 8. mobile acquires a device token from spl-relay

The mobile makes one HTTPS POST to `spl-relay`'s control plane:

```
POST https://link.solstone.app/enroll/device
{
  "instance_id": "<from step 7>",
  "home_attestation": "<from step 7>"
}
```

`spl-relay` validates the `home_attestation` against the home's registered CA public key (per [`tokens.md`](tokens.md) §"POST /enroll/device"). The attestation binds this specific device fingerprint to a specific pair ceremony within a 5-minute window; its `jti` is consumed exactly once via a D1 UNIQUE constraint. If valid, `spl-relay` issues a **device token** — a JWT scoped to (`instance_id`, fingerprint), signed by `spl-relay`'s signing key. Mobile stores it in Keychain alongside the client cert.

Pairing complete. The mobile now holds: ECDSA private key + client cert + CA chain + device token. User-visible: `LITERAL: "Paired with <home label>."`

## revocation

Revoking a device is a one-step operation **on the home, not on `spl-relay`.**

1. User taps `LITERAL: "Unpair device"` in convey.
2. Convey edits `authorized_clients.json`, removing the matching fingerprint entry.
3. The TLS layer's mtime poller reloads the file within ~500 ms.
4. The next dial from the revoked device opens the tunnel WS through `spl-relay` (rendezvous still works — the device token is still valid), but the TLS handshake on the home rejects the client cert via `verify_callback`. The mobile sees a TLS handshake failure, surfaced as `LITERAL: "This device was unpaired from your solstone."`

This is the authoritative revocation point. The device token at `spl-relay` may remain valid; it confers no data access without the TLS handshake succeeding. v1 does not propagate revocation to `spl-relay`. (Defense-in-depth — invalidate the device token too — is on the H2 list but not blocking.)

The TLS-layer rejection is **not** an app-layer post-handshake drop. The prototype found (§8 + §11.3) that app-layer fingerprint checks produce silent disconnects with no clean error semantics; v1 enforces the check inside the TLS handshake using pyOpenSSL's `verify_callback` precisely so the mobile receives a specific TLS alert and can show a meaningful error.

## why a nonce, not a long-lived secret

The nonce in the QR is short-lived, single-use, and exists only to bind a specific mobile-to-home conversation to a specific user-initiated moment. It is not a credential — it grants nothing beyond the right to submit one CSR for one signing.

This means a leaked QR (over the user's shoulder, in a video call, accidental screenshot) is harmless after 5 minutes or after a successful pair, whichever comes first. There is no long-lived "pairing secret" in the system that an attacker could capture.

## why on-device keypair generation, not server-issued

The mobile generates its own keypair so that the home (and `spl-relay`) never possess the device's private key. The home only ever sees the public key in the CSR. This is a structural property: even a compromised home cannot impersonate a paired device elsewhere; even a compromised `spl-relay` cannot mint a usable mobile identity (it can only mint device tokens, which are useless without the TLS-handshake-required client cert).

## off-lan: relay-addressed form

Off-LAN pairing is the relay-addressed QR form specified above. It lets a phone pair from anywhere by carrying the home `instance_id`, rotating TOTP, 128-bit nonce, CA SPKI pin, and relay origin in the QR.

The relay validates the TOTP by `instance_id` and mints the short-lived relay-side pairing authorization described in [`tokens.md`](tokens.md) and [`session.md`](session.md). The relay never sees the home-side pairing nonce, device role, CSR, client cert, or pairing payload.

The blind-by-construction posture is preserved: `spl-relay` handles rendezvous authorization metadata (`instance_id` + TOTP) but not enrollment material. LAN pairing remains the shortest trust-on-first-use path when the phone is near the home; relay-addressed pairing exists for the off-LAN posture. The phone-side completion ceremony for the relay form is specified separately; this document fixes the QR wire contract.

## related

- [`tokens.md`](tokens.md) — the device token issued in step 8, and the service token the home uses to register its CA fingerprint with `spl-relay`.
- [`session.md`](session.md) — what the mobile does with the cert + token after pairing completes (dial, tunnel, TLS handshake).
- [`framing.md`](framing.md) — the multiplex inside the tunnel that pairing makes reachable.
- [`../docs/architecture.md`](../docs/architecture.md) — trust boundaries that explain why pairing has the shape it does.
