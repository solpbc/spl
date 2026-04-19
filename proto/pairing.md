# pairing

How a mobile device first becomes able to dial a particular home solstone through `spl-relay`.

The end state of a successful pairing:

- The mobile device holds a **client cert** signed by the home's local CA, with the matching private key in iOS Keychain (`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`).
- The home holds the device's cert **fingerprint** in `authorized_clients.json`, alongside the device label and pair date.
- The mobile device holds a **device token** issued by `spl-relay`'s control plane, scoped to (`home_instance_id`, this device).
- Future dial attempts from this device authenticate at the rendezvous (device token) and at the data plane (TLS client cert verified inside the handshake against the fingerprint file).

This is a one-time ceremony per device. Re-pairing is identical (revoke first, pair again).

v1 supports **LAN-primary pairing only.** The mobile and home must be on the same wifi at pair time. Off-LAN pairing fallback is **deferred to H2** — see *off-lan: deferred* at the end. Once paired, everyday use works from any network.

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

- Generates a 256-bit random **nonce**.
- Records `(nonce, expires_at, used = false)` in an in-memory single-use table. `expires_at = now + 5 minutes`.
- Returns a **pair URL** of the shape `https://<lan-ip>:<port>/pair?token=<nonce>`.

`<lan-ip>` is the home's address on the local subnet (the same address convey is reachable on); `<port>` is the pair server's port. The nonce is the only sensitive material in the URL — without a valid nonce, the `/pair` endpoint refuses to enroll.

### 2. convey displays the QR

Convey renders a QR code encoding the pair URL plus a **CA fingerprint pin** (SHA-256 of the home CA's public key). The mobile app uses this pin to detect a man-in-the-middle on the local LAN — even on a hostile wifi, only the real home's self-signed cert chain will match.

QR payload (URL-encoded query string format):

```
spl://pair?u=<base64url(pair_url)>&pin=<base64url(ca_fingerprint_sha256)>
```

The `spl://` scheme is recognized by the iOS app via Universal Link or in-app camera scanner; the user can also paste the URL manually if the QR scan fails.

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

### 7. home returns cert + chain

Response body:

```json
{
  "client_cert": "<PEM>",
  "ca_chain": ["<home CA PEM>"],
  "instance_id": "<home_instance_id>",
  "home_label": "<user-named home, e.g. 'living room mac'>"
}
```

The mobile stores `client_cert`, the matching private key (already in Keychain from step 4), and `ca_chain` (used to validate the home's TLS server cert during everyday tunnel use). It also stores `instance_id` — this is the address it will dial through `spl-relay`.

### 8. mobile acquires a device token from spl-relay

The mobile makes one HTTPS POST to `spl-relay`'s control plane:

```
POST https://spl.solpbc.org/enroll/device
{
  "instance_id": "<from step 7>",
  "client_cert": "<PEM>"
}
```

`spl-relay` validates that:

- The `client_cert` is signed by a CA whose fingerprint the home has registered with `spl-relay` at home enrollment (the home registers its CA fingerprint when it acquires its account token).
- The `instance_id` exists and the requesting client has not been revoked at the rendezvous layer (account-token revocation, distinct from `authorized_clients.json` — revocation in v1 is enforced at the TLS handshake on the home, but `spl-relay` honors a future revocation list for defense-in-depth).

If valid, `spl-relay` issues a **device token** — a JWT scoped to (`instance_id`, fingerprint), signed by `spl-relay`'s signing key (see [`tokens.md`](tokens.md)). Mobile stores it in Keychain alongside the client cert.

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

## off-lan: deferred

An off-LAN fallback ceremony — bootstrapping a pair through `spl-relay` when the phone and home are not on the same wifi — is on the H2 roadmap. The shape would involve `spl-relay`'s control plane brokering a one-shot CSR exchange via short-TTL keys in CF KV, with the home polling its listen WS for an enrollment signal. The full flow is sketched in `cpo/research/market/2026-04-17-cf-tunnel-embedded-architecture.md`.

v1 deliberately does not ship this. Reasons:

- LAN pairing is the trust-on-first-use moment users expect (matching AirPods, Apple TV, etc.). Putting that ceremony anywhere except "phone in front of solstone, on the same wifi" weakens the trust story.
- An off-LAN fallback adds a code path through `spl-relay` that handles enrollment material — even briefly. The blind-by-construction posture is cleanest when `spl-relay` has no role in pairing whatsoever.
- Alpha users will be technical and on home wifi at pair time. The constraint costs us nothing for v1.

If alpha feedback demands off-LAN, H2 reopens this. v1 ships LAN-only.

## related

- [`tokens.md`](tokens.md) — the device token issued in step 8, and the account token the home uses to register its CA fingerprint with `spl-relay`.
- [`session.md`](session.md) — what the mobile does with the cert + token after pairing completes (dial, tunnel, TLS handshake).
- [`framing.md`](framing.md) — the multiplex inside the tunnel that pairing makes reachable.
- [`../docs/architecture.md`](../docs/architecture.md) — trust boundaries that explain why pairing has the shape it does.
