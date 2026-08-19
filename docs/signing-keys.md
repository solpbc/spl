# signing keys

This document is the public-facing operational guide for the JWT signing keys used by `spl-relay`. It applies to both sol pbc's hosted deployment and any self-hosted instance.

`spl-relay` uses one signing keypair to mint and verify the JWTs that authorize WebSocket establishment with the relay. Lose the private key and every home has to enroll again; the old *public* key is still in `JWKS_PUBLIC` and on the transparency endpoint, so you can keep publishing it and let devices carry themselves across. **Leak** it and you have to trim the old key immediately, which forces every paired device to re-pair as well. See *key compromise*.

## the two key layers — do not conflate

`spl` has two cryptographic layers, with different keys, different algorithms, and different concerns. Mixing them up is the most common conceptual mistake.

| layer | algorithm | what it protects | where the keys live |
|---|---|---|---|
| **JWT signing layer** (this document) | **Ed25519 / EdDSA** | rendezvous: authorizes a WebSocket open to `spl-relay` | private: `env.SIGNING_JWK` (Worker secret); public: `env.JWKS_PUBLIC` (Worker secret + `/.well-known/jwks.json`) |
| **mTLS layer** (see [`../proto/pairing.md`](../proto/pairing.md), [`../proto/session.md`](../proto/session.md)) | **ECDSA-P256** | data: authorizes the actual byte exchange between mobile and home | home CA private key on the home machine, encrypted at rest under the owner's solstone unlock secret; mobile client cert in iOS Keychain |

The two layers are independent. The signing key never appears in any TLS handshake. The home CA never signs a JWT. **A compromise of one is not a compromise of the other.**

This document is about **only** the JWT signing layer.

## why Ed25519 for JWT signing

Both ECDSA-P256 and Ed25519 are cryptographically sound for JWT signing. We choose Ed25519 because:

- Deterministic signatures — no nonce-reuse foot-gun.
- Smaller keys (32-byte public, 32-byte private) and signatures (64 bytes); JWT bytes matter for the WebSocket handshake budget.
- First-class on Cloudflare Workers via Web Crypto's `Ed25519` algorithm (GA).
- Cleanest auditing surface for a service many third parties will inspect.

The mTLS layer can't use Ed25519 — Node and Bun TLS stacks don't advertise Ed25519 in signature schemes by default, so the handshake fails with `NO_SUITABLE_SIGNATURE_ALGORITHM`. ECDSA-P256 is the cross-stack baseline there. The two algorithms reflect the two ecosystems' constraints.

## key shape

JWK format (per RFC 7517 / RFC 8037):

```json
{
  "kty": "OKP",
  "crv": "Ed25519",
  "kid": "<UUIDv7>",
  "x": "<base64url public key, 32 bytes>",
  "d": "<base64url private key, 32 bytes — PRIVATE FIELD>",
  "alg": "EdDSA",
  "use": "sig"
}
```

`kid` is required and stable for the life of the keypair. It's how rotation works without disruption.

## generation — self-host

For self-hosters, the bundled generator script is the supported path:

```sh
cd relay
npm run gen-key
```

(Or invoke directly: `npm run gen-key -- --out ~/.spl/alternate-keypair.json` to override the path.)

The script:

1. Generates an Ed25519 JWK keypair via Web Crypto. There is no fallback; on a runtime whose Web Crypto lacks Ed25519 the script fails rather than substituting another algorithm.
2. Stamps a fresh `kid` (UUIDv7) and `created_at` timestamp.
3. Writes the keypair to `~/.spl/signing-keypair.json` (default; override with `--out`). File mode `0600`.
4. Prints the exact `wrangler secret put SIGNING_JWK` and `wrangler secret put JWKS_PUBLIC` commands to run next.
5. Warns clearly: this is the root of trust for your tunnel; lose it and every home must enroll again, and leaking it costs every paired device a re-pair on top.

Storage guidance for the keypair file:

- **Not in a cloud drive** (no iCloud, Dropbox, Google Drive). Cloud-synced is not a backup; it's a sync hazard with sharing surface area.
- **Offline backup** is required: print to paper, write to a hardware token, or copy to an encrypted USB stored physically separately.
- **Rotation is your responsibility.** No bug-bounty coverage from sol pbc for self-hosted instances.

## provisioning to `spl-relay`

Two Worker secrets, set via `wrangler secret put`:

```sh
# Private signing key (single keypair, JSON object — kid, kty, crv, x, d).
wrangler secret put SIGNING_JWK --env production

# Public JWKS (JSON object: { "keys": [ { kid, kty, crv, x, ... }, ... ] }).
wrangler secret put JWKS_PUBLIC --env production
```

Paste the JSON when prompted. wrangler stores both secrets encrypted at rest on Cloudflare's edge; they are exposed to the Worker only at runtime via `env.SIGNING_JWK` and `env.JWKS_PUBLIC`.

The Worker uses:

- `env.SIGNING_JWK` to sign tokens at the control-plane endpoints: `/enroll/home`, `/enroll/device`, and `/token/refresh`.
- `env.JWKS_PUBLIC` to verify tokens on every `/session/listen`, `/session/dial`, `/session/pair-window` and `/tunnel/<id>` upgrade, **and at `/token/refresh`**. The JWKS contains all currently valid public keys; verification looks up `kid` from the JWT header. (`/session/pair-dial` is anonymous and presents no token.)

⚠ `/token/refresh` is the one endpoint on both lists: it verifies the presented token against `JWKS_PUBLIC` and then signs its replacement with `SIGNING_JWK`. That is precisely why the overlap window works — a device refreshing inside it is admitted on the old `kid` and re-issued on the new one — and why trimming the JWKS ends the device's ability to recover itself.

### `/.well-known/jwks.json`

`spl-relay` exposes the current `env.JWKS_PUBLIC` at:

```
GET https://<your-relay-host>/.well-known/jwks.json
```

This is the transparency endpoint. Anyone can verify what key the relay is currently signing with — no internal access required. The endpoint is unauthenticated, returns a JSON object of the same shape stored in the secret, and is cached for 5 minutes.

For sol pbc's hosted deployment: `https://link.solstone.app/.well-known/jwks.json`.

## rotation

Default cadence: **12 months**, with a **90-day overlap window** measured from the step 3 push.

90 is derived rather than chosen: it is how long a device token stays refreshable. The reasoning lives in [`../proto/tokens.md`](../proto/tokens.md) § rotation; this runbook carries the number and the steps, not the derivation.

⚠ **Two things the number does not decide.** It bounds *devices*; a home has no refresh path at any window length, so step 5 is released by the sweep in step 4 and never by the calendar. And a 12-month cadence with a 90-day overlap keeps the old key **verifying** for 15 months, though it stops **signing** at step 3. If you need key lifetime bounded at 12 months, shorten the cadence to 9 rather than the overlap; shortening the overlap only moves the cost onto owners. On compromise none of this applies, because the kill switch trims immediately with no overlap at all.

The mechanism:

1. **Generate the new keypair to a new path:** `npm run gen-key -- --out ~/.spl/signing-keypair-<date>.json`. New `kid`. ⚠ Do not re-run the bare command — it refuses to overwrite an existing keypair file and exits non-zero, and the `--force` that would let it through would destroy the very key step 6 tells you to archive.
2. **Push the new JWKS containing both keys.** The new JSON is `{ "keys": [<old public>, <new public>] }`. Paste it into:

   ```sh
   wrangler secret put JWKS_PUBLIC --env production
   ```

3. **Push the new private key.** Issuance immediately switches to the new `kid`:

   ```sh
   wrangler secret put SIGNING_JWK --env production
   ```

4. **Hold the old key 90 days from the step 3 push, and move every home onto the new key inside that window.** Tokens minted under the old `kid` continue to verify against its public key in the JWKS. ⚠ The clock starts at step 3, not step 2 — issuance switches with the private key, so starting it at the JWKS push trims early by the whole step 2 to step 3 gap and strands the newest old-`kid` tokens.

   Devices carry themselves across, but not quickly. A running mobile re-issues its own 60-day token via `POST /token/refresh` at 80% of TTL, a token age of 48 days, so a device whose token was fresh on the day you pushed the key waits 48 days before it even tries.

   ⚠ **The device that decides the window is the one that was switched off**, not the running one above. It comes back inside its 30-day grace still able to refresh, but only while the old `kid` is published. Trim before then and it cannot use the grace at all, because the refusal it meets is an unknown `kid` rather than an expiry. It re-pairs instead, which costs its owner a physical QR ceremony for nothing.

   **Homes do not carry themselves across at all.** There is no endpoint that re-issues a service token, no timer in `spl-relay` that touches token lifetime, and a 365-day service token minted under the old `kid` will sit there unexpired long after the window closes. A home moves to the new key only when `POST /enroll/home` is called again ([`../proto/tokens.md`](../proto/tokens.md) §TTLs).

   🔴 **You cannot make that call for them, and the reason is not access — it is where the answer goes.** `/enroll/home` returns the new token to whoever sent the request, and nothing forwards it onward. An operator-side call therefore rotates the database row, stamps `rotated_at`, and leaves the home holding its old token: the sweep looks complete and the fleet is stranded. (`GET /admin/instances` does not expose `ca_pubkey_pem` either, but do not lean on that — you own the D1 database and could read it.) What you do instead is get each home to re-enroll itself: on solstone that is the owner disabling and re-enabling the private link, which calls the endpoint with the CA and label the home already holds.

   Then confirm with `GET /admin/instances`, which takes `Authorization: Bearer <GRANT_SECRET>` like every admin route. It reports `created_at` and `rotated_at` per instance, and the sweep is done when every non-revoked instance carries one of the two later than the moment you pushed the new private key. Check both: a re-enroll stamps `rotated_at`, while an instance that enrolled for the first time after the push has a null `rotated_at` and is already on the new `kid`. ⚠ `rotated_at` tells you the row changed, not that the home has the new token in hand — it is only the second half of the evidence, and the first half is that the home made the call.

5. **Push the trimmed JWKS**, once the window has passed *and* the sweep is complete. New JSON is `{ "keys": [<new public>] }`:

   ```sh
   wrangler secret put JWKS_PUBLIC --env production
   ```

   Any straggler token under the old `kid` now fails validation cleanly. That includes at `POST /token/refresh`, which verifies the presented token against this same JWKS: a device that missed the window cannot refresh its way back, because the refresh fails on the check that stranded it. The owner re-pairs that device from the home. The home's CA is untouched, so re-pairing simply mints the device a fresh certificate, and with it a new `cid` (the client id, defined in [`../proto/identity.md`](../proto/identity.md)). **A home does not recover on its own at all.** It will fail every `/session/listen` open, holding a token that still looks valid to it, until someone enrolls it again. That is why step 4 is a gate and not a wait.

6. **Archive the old keypair** somewhere offline. Keep it for **at least 90 days measured from the step 5 trim** (forensic and replay defense), then destroy it. That retention is a separate clock from the overlap window, and shares its length only by coincidence.

Live tunnels survive a rotation — `JWKS_PUBLIC` and `SIGNING_JWK` updates do not redeploy the Worker, so existing WebSockets aren't disconnected. (If a `wrangler deploy` is also part of the rotation for unrelated reasons, expect every WS to disconnect; clients reconnect within 10 s without re-pair.)

## key compromise

If you have any reason to believe the private signing key has been exposed — disk leak, supply-chain breach, accidental commit, employee departure with possible access — treat it as compromised. The default posture is **rotate immediately and force re-enroll**.

There is **no graceful migration window** on compromise. A migration window extends the attacker's window. The runbook is:

1. **Declare the incident.** Open an incident record. Note the time of detection and the suspected exposure window.
2. **Generate a replacement keypair** (per *generation* above). New `kid`.
3. **Publish a JWKS containing only the new public key:**

   ```sh
   wrangler secret put JWKS_PUBLIC --env production
   ```

   This is the kill switch. Every existing token instantly fails validation, including any minted by the attacker.

   ⚠ **Run steps 3 and 4 back to back.** Compromise inverts the rotation order deliberately, so between them the relay is still signing under the old `kid` while the JWKS no longer contains it. Anything `/enroll/home`, `/enroll/device` or `/token/refresh` mints in that gap is dead on arrival.

4. **Push the new private key:**

   ```sh
   wrangler secret put SIGNING_JWK --env production
   ```

5. **Get every home to re-enroll.** The kill switch invalidates service tokens too, and nothing in the protocol re-issues one. As in rotation step 4, **you cannot make the call for them** — `/enroll/home` hands the new token to its caller, so a call from your side rotates the row and leaves the home holding nothing. Trigger the home-side re-enroll (on solstone, the owner disables and re-enables the private link), then confirm against `GET /admin/instances` (bearer `GRANT_SECRET`) that every non-revoked instance has a `rotated_at` (or, for one first enrolled since the kill switch, a `created_at`) later than it. Until that call is made for an instance, its home cannot open `/session/listen` and is unreachable off-LAN. A paired device holding a now-invalid device token is refused at the rendezvous, not at TLS: the relay answers the WebSocket upgrade with `401` carrying an `x-close-code: 4401` header, and `POST /token/refresh` answers `401` without it. Neither is a close frame; the upgrade never completes. The owner re-pairs that device from the home, and the home's own CA is untouched, so the device simply receives a fresh certificate and a new `cid`.
6. **Archive the compromised keypair** with metadata noting compromise, root cause, and remediation. Do not delete — keep for forensic review.
7. **Self-hoster note.** If you operate your own relay, this runbook is yours to execute, and step 5 is the expensive one: it needs an action at every home and at every device, and none of it can be done from your side. Your users re-pair their devices through the home, and each home has to be made to re-enroll itself — it will not do that on its own against your new key, and you cannot do it for it. There is no sol pbc support path for self-hosted compromise — the trust chain is end-to-end yours.

Target: **< 4 hours from detection to the new key being live.**

## what compromise does *not* affect

The blind-by-construction architecture means a JWT signing key compromise has a bounded blast radius:

- **No payload data is exposed.** Tokens authorize the rendezvous, not the data. An attacker with a forged token can open a WebSocket to the relay, but cannot complete the inner TLS handshake without the matching mobile client cert (which lives only on a real paired device's Keychain).
- **No past sessions are decrypted.** TLS material is held by the home and the mobile device. The signing key never sees TLS plaintext.
- **No other deployments are affected.** Each deployment environment and each self-host has its own keypair.

That said: *while the compromised key is live*, an attacker can mint tokens that pass relay validation. Combined with a separate compromise of either the home's CA or a paired device's Keychain, the rendezvous-layer access becomes meaningful. Defense-in-depth says: rotate fast, force re-enroll, treat the relay-side compromise seriously even though it can't decrypt anything alone.

## environment isolation

Use **separate keypairs per environment, no exceptions.** A token signed by one deployment must never be accepted by another deployment. The bundled generator can produce additional keypairs with `--out <path>`, and the wrangler secret commands take `--env <name>` for whichever environments you define in `wrangler.toml`.

If you operate multiple environments, rotate on the same 12-month cadence but **out of phase**. You never want to be rotating all keys at once; that reduces the blast radius of a rotation script bug.

## self-host vs. sol pbc internal

This document is the public-facing playbook for any deployment of `spl-relay`. sol pbc additionally maintains an internal operational playbook covering vault paths, internal commands, and sol pbc's specific provisioning flow. That playbook is sol pbc's; **self-hosters follow the public-facing version you're reading**.

If you find this document insufficient for your deployment, open an issue on `github.com/solpbc/spl` — the public version should be sufficient for any reasonable self-host.

## related

- [`../proto/tokens.md`](../proto/tokens.md) — the wire format of the JWTs this signing key produces. Required claims, scopes, TTLs, validation contract.
- [`architecture.md`](architecture.md) — the trust boundaries that explain why the signing key sits where it does and what the blast-radius shape looks like.
- [`../AGENTS.md`](../AGENTS.md) §4 — the safety rails for any code that touches signing-key material.
- [`self-host.md`](self-host.md) — end-to-end self-host walkthrough, with this document linked at the signing-key step.
