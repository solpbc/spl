# signing keys

This document is the public-facing operational guide for the JWT signing keys used by `spl-relay`. It applies to both sol pbc's hosted deployment and any self-hosted instance.

`spl-relay` uses one signing keypair to mint and verify the JWTs that authorize WebSocket establishment with the relay. Lose the private key and every paired device must re-enroll. Take this seriously.

## the two key layers — do not conflate

`spl` has two cryptographic layers, with different keys, different algorithms, and different concerns. Mixing them up is the most common conceptual mistake.

| layer | algorithm | what it protects | where the keys live |
|---|---|---|---|
| **JWT signing layer** (this document) | **Ed25519 / EdDSA** | rendezvous: authorizes a WebSocket open to `spl-relay` | private: `env.SIGNING_JWK` (Worker secret); public: `env.JWKS_PUBLIC` (Worker secret + `/.well-known/jwks.json`) |
| **mTLS layer** (see [`../proto/pairing.md`](../proto/pairing.md), [`../proto/session.md`](../proto/session.md)) | **ECDSA-P256** | data: authorizes the actual byte exchange between mobile and home | home CA private key on the home machine, encrypted at rest under the user's solstone unlock secret; mobile client cert in iOS Keychain |

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

(Or invoke directly: `npm run gen-key -- --out ~/.spl/staging-keypair.json` to override the path.)

The script:

1. Generates an Ed25519 JWK keypair via Web Crypto (or `openssl genpkey -algorithm ED25519` as a fallback).
2. Stamps a fresh `kid` (UUIDv7) and `created_at` timestamp.
3. Writes the keypair to `~/.spl/signing-keypair.json` (default; override with `--out`). File mode `0600`.
4. Prints the exact `wrangler secret put SIGNING_JWK` and `wrangler secret put JWKS_PUBLIC` commands to run next.
5. Warns clearly: this is the root of trust for your tunnel; lose it and every paired device must re-enroll.

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

- `env.SIGNING_JWK` to sign tokens at the (control-plane) `/enroll/home` and `/enroll/device` endpoints.
- `env.JWKS_PUBLIC` to verify tokens on every `/session/listen`, `/session/dial`, and `/tunnel/<id>` upgrade. The JWKS contains all currently valid public keys; verification looks up `kid` from the JWT header.

### `/.well-known/jwks.json`

`spl-relay` exposes the current `env.JWKS_PUBLIC` at:

```
GET https://<your-relay-host>/.well-known/jwks.json
```

This is the transparency endpoint. Anyone can verify what key the relay is currently signing with — no internal access required. The endpoint is unauthenticated, returns a JSON object of the same shape stored in the secret, and is cached for 5 minutes.

For sol pbc's hosted deployment: `https://spl.solpbc.org/.well-known/jwks.json`.

## rotation

Default cadence: **12 months**, with a **30-day overlap window**. The mechanism:

1. **Generate the new keypair** per *generation* above. New `kid`.
2. **Push the new JWKS containing both keys.** The new JSON is `{ "keys": [<old public>, <new public>] }`. Paste it into:

   ```sh
   wrangler secret put JWKS_PUBLIC --env production
   ```

3. **Push the new private key.** Issuance immediately switches to the new `kid`:

   ```sh
   wrangler secret put SIGNING_JWK --env production
   ```

4. **Wait the overlap window.** Tokens minted under the old `kid` continue to verify against its public key in the JWKS. Homes and devices automatically re-issue at 80% of TTL — by the time the window closes, almost no tokens with the old `kid` remain in circulation.
5. **Push the trimmed JWKS.** New JSON is `{ "keys": [<new public>] }`:

   ```sh
   wrangler secret put JWKS_PUBLIC --env production
   ```

   Any straggler token under the old `kid` now fails validation cleanly. The home or device re-issues on next dial; pairing material is unaffected.

6. **Archive the old keypair** somewhere offline. Keep it for at least 90 days after the overlap window closes (forensic / replay defense), then destroy it.

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

   This is the kill switch. Every existing token instantly fails validation — including any minted by the attacker.

4. **Push the new private key:**

   ```sh
   wrangler secret put SIGNING_JWK --env production
   ```

5. **Force re-enroll.** Notify the control plane (or the home / mobile client logic, depending on your deployment) to purge cached account tokens and force re-issuance on next check-in. Paired devices that hold a now-invalid device token will get TLS-handshake-failure-style errors at the relay (rendezvous fails); the user re-pairs through convey.
6. **Archive the compromised keypair** with metadata noting compromise, root cause, and remediation. Do not delete — keep for forensic review.
7. **Self-hoster note.** If you operate your own relay, this runbook is yours to execute. Your users (the people you've paired devices for) must re-enroll their devices through the home; the home itself re-enrolls automatically against your new key. There is no sol pbc support path for self-hosted compromise — the trust chain is end-to-end yours.

Target: **< 4 hours from detection to the new key being live.**

## what compromise does *not* affect

The blind-by-construction architecture means a JWT signing key compromise has a bounded blast radius:

- **No payload data is exposed.** Tokens authorize the rendezvous, not the data. An attacker with a forged token can open a WebSocket to the relay, but cannot complete the inner TLS handshake without the matching mobile client cert (which lives only on a real paired device's Keychain).
- **No past sessions are decrypted.** TLS material is held by the home and the mobile device. The signing key never sees TLS plaintext.
- **No other deployments are affected.** Each environment (prod / staging) and each self-host has its own keypair.

That said: *while the compromised key is live*, an attacker can mint tokens that pass relay validation. Combined with a separate compromise of either the home's CA or a paired device's Keychain, the rendezvous-layer access becomes meaningful. Defense-in-depth says: rotate fast, force re-enroll, treat the relay-side compromise seriously even though it can't decrypt anything alone.

## staging vs. production

Use **separate keypairs per environment, no exceptions.** A staging-signed token must never be accepted in production. The bundled generator can produce both — pass `--out ~/.spl/staging-keypair.json` for staging — and the wrangler secret commands take `--env staging` or `--env production`.

If you operate both environments, rotate on the same 12-month cadence but **out of phase by 6 months**. You never want to be rotating both at once; reduces the blast radius of a rotation script bug.

## self-host vs. sol pbc internal

This document is the public-facing playbook for any deployment of `spl-relay`. sol pbc additionally has an internal operational playbook (`cso/playbooks/spl-signing-key-lifecycle.md`) covering vault paths, internal commands, and sol pbc's specific provisioning flow. That playbook is sol pbc's; **self-hosters follow the public-facing version you're reading**.

If you find this document insufficient for your deployment, open an issue on `github.com/solpbc/spl` — the public version should be sufficient for any reasonable self-host.

## related

- [`../proto/tokens.md`](../proto/tokens.md) — the wire format of the JWTs this signing key produces. Required claims, scopes, TTLs, validation contract.
- [`architecture.md`](architecture.md) — the trust boundaries that explain why the signing key sits where it does and what the blast-radius shape looks like.
- [`../AGENTS.md`](../AGENTS.md) §3 — the safety-rail invariants for any code that touches signing-key material.
- [`self-host.md`](self-host.md) — end-to-end self-host walkthrough, with this document linked at the signing-key step.
