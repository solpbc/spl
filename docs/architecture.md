# spl architecture

## overview

See the diagram in [`../README.md`](../README.md#architecture). This document will carry the deeper version once the MVP build lands — component boundaries, data-flow, and the full rendezvous sequence. The trust-boundary analysis is below.

## trust boundaries

`spl` has **two cryptographic layers**, with distinct keys, distinct algorithms, and distinct concerns. The architecture is built so that a compromise of one is not a compromise of the other. They are referenced enough in the code and in adjacent docs that conflating them is the most common conceptual mistake — so they are called out explicitly here.

### layer 1 — JWT (rendezvous auth)

- **Algorithm:** Ed25519 / EdDSA.
- **What it authorizes:** the right to open a WebSocket to `solcf` (`/session/listen`, `/session/dial`, `/tunnel/<id>`).
- **Who signs:** sol pbc (or the self-host operator) using a private key held in `env.SIGNING_JWK` on the Worker.
- **Who verifies:** `solcf` itself, on every WebSocket upgrade. Verification uses the public JWKS in `env.JWKS_PUBLIC`, with `kid`-keyed lookup so rotations are non-disruptive.
- **Where the public key lives:** in `env.JWKS_PUBLIC` and mirrored at `https://<solcf-host>/.well-known/jwks.json` for transparency.
- **Operational lifecycle:** [`signing-keys.md`](signing-keys.md) (public-facing playbook).
- **Wire format:** [`../proto/tokens.md`](../proto/tokens.md).

### layer 2 — TLS 1.3 (in-tunnel end-to-end)

- **Algorithm:** ECDSA-P256, for both the home CA and the mobile client cert.
- **What it authorizes:** the actual byte exchange between mobile and home, *inside* the tunnel that JWT layer set up.
- **Who signs:** the home's local CA, generated on the home machine at first run, never transmitted, never escrowed. The CA private key is encrypted at rest under the user's solstone unlock secret.
- **Who verifies:** the home itself, via pyOpenSSL's `verify_callback` inside the TLS handshake — the mobile presents its paired client cert; the home checks the SHA-256 fingerprint against `authorized_clients.json` and rejects unauthorized fingerprints with a clean TLS alert.
- **Where the keys live:** the CA private key on the home, encrypted; the mobile client private key in iOS Keychain (`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`). Neither ever traverses `solcf`.
- **Why ECDSA, not Ed25519:** the JOSE side gets Ed25519 for the reasons above; the TLS side has to use ECDSA-P256 because Node and Bun TLS stacks don't advertise Ed25519 in signature schemes by default. Ed25519 in TLS would fail with `NO_SUITABLE_SIGNATURE_ALGORITHM` (prototype finding §11.7).
- **Wire format:** [`../proto/pairing.md`](../proto/pairing.md) for cert issuance; [`../proto/session.md`](../proto/session.md) for handshake placement.

### the blind-by-construction invariant

The two layers exist to make a precise claim possible:

> **`solcf` can mint, verify, and rotate JWTs all day; the JWTs confer no data access.**

Possessing a valid JWT lets you open a WebSocket to `solcf`. It does not let you complete the inner TLS handshake — that requires the mobile client cert and private key, which live only on a paired device. It does not let you decrypt past traffic — there is no key escrow; the relay never sees TLS plaintext. It does not let you mint a usable mobile identity — the home's CA private key never traverses the relay.

This is what makes the trust claim load-bearing: not "sol pbc decided not to look at the bytes," but **"sol pbc holds no key that could decrypt the bytes, even if it tried."**

## what the operator can see

- Which account-token established which listen socket.
- Which device-token dialed which target.
- Byte counts and timing of relayed frames.
- WebSocket connection liveness (connect, disconnect, wake).
- Rate-limit / abuse signals.

## what the operator cannot see

- The contents of any relayed frame (TLS 1.3 end-to-end inside the tunnel).
- Any user-generated data flowing through solstone.
- Any key that would let the operator decrypt a past or present session (no key escrow).
- Any authentication material that would let the operator impersonate either endpoint (no mTLS material at the relay).

## placeholder

The detailed architecture — sequence diagrams, state machines, wake-latency bounds, pending-buffer policy, framing edge cases — will be filled in as the MVP lands. Until then, [`../README.md`](../README.md) and [`../AGENTS.md`](../AGENTS.md) carry the invariants, and the [`../proto/`](../proto/) docs carry the wire-format contracts.
