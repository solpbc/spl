# spl architecture

## overview

See the diagram in [`../README.md`](../README.md#architecture). This document will carry the deeper version once the MVP build lands — component boundaries, data-flow, trust boundary analysis, and the full rendezvous sequence.

## trust boundaries

- **`solcf` (the relay)** is blind. It authenticates the *rendezvous* (account token from home, device token from mobile) but never the *payload*. It holds no key that can decrypt the inner stream.
- **`home` (the solstone-embedded python module)** terminates TLS. The home CA's private key lives on the home machine only, encrypted at rest under the user's existing solstone unlock secret.
- **Mobile client** holds its paired client cert + private key in Keychain (`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`). Revocation is a file edit on home — the fingerprint is removed from `authorized_clients.json`, the next reconnect from that device fails at the TLS handshake.

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
- Any authentication material that would let the operator impersonate either endpoint.

## placeholder

The detailed architecture — sequence diagrams, state machines, wake-latency bounds, pending-buffer policy, framing edge cases — will be filled in as the MVP lands. Until then, [`../README.md`](../README.md) and [`../AGENTS.md`](../AGENTS.md) carry the invariants.
