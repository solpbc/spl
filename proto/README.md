# proto

Shared protocol documentation. The authoritative description of the wire formats that `solcf`, `home`, and the iOS client all have to agree on.

## status

Placeholder. Detailed specs land as each layer is built for the MVP.

## what goes here

- **Framing** (`framing.md`) — the SSH-channel-style multiplexing frame (`stream_id | flags | length | payload`) that carries many concurrent logical streams over one tunnel WebSocket.
- **Pairing** (`pairing.md`) — the LAN pairing ceremony (QR nonce → HTTPS → CSR → cert chain → fingerprint-in-file).
- **Tokens** (`tokens.md`) — account-token and device-token JWT shape, signing key rotation story, validation rules.
- **Session flow** (`session.md`) — listen / dial / tunnel lifecycle, pair-signal semantics, hibernation wake behavior, disconnect semantics, pending-buffer cap.

The rule for this directory: **if any two components would need to agree on the same detail, it is documented here, not in their READMEs**. A subtle divergence in the framing interpretation between the Worker and the python home is the exact class of bug this directory exists to prevent.
