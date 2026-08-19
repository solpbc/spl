# proto

Shared protocol documentation. The authoritative description of the wire formats and ceremonies that `spl-relay`, `home`, and the iOS client all have to agree on.

The rule for this directory: **if any two components would need to agree on the same detail, it is documented here, not in their READMEs**. A subtle divergence in framing interpretation between the Worker and the python home is the exact class of bug this directory exists to prevent.

## the documents

- [`framing.md`](framing.md) — SSH-channel-style multiplexing inside the TLS tunnel. Frame layout (`stream_id | flags | length | payload`), stream lifecycle, per-stream credit-based flow control, ordering guarantees. The contract between the two TLS endpoints; the relay does not parse frames.
- [`identity.md`](identity.md) — journal identity. The jid derivation from the journal CA's public key, its refusal vocabulary, and the definition of the client id (`cid`) as the fingerprint of that client's certificate.
- [`pairing.md`](pairing.md) — LAN-primary pairing ceremony. QR + nonce, on-device keypair generation, CSR submitted to the home over pinned-cert HTTPS, home-CA signing, fingerprint recorded in `authorized_clients.json`, device token acquired from the relay's control plane.
- [`pair-window.md`](pair-window.md) — off-LAN home-opened pairing window. Defines the `0x06` pair-link form, relay-side RK derivation, and RK-addressed pair-window / pair-dial admission.
- [`tokens.md`](tokens.md) — service-token (home → relay) and device-token (mobile → relay) JWT structure. **EdDSA / Ed25519** signature, required claims, scopes, TTLs, and the `kid`-keyed JWKS rotation model. Validation contract between the relay and both endpoints.
- [`session.md`](session.md) — listen / dial / tunnel WebSocket lifecycle. Single-WS-per-side on mobile (the dial WS becomes the tunnel WS — saves a round-trip). Hibernation and RFC 6455 control-frame keepalive behavior. Recoverable presence-held dial ownership with a 20-second first-buffered-byte attach lease. Deploy-disconnect semantics. WS-tag cardinality. The 16 MiB pending-buffer cap.

## reading order

If you're new to the protocol: [`session.md`](session.md) first (the lifecycle), then [`framing.md`](framing.md) (what flows inside), then [`identity.md`](identity.md) (who the parties are), then [`pairing.md`](pairing.md) and [`pair-window.md`](pair-window.md) (how a device first becomes able to dial), then [`tokens.md`](tokens.md) (the JWT shapes that authorize the rendezvous).

If you're touching the relay in this repository, or any client or home implementation in its own repository (see the root README's implementations table): read the document for the layer you're touching, plus [`tokens.md`](tokens.md) (because every WebSocket open touches token validation). Check your implementation against [`definition/`](definition/) — it carries the wire values and a conformance corpus as data, so you do not have to re-derive them from prose.

## boundary

The protocol documents own the **wire**. They do not own:

- **Implementation details** in any one component — those live in that component's README and source.
- **The signing-key lifecycle** — see [`../docs/signing-keys.md`](../docs/signing-keys.md). [`tokens.md`](tokens.md) describes what tokens look like and how rotation is structured at the wire layer; the operational playbook for generating, storing, provisioning, rotating, and revoking the signing key itself is a separate document.
- **Trust boundary architecture** — see [`../docs/architecture.md`](../docs/architecture.md). The proto docs reference the boundaries; that document explains them.

## related

- [`../docs/client-implementation-audit.json`](../docs/client-implementation-audit.json) — what each in-repo component actually implements of the pair-link contract, with per-claim evidence. Read it before assuming a component here conforms to these documents; several do not.


- [`../README.md`](../README.md) — product framing, architecture diagram, install / run / test.
- [`../AGENTS.md`](../AGENTS.md) — the developer guide. Read before changing anything in this directory.
- [`../docs/architecture.md`](../docs/architecture.md) — trust boundaries.
- [`../docs/signing-keys.md`](../docs/signing-keys.md) — signing-key lifecycle (operational, not wire-format).
