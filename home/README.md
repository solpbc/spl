# home

The python tunnel module. Standalone MVP implementation of the home side of spl — opens a listen WebSocket to `spl-relay`, terminates TLS 1.3 inside each incoming tunnel (with handshake-time fingerprint pinning against `authorized_clients.json`), and serves a minimal test HTTP app.

## status

MVP — the full protocol surface is implemented:

- `python -m spl.home start` runs the long-lived listen process (enrolls with the relay on first run, reconnects on disconnect)
- `python -m spl.home pair --device-label X` mints a fresh LAN pair nonce
- Local CA (ECDSA-P256, 10-year) generated on first run, private key encrypted at rest
- Pair HTTPS server signs CSRs, emits `home_attestation` JWTs per proto/tokens.md
- `authorized_clients.json` reloads on mtime change
- pyOpenSSL TLS 1.3 server with `verify_callback` fingerprint check inside the handshake
- Multiplex framing per proto/framing.md (256 concurrent streams, 1 MiB initial credit window)
- Test HTTP app at `/echo`, `/stream`, `/upload` (SHA-256 response)

Paired with `../relay/` (the Worker) and `../mobile/` (the Bun/TS client).

## what it is

Four cooperating pieces, all in one python package (`spl.home`):

- `spl.home.relay_client` — outbound listen WS manager. Uses `websockets` library; relies on library-default ping + CF auto ping/pong for liveness. No app-level heartbeat.
- `spl.home.pair_server` — local HTTPS pairing server. Serves a short-lived, single-use nonce over LAN; on submission signs a CSR with the home CA, writes the fingerprint to `authorized_clients.json`, mints the attestation, returns the cert chain.
- `spl.home.tls_adapter` — TLS 1.3 server inside the tunnel. Uses `pyOpenSSL` (not stdlib `ssl`) to expose a `verify_callback` that rejects unauthorized client fingerprints **inside the handshake** — revocation is immediate, not post-handshake.
- `spl.home.mux` — multiplexes many logical HTTP streams over one tunnel WebSocket, per proto/framing.md.

Shared helpers: `spl.home.ca` (CA + CSR + attestation), `spl.home.auth` (authorized_clients.json), `spl.home.nonces` (pair-nonce store), `spl.home.app` (test HTTP handlers), `spl.home.config` (persistent state).

## prerequisites

- **Python 3.11+**
- **uv** (preferred) or **pip**

## install

```sh
make install
```

## run

First-run bootstrap (enrolls with the relay, generates CA, starts listening):

```sh
python -m spl.home start --relay https://spl.example.org
```

Pair a phone (in another shell):

```sh
python -m spl.home pair --device-label "Jer's phone"
# → Pair URL: https://127.0.0.1:8443/pair?token=<nonce>
```

## test

```sh
make test
```

42 unit tests covering framing encode/decode, CA + CSR + attestation minting, authorized-clients mtime reload + atomic writes, nonce single-use semantics, mux open/data/close/reset behavior, and the test HTTP app. Integration tests against a live `spl-relay` are part of the top-level `../Makefile`.

## why pyOpenSSL

Stdlib `ssl` doesn't expose a `verify_callback` that can reject a client cert *inside* the handshake. The result is a post-handshake drop — the client sees a silent disconnect instead of a TLS alert. The prototype found the UX difference is real: pyOpenSSL's handshake-time reject gives the mobile app a clean "this device was unpaired" error; stdlib gives a useless timeout.

## why ECDSA-P256 (not Ed25519) for the mTLS layer

Node/Bun TLS stacks don't advertise Ed25519 in their default signature schemes, so Ed25519 client certs fail the handshake with `NO_SUITABLE_SIGNATURE_ALGORITHM`. ECDSA-P256 works cross-stack. This is the same split as the relay's spec: JWT layer uses Ed25519 (proto/tokens.md), mTLS layer uses ECDSA-P256 (proto/pairing.md). Do not conflate.
