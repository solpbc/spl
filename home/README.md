# home

The python tunnel module. Embeds in solstone to open a long-held listen WebSocket to `spl-relay`, terminate TLS inside each incoming tunnel, and forward decrypted traffic to the local convey server.

## status

Scaffold only. The MVP build lands in a later phase; see [`../AGENTS.md`](../AGENTS.md) §6.

## what it is

Three cooperating asyncio pieces, all in one python package:

- `spl.tunnel` — outbound listen-WS manager to `spl-relay`. Uses the `websockets` library; relies on library-default ping + CF auto ping/pong for liveness. No app-level heartbeat.
- `spl.pair` — local HTTPS pairing server. Serves a short-lived, single-use QR/URL nonce over LAN; on scan, signs a client CSR with the home CA, writes the fingerprint to `authorized_clients.json`, and returns the cert chain.
- `spl.relay_server` — TLS 1.3 server inside the tunnel. Uses `pyOpenSSL` (not stdlib `ssl`) to expose a `verify_callback` that rejects unauthorized client fingerprints **inside the handshake** — revocation is immediate, not post-handshake.

Shared framing code (`spl.framing`) multiplexes many logical streams — HTTP, WebSocket, SSE — over one tunnel WebSocket.

## prerequisites

- **Python 3.11+**
- **uv** (preferred) or **pip**

## install

```sh
make install
```

## develop

```sh
make dev
```

Runs `spl.tunnel` against a local `spl-relay` (see `../relay/`). Configuration via `.env.local` (gitignored): `SPL_RELAY_ENDPOINT`, `ACCOUNT_TOKEN`, `CA_CERT_PATH`.

## test

```sh
make test
```

Unit tests run without network. Integration tests against a live `spl-relay` are marked `@pytest.mark.integration` and not gated by default CI.

## why pyOpenSSL

Stdlib `ssl` doesn't expose a `verify_callback` that can reject a client cert *inside* the handshake. The result is a post-handshake drop — the client sees a silent disconnect instead of a TLS alert. The prototype (see spl prototype report, internal) confirmed the UX difference is real: pyOpenSSL's handshake-time reject gives the mobile app a clean "this device was unpaired" error; stdlib gives a useless timeout.

## why ECDSA-P256 (not Ed25519)

Node/Bun TLS stacks don't advertise Ed25519 in their default signature schemes, so Ed25519 client certs fail the handshake with `NO_SUITABLE_SIGNATURE_ALGORITHM`. ECDSA-P256 works cross-stack. This is a prototype finding; don't re-derive it.
