# mobile

Example mobile client. Bun/TypeScript CLI that exercises the full mobile
side of the v1 protocol end-to-end — pair, dial, tunnel, HTTP. Not an iOS
app; the iOS build lives in `../ios/` and uses this as its wire-format
reference.

## status

MVP — feature-complete for the v1 scope:

- `spl-mobile pair <lan-url> <device-label>` runs the LAN pair ceremony:
  generates a fresh ECDSA-P256 keypair, posts a CSR, receives the signed
  client cert + home_attestation, forwards to spl-relay `/enroll/device`,
  stores the resulting device token alongside the keypair.
- The same `pair` command auto-detects a relay-addressed QR link
  (`https://go.solstone.app/p#...`) and runs the off-LAN pair ceremony through
  `/session/pair-ticket` + `/session/pair-dial`.
- `spl-mobile dial` opens the WS to spl-relay, runs TLS 1.3 inside the
  tunnel, and blocks until disconnect.
- `spl-mobile test` runs the full scenario matrix: `/echo` with byte-for-
  byte verification, `/stream` chunked SSE, `/upload` with SHA-256 check,
  and 10 concurrent multiplexed streams.

## prerequisites

- **Bun 1.1+** — exposes the browser-compatible `WebSocket` global and
  native TypeScript exec. No third-party WebSocket library needed.

## install

```sh
make install
```

## use

```sh
# First, start the home (see ../home/README.md) and mint a nonce:
python -m spl.home start --relay https://spl.example.org &
python -m spl.home pair --device-label "My Laptop"
# → prints a pair URL

# Then pair this CLI with the home over LAN:
spl-mobile pair "https://192.168.1.10:8443/pair?token=<nonce>" "My Laptop" \
    --relay https://spl.example.org

# Or pair from a relay-addressed QR link:
spl-mobile pair "https://go.solstone.app/p#<fragment>" "My Laptop" \
    --relay https://spl.example.org

# Verify the tunnel works end-to-end:
spl-mobile test
```

## architecture

- `src/framing.ts` — TS mirror of the home's `spl.home.framing`. Wire
  format is spec'd in `../proto/framing.md`; both endpoints must stay in
  lockstep.
- `src/mux.ts` — dialer-side multiplexer. Originates odd stream IDs per
  `proto/framing.md` §id-allocation; tears down on peer RESET; grants
  credit as bytes drain.
- `src/_csr_internal.ts` — ASN.1 DER + PKCS#10 CSR + PKCS#8 key builders.
  Extracted from `pair.ts` so tests can import without the network side.
- `src/pair.ts` — legacy manual LAN pair flow (`<ip>:<port>/pair?token=` via
  plain HTTPS). CA fingerprint pin via `tls.checkServerIdentity`; SHA-256 over
  the peer's DER cert compared to the supplied `--pin`. The QR-driven LAN path
  is `pair_direct.ts`.
- `src/pair_direct.ts` — LAN-direct (v0x04) QR pair flow. Opens cert-less TLS
  straight to the home's `<ip>:<port>` from the pair-link, runs the mux, posts
  the CSR to `/app/link/pair?token=`, then pins the QR's embedded CA cert-DER
  fingerprint against the returned `ca_chain` and binds it to the live peer
  leaf (`assertDirectCaPin`). Same pin posture as the relay flow, no tunnel.
- `src/pair_relay.ts` — relay-addressed off-LAN pair flow. Requests a
  pair-ticket, opens `/session/pair-dial`, posts the CSR through the tunnel,
  then enrolls the returned home attestation.
- `src/qr_link.ts` / `src/crockford32.ts` — pair-link parser and Crockford
  base32 codec shared by the relay + LAN-direct QR flows and tests.
- `src/spki.ts` — CA pin helpers: SPKI fingerprint for relay pairing
  (`assertCaPin`) and cert-DER fingerprint for LAN-direct (`assertDirectCaPin`).
- `src/dial.ts` — relay tunnel (WS open → TLS 1.3 inside the WS via Node's
  `tls` module on a Duplex adapter per prototype finding §11.6 → mux on top)
  and `openDirectTunnel` (TLS straight to a LAN socket → mux), sharing one
  mux/session builder.
- `src/http_client.ts` — minimal HTTP/1.1 client over a mux stream.
- `src/index.ts` — CLI dispatch.

## Pairing: pin posture and limitation

Both QR pair flows open cert-less TLS and pin the home's CA from the `/pair`
response. The relay flow (`assertCaPin`) compares the first 16 bytes of SHA-256
over the CA **SPKI** to the v0x03 QR fingerprint; the LAN-direct flow
(`assertDirectCaPin`) compares the first 16 bytes of SHA-256 over the CA
**certificate DER** to the v0x04 QR fingerprint. Both then verify the live TLS
leaf is signed by that pinned CA, and that the CA is self-signed — so a relay
or on-path LAN attacker cannot terminate TLS with its own key while proxying
the real home's `ca_chain`.

Bun's `node:tls` compatibility exposes only the peer leaf certificate after a
cert-less handshake, not the presented CA chain. So this CLI pins *after* the
one-use nonce is sent, not before — an active malicious relay (off-LAN) or
on-path attacker (LAN) could harvest that nonce during the pairing window. Full
pin-before-nonce active-MITM resistance is the production native client's
responsibility, because it can walk the presented chain at TLS time. This CLI
is a wire-format reference and test harness, not the production security
boundary.

## test

```sh
make test
```

38 unit tests — framing encode/decode roundtrip, flag validation, WINDOW
+ RESET parsing, pair-link parsing (relay + LAN-direct), CA pin helpers
(SPKI + cert-DER, accept/reject/wrong-domain/unsigned-leaf), and a
**wire-compat snapshot** that hardcodes Python-side byte encodings to detect
any TS/Python drift. Integration tests (full pair → dial → test) against the
other two components live in the top-level `../Makefile`.
