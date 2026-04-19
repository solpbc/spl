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

# Then pair this CLI with the home:
spl-mobile pair "https://192.168.1.10:8443/pair?token=<nonce>" "My Laptop" \
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
- `src/pair.ts` — LAN pair flow. CA fingerprint pin via
  `tls.checkServerIdentity`; SHA-256 over the peer's DER cert compared
  to the supplied `--pin`.
- `src/dial.ts` — WS open → TLS 1.3 inside the WS (via Node's `tls`
  module on a Duplex adapter per prototype finding §11.6) → mux on top.
- `src/http_client.ts` — minimal HTTP/1.1 client over a mux stream.
- `src/index.ts` — CLI dispatch.

## test

```sh
make test
```

18 unit tests — framing encode/decode roundtrip, flag validation, WINDOW
+ RESET parsing, and a **wire-compat snapshot** that hardcodes Python-
side byte encodings to detect any TS/Python drift. Integration tests
(full pair → dial → test) against the other two components live in the
top-level `../Makefile`.
