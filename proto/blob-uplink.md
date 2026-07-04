# browser blob-uplink

Browser blob-uplink is the v1 wire contract for the cert-less browser extension
client class. The DATA path reuses the existing relay tunnel; pairing reuses the
`0x06` home-opened pair-window from [`pair-window.md`](pair-window.md).

Related contracts:

- [`pairing.md`](pairing.md) — native pairing and the browser registration variant.
- [`pair-window.md`](pair-window.md) — RK-addressed off-LAN pairing window.
- [`session.md`](session.md) — relay WebSocket lifecycle and WS-layer minimality.
- [`tokens.md`](tokens.md) — device tokens and validation.

## relationship to the relay

The DATA path adds nothing at the relay. The extension holds an ordinary device
token and dials `/session/dial?instance=<id>&token=<device_token>` exactly like a
native client using the documented `?token=` fallback. The blob bytes ride the
opaque tunnel in place of TLS records; `spl-relay` forwards them as bytes and
does not parse HPKE, tar, gzip, metadata, or observer segment contents.

Pairing also reuses the existing relay shape. A browser cannot set
`Sec-Pair-Key`, so the pair-dial RK is carried in
`Sec-WebSocket-Protocol: spl-v1, spl-pair.<RK hex>` and the relay selects
exactly `spl-v1` on the 101 response. The home side remains native and continues
to use `Sec-Pair-Key` for the pair-window and pairing tunnel attach.

## wire contract

```text
=== spl browser blob-uplink — wire contract v1 ===

Transport: the existing relay tunnel. Nothing new at the relay for the DATA
path. The extension holds an ordinary device token (its device_fp is the
SHA-256 of its P-256 public-key SPKI DER, in place of a cert fingerprint) and
dials /session/dial?instance=<id>&token=<device_token> exactly like a native
client. The bytes below ride the opaque tunnel, in place of the TLS records a
native client would send. Blobs are uploaded one per tunnel, sequentially.

Crypto suite (HPKE, RFC 9180):
  mode  = 2  (auth)          -- sender authenticated by its static P-256 key
  kem   = 0x0010  DHKEM(P-256, HKDF-SHA256)
  kdf   = 0x0001  HKDF-SHA256
  aead  = 0x0002  AES-256-GCM

HPKE info  = "spl-blob-v1" || instance_id_16 || sender_fp_32
  instance_id_16 = the home instance UUID as 16 raw bytes
  sender_fp_32   = SHA-256 of the extension public-key SPKI DER (32 bytes)
HPKE AAD   = the Offer header bytes, exactly as sent (magic .. ct_len inclusive)

Multi-byte integers are big-endian.

--- extension -> home: Offer (sent first, small, fits the relay pending buffer) ---
  magic        4     "SBO1"
  version      1     0x01
  kem_id       2     0x0010
  kdf_id       2     0x0001
  aead_id      2     0x0002
  sender_fp   32     SHA-256(extension SPKI DER)
  blob_id     16     UUIDv7 (idempotency key)
  ct_len       8     u64 length of the HPKE ciphertext that will follow

--- home -> extension: Ready ---
  magic        4     "SBR1"
  version      1     0x01
  status       1     0x00 = proceed; nonzero = reject (extension closes, retries later)

--- extension -> home: Sealed (streamed; may arrive across several WS frames) ---
  enc         65     HPKE encapsulated key (uncompressed P-256 point)
  ct       ct_len    HPKE single-shot seal of gzip(tar(files)), AAD = Offer bytes

  Plaintext inside the seal = gzip(tar(...)) containing:
    blob.json   -> { "v":1, "day":"YYYYMMDD", "segment":"HHMMSS_LEN",
                     "host":"<host>", "meta": { ... } }
    <one or more observer segment files, e.g. browser_<host>.jsonl>
  tar entries MUST be plain files only (reject absolute paths, "..", symlinks,
  hardlinks, devices; bound entry count and total uncompressed size).

--- home -> extension: Ack ---
  magic        4     "SBA1"
  version      1     0x01
  status       1     0x00 = ok (stored) ; 0x01 = duplicate (already had it)
  blob_id     16     echoes the Offer blob_id
  tag         16     first 16 bytes of HMAC-SHA256(K_ack, "spl-blob-ack" ||
                     status_byte || blob_id), where
                     K_ack = HPKE context.export("spl-blob-ack-v1", 32)

Idempotency: the home dedupes on blob_id. A replayed blob_id it has already
stored -> Ack status=0x01 duplicate, no re-store. seq is NOT part of this
contract (delivery order is not enforced; blob_id idempotency is the whole
mechanism).

=== pairing (browser registration variant) ===
Reuses the 0x06 home-opened pair-window at the relay byte-for-byte. RK is
carried in the Sec-WebSocket-Protocol subprotocol (browser cannot set the
Sec-Pair-Key header). Inside the pairing tunnel, the inner CSR->cert step is
replaced by public-key registration:

  1. extension -> home: PairHello  magic "SBP1" | version 0x01
  2. home -> extension: signed identity
        { pkH_spki, ca_spki, instance_id, sig }
        sig = ECDSA-P256/SHA-256 by the home CA private key over
              "spl-pair-browser-v1" || pkH_spki || instance_id
        ca_spki = the CA public-key SPKI DER. The 0x06 link carries only the
        16-byte ca_fp_spki pin, not the key, so the home supplies the full CA
        key here. The extension checks SHA-256(ca_spki)[:16] == ca_fp_spki, then
        verifies sig with ca_spki -- this authenticates the home's HPKE recipient
        key with no TLS.
  3. extension -> home: HPKE base-mode (mode 0) seal to pkH,
        info = instance_id_16, plaintext = { S, ext_pub_spki, device_label }
        (S = the 8-byte pair-window nonce; the home-side single-use gate)
  4. home: verify S live/single-use, register the extension public key, mint a
        home_attestation (ES256 by the CA key, device_fp = SHA-256(ext SPKI)),
        reply HPKE-sealed { instance_id, home_attestation }.
  5. extension: POST /enroll/device { instance_id, home_attestation } over
        plain HTTPS (control plane, no header constraint) -> device_token.

=== end wire contract v1 ===
```

## blindness and WS-layer minimality

This contract preserves the relay boundary described in
[`session.md`](session.md#ws-layer-minimality) and
[`../docs/architecture.md`](../docs/architecture.md). The subprotocol RK carrier
is a request-scoped rendezvous credential consumed during HTTP upgrade, in the
same category as `Sec-Pair-Key`, and carries only RK. The echoed `spl-v1` is a
fixed constant with zero runtime state; the relay never echoes the
`spl-pair.<RK>` token. Blob bytes are HPKE-protected opaque tunnel payload, and
the relay holds no key and runs no HPKE code.

## interop fixture

The HPKE-running lodes use the following fixture as an interop gate: create the
auth-mode recipient context from `(enc, skRm, info, pkSm)`, open
`encryption[0].ct` with its `aad`, and assert it equals `pt`; then assert the
empty-context `L=32` export equals the value below. This repo does not run that
gate. The relay forwards opaque bytes and performs no HPKE operation.

```text
RFC 9180 test vector — mode=2 (auth), kem=0x0010, kdf=0x0001, aead=0x0002
info = 4f6465206f6e2061204772656369616e2055726e
skRm = d9f10996a02cd6c9dbda1d1f225f18f781ea3c893b8c2a6cb2e266e59f3cd9a9
pkRm = 04cd38ef80923e26f157e06c9887f80177c97e1005a41104127271237f946df22eda13d40801bce6184f1a631c44b0807a1a5e8d039975ed0f6079fcbd2dfe6652
skSm = 6e7b14befe49443dc501def1cc2f0f293d9c5cfa045a23e9a2e0e7703b42705d
pkSm = 04ece9b48cc98ee03ba742fe1218a3fbec960cc34b6e1defdcd3285276f39028e95b90f9526607565888766a1101f429dc3ec87364b5c8c613f0a081881950427f
enc  = 04a7aeac79fda402674ef247c12d6f5fdfd21498d896b67ff04ec181382d4516b7662be32b4a2ae817c2d57104ecb6fcaa527438939810612d1b3d0af36ffc66ce
encryption[0].aad = 436f756e742d30
encryption[0].pt  = 4265617574792069732074727574682c20747275746820626561757479
encryption[0].ct  = 59b9890aabf94c1d502c39d8d356989ab0880ed43e984255db7b32a8d7b0ad5beba799a4ec326a0ddca3dd5e5d
export "" (empty context) L=32 = 6c0386ae15b1b834a5247ca5595b4e102347cbcdc65de64832f36008ce9c9483
```
