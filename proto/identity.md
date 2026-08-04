# journal identity

The journal's own identity, and the device identity that sits beside it. Two values, computed two different ways.

- The **jid** identifies a journal. The home derives it from its own CA's public key, and a client compares it against the `instance_id` it dials.
- The **did** identifies a paired device. It is the fingerprint of that device's certificate, taken directly rather than derived, and it is carried as `device_fp` in the token claims and as `fingerprint` in the home's authorized-client ledger. It is **not** the `device_id` that appears in a `session.dial` token's subject; that is a different value.

This document is the normative source for both. Machine-readable form for both, and conformance vectors for the jid, are in [`definition/`](definition/README.md).

## why this is in the protocol

The home derives the jid, and any implementation that checks it MUST derive it identically from the same key. A client pairing off-LAN is expected to compare the jid it derives against the `instance_id` it was given, as an integrity check on the CA it pinned ([`pair-window.md`](pair-window.md)). A divergence does not fail loudly: it fails as a mismatch between two parties who each believe they are correct.

## the jid

### key domain

The jid is derived from a **`SubjectPublicKeyInfo` structure, DER-encoded, carrying an elliptic-curve public key on the P-256 curve** (`secp256r1`, OID `1.2.840.10045.3.1.7`).

The derivation is **over the key, not over the bytes it arrived in**. An implementation MUST parse the `SubjectPublicKeyInfo`, MUST confirm the algorithm is `id-ecPublicKey` on P-256, MUST confirm the public point lies on the curve, and MUST re-serialize the key to its canonical `SubjectPublicKeyInfo` DER form before deriving. The canonical form carries the point uncompressed.

Two encodings of one key therefore produce one jid. An implementation that hashes the bytes it was handed will agree with a conforming one on any uncompressed encoding, and disagree on a compressed point.

### derivation

Byte offsets below are 0-indexed. Over the canonical DER, in order:

1. HKDF-SHA256, salt `solstone/journal/v1`, info `solstone/jid/uuidv8/v1`, output length 16 bytes. Both labels are ASCII with no terminator.
   The HKDF is per RFC 5869, and the IKM is the canonical `SubjectPublicKeyInfo` DER. The salt is 19 bytes and the info is 22 bytes, both ASCII.

2. Set the version nibble: byte 6 becomes `(byte6 & 0x0F) | 0x80`, making this a UUID version 8 as defined by RFC 9562.
3. Set the variant bits: byte 8 becomes `(byte8 & 0x3F) | 0x80`, the RFC 9562 variant.
4. Render as a lowercase hyphenated UUID.

The 16 stamped bytes, before rendering, are the jid's byte form. They are the input to the journal mark, which this repository does not specify.

### refusals

An implementation MUST refuse, and MUST distinguish, these three:

| kind | when |
|---|---|
| `not_p256` | the algorithm is not `id-ecPublicKey`, or the curve is not P-256 |
| `invalid_point` | the structure parses and names P-256, but the public point is not on the curve |
| `malformed_spki` | the input is not a well-formed `SubjectPublicKeyInfo` |

An implementation MUST NOT signal a refusal in-band as a returned jid. A jid returned for a key that was never validated identifies nothing.

## the did

A paired device is identified by the **SHA-256 digest of its client certificate, over the certificate's DER encoding**, rendered lowercase hexadecimal with a `sha256:` prefix. That is the same value the home records for the device when it signs the certificate.

> **`ca_fp` names more than one value in this protocol, and they are not interchangeable.** The direct pair-link's `ca_fp` is the leading 16 bytes of SHA-256 over the CA certificate DER ([`pairing.md`](pairing.md)). The relay pair-link's `ca_fp_spki` is the leading 16 bytes over the CA `SubjectPublicKeyInfo` DER ([`pair-window.md`](pair-window.md)). A service token's `ca_fp` claim is a full 32-byte digest over the home's CA public key ([`tokens.md`](tokens.md)). The `pair-start` response's `ca_fingerprint` is the full 32 bytes over the CA certificate DER ([`pairing.md`](pairing.md)).
>
> Each is specified where it is used, and this document deliberately does not restate them: an enumeration maintained by hand in a fifth place is one that goes stale. What matters here is that the `did` is none of them.

A device gets neither a jid nor a mark, because both are derived from a journal CA key and a device has no such key.

Because the did is taken over the certificate, a device that is issued a new certificate gets a new did. Re-pairing does exactly that: [`pairing.md`](pairing.md) specifies it as revoke-then-pair-again, which mints a fresh certificate for the same physical device. Nothing renews a certificate in place.

## conformance vectors

Six vectors, all reproducible from published constants rather than from any implementation's output. Two expect a jid and four expect a refusal, covering all three refusal kinds. The first two carry the same expected jid for the same key under two encodings.

Every implementation that derives a jid MUST reproduce all six of these results exactly, refusals included. Inline these vectors verbatim, or consume them from the machine-readable corpus.

### `identity.jid.canonical`

The P-256 generator point as a public key, canonically encoded.

```
spki_der_hex: 3059301306072a8648ce3d020106082a8648ce3d030107034200046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5
jid:          5620bab1-476a-88df-93d4-f4f525b991dd
```

### `identity.jid.compressed-point`

The same key, point compressed. **Expects the same jid.** An implementation that validates the key but digests the bytes it was handed rather than the canonical re-serialization fails this vector alone.

```
spki_der_hex: 3039301306072a8648ce3d020106082a8648ce3d030107032200036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
jid:          5620bab1-476a-88df-93d4-f4f525b991dd
```

### `identity.jid.off-curve-point`

The canonical vector with the low bit of Y's final byte flipped, `f5` to `f4`. Well-formed DER, algorithm and curve OIDs unchanged, point not on the curve. Expects `invalid_point`.

```
spki_der_hex: 3059301306072a8648ce3d020106082a8648ce3d030107034200046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f4
```

### `identity.jid.wrong-curve`

The P-384 generator point. Correct algorithm OID, wrong curve OID. Expects `not_p256`.

```
spki_der_hex: 3076301006072a8648ce3d020106052b8104002203620004aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab73617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f
```

### `identity.jid.wrong-algorithm`

An Ed25519 public key, from an all-zero seed. Not an elliptic-curve key in the `id-ecPublicKey` sense. Expects `not_p256`.

```
spki_der_hex: 302a300506032b65700321003b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29
```

### `identity.jid.malformed`

The canonical vector truncated to its first 40 bytes. The outer SEQUENCE claims more content than the input holds, so nothing parses. Expects `malformed_spki`.

```
spki_der_hex: 3059301306072a8648ce3d020106082a8648ce3d030107034200046b17d1f2e12c4247f8bce6e563
```

## scope

This document defines the jid derivation, its refusals, and what the did is. It does not define the journal mark, the pairing ceremony, session lifecycle, framing, or token claims, and silence here grants no permission to change any of them.
