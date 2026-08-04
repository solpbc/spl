# journal identity

The journal's own identity, and the device identity that sits beside it. Two values, two mechanisms, deliberately not one.

- The **jid** identifies a journal. It is derived from the journal CA's public key.
- The **did** identifies a paired device. It is the fingerprint of that device's certificate. There is no derivation.

This document is the normative source for both. Machine-readable form and conformance vectors are in [`definition/`](definition/README.md).

## why this is in the protocol

A client renders the jid for its owner during pairing and refuses a mismatch. So every implementation that pairs has to derive the same value from the same key, and a divergence does not degrade gracefully. It presents to the owner as evidence that something is wrong with their journal. Independent implementations agreed only because the literals were copied by hand.

## the jid

### key domain

The jid is derived from a **`SubjectPublicKeyInfo` structure, DER-encoded, carrying an elliptic-curve public key on the P-256 curve** (`secp256r1`, OID `1.2.840.10045.3.1.7`).

The derivation is **over the key, not over the bytes it arrived in**. An implementation MUST parse the `SubjectPublicKeyInfo`, MUST confirm the algorithm is `id-ecPublicKey` on P-256, MUST confirm the public point lies on the curve, and MUST re-serialize the key to its canonical `SubjectPublicKeyInfo` DER form before deriving. The canonical form carries the point uncompressed.

Two encodings of one key therefore produce one jid. An implementation that hashes the bytes it was handed will agree with a conforming one on every input a current producer emits, and disagree on a compressed point.

### derivation

Over the canonical DER, in order:

1. HKDF-SHA256, salt `solstone/journal/v1`, info `solstone/jid/uuidv8/v1`, output length 16 bytes. Both labels are ASCII with no terminator.
2. Set the version nibble: byte 6 becomes `(byte6 & 0x0F) | 0x80`, making this a UUID version 8 as defined by RFC 9562.
3. Set the variant bits: byte 8 becomes `(byte8 & 0x3F) | 0x80`, the RFC 9562 variant.
4. Render as a lowercase hyphenated UUID.

The 16 raw bytes, before rendering, are the jid's byte form. They are the input to the journal mark, which is not specified in this repository.

### refusals

An implementation MUST refuse, and MUST distinguish, these three:

| kind | when |
|---|---|
| `not_p256` | the algorithm is not `id-ecPublicKey`, or the curve is not P-256 |
| `invalid_point` | the structure parses and names P-256, but the public point is not on the curve |
| `malformed_spki` | the input is not a well-formed `SubjectPublicKeyInfo` |

Refusing is not optional and MUST NOT be a value. An implementation that returns a jid for a key it could not validate has produced an identifier for something that is not a journal identity.

## the did

A paired device is identified by the **SHA-256 digest of its client certificate, over the certificate's DER encoding**, rendered lowercase hexadecimal with a `sha256:` prefix. That is the same value the home records for the device when it signs the certificate.

> **Three fingerprints, three digest inputs.** They are computed over different bytes, and crossing them breaks pairing in ways that are hard to see:

| value | digest input | length used |
|---|---|---|
| `did` | the **certificate** DER | the full 32 bytes |
| the direct-form `ca_fp` | the CA **certificate** DER | the leading 16 bytes |
| the relay-form `ca_fp_spki` | the CA **`SubjectPublicKeyInfo`** DER | the leading 16 bytes |

A device does not get a jid, and does not get a mark. A mark is derived from a jid; a certificate fingerprint is not one.

Because the did is taken over the certificate, re-issuing a device's certificate changes its did. Nothing in this protocol re-issues one.

## conformance vectors

Five vectors, all reproducible from published constants rather than from any implementation's output. The first two carry the same expected jid, which is the point of them.

Every implementation that derives a jid MUST reproduce all five of these results exactly, including the two refusals. Inline these vectors verbatim, or consume them from the machine-readable corpus.

### `identity.jid.canonical`

The P-256 generator point as a public key, canonically encoded.

```
spki_der_hex: 3059301306072a8648ce3d020106082a8648ce3d030107034200046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5
jid:          5620bab1-476a-88df-93d4-f4f525b991dd
```

### `identity.jid.compressed-point`

The same key, point compressed. **Expects the same jid.** An implementation that hashes its input rather than the key it names will fail this one and pass every other vector here.

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

## scope

This document defines the jid derivation, its refusals, and what the did is. It does not define the journal mark, the pairing ceremony, session lifecycle, framing, or token claims. The mark is not specified in this repository. Silence here grants no permission to change those.
