// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

// Bun 1.3.10's node:tls compatibility exposes the peer leaf certificate but
// not the presented issuer chain after a cert-less handshake. Relay pairing
// therefore pins after /pair returns the home's CA PEM. The leaf-signature
// check below is load-bearing: it binds that returned, QR-pinned CA to the
// live TLS endpoint so a relay cannot terminate TLS with its own leaf while
// proxying the real home's ca_chain.

import { X509Certificate, createHash } from "node:crypto";

export class PinningError extends Error {
	constructor(message: string) {
		super(message);
		this.name = "PinningError";
	}
}

export function spkiFp16(spkiDer: Uint8Array | Buffer): Uint8Array {
	return new Uint8Array(createHash("sha256").update(spkiDer).digest().subarray(0, 16));
}

export function caCertSpkiFp16(caPem: string): Uint8Array {
	const caX = new X509Certificate(caPem);
	const spkiDer = caX.publicKey.export({ type: "spki", format: "der" }) as Buffer;
	return spkiFp16(spkiDer);
}

export function assertCaPin(args: {
	caPem: string;
	expectedFp16: Uint8Array;
	peerLeaf: X509Certificate | undefined;
}): void {
	const caX = new X509Certificate(args.caPem);
	const actualFp16 = caCertSpkiFp16(args.caPem);
	if (!bytesEqual(actualFp16, args.expectedFp16)) {
		throw new PinningError("CA SPKI pin mismatch: presented CA does not match the QR fingerprint");
	}
	if (!args.peerLeaf || !args.peerLeaf.verify(caX.publicKey)) {
		throw new PinningError("TLS leaf is not signed by the pinned CA — possible relay MITM");
	}
	if (!caX.verify(caX.publicKey)) {
		throw new PinningError("pinned CA is not self-signed");
	}
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
	if (a.byteLength !== b.byteLength) return false;
	let diff = 0;
	for (let i = 0; i < a.byteLength; i++) diff |= a[i] ^ b[i];
	return diff === 0;
}
