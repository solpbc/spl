// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

// CSR + ECDSA-P256 PKCS#8 builders extracted from pair.ts so tests can
// import them without dragging the network-side code along. The name is
// underscored because this is an implementation detail of pair.ts — not
// a public surface.

import { webcrypto } from "node:crypto";

export async function buildCsr(
	commonName: string,
	publicJwk: Record<string, string>,
	privateKey: CryptoKey,
): Promise<string> {
	const pubPoint = jwkToP256Point(publicJwk);
	const subject = buildName(commonName);
	const subjectPublicKeyInfo = buildEcP256Spki(pubPoint);
	const tbsCertRequest = derSeq([
		derInteger(new Uint8Array([0x00])),
		subject,
		subjectPublicKeyInfo,
		new Uint8Array([0xa0, 0x00]),
	]);

	const sigRaw = new Uint8Array(
		await webcrypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, privateKey, tbsCertRequest),
	);
	const sigDer = rawP256ToDer(sigRaw);

	const sigAlg = derSeq([derOid([1, 2, 840, 10045, 4, 3, 2])]);
	const csrDer = derSeq([tbsCertRequest, sigAlg, derBitString(sigDer)]);
	return derToPem(csrDer, "CERTIFICATE REQUEST");
}

export function jwkToPkcs8Pem(jwk: Record<string, string>): string {
	const d = b64urlDecode(jwk.d);
	if (d.byteLength !== 32) throw new Error("P-256 private scalar must be 32 bytes");
	const pubPoint = jwkToP256Point(jwk);
	const ecPrivateKey = derSeq([
		derInteger(new Uint8Array([0x01])),
		derOctet(d),
		derTagged(0, derOid([1, 2, 840, 10045, 3, 1, 7])),
		derTagged(1, derBitString(pubPoint)),
	]);
	const algId = derSeq([derOid([1, 2, 840, 10045, 2, 1]), derOid([1, 2, 840, 10045, 3, 1, 7])]);
	const pkcs8 = derSeq([derInteger(new Uint8Array([0x00])), algId, derOctet(ecPrivateKey)]);
	return derToPem(pkcs8, "PRIVATE KEY");
}

export function jwkToP256Point(jwk: Record<string, string>): Uint8Array {
	const x = b64urlDecode(jwk.x);
	const y = b64urlDecode(jwk.y);
	if (x.byteLength !== 32 || y.byteLength !== 32) {
		throw new Error("P-256 public coordinates must be 32 bytes");
	}
	const point = new Uint8Array(65);
	point[0] = 0x04;
	point.set(x, 1);
	point.set(y, 33);
	return point;
}

function buildName(commonName: string): Uint8Array {
	const cn = derSeq([derOid([2, 5, 4, 3]), derUtf8(commonName)]);
	const rdn = derSet([cn]);
	return derSeq([rdn]);
}

function buildEcP256Spki(pubPoint: Uint8Array): Uint8Array {
	const algId = derSeq([derOid([1, 2, 840, 10045, 2, 1]), derOid([1, 2, 840, 10045, 3, 1, 7])]);
	const subjectPublicKey = derBitString(pubPoint);
	return derSeq([algId, subjectPublicKey]);
}

export function rawP256ToDer(raw: Uint8Array): Uint8Array {
	if (raw.byteLength !== 64) throw new Error("P-256 raw sig must be 64 bytes");
	const r = stripLeadingZeros(raw.slice(0, 32));
	const s = stripLeadingZeros(raw.slice(32, 64));
	return derSeq([derInteger(r), derInteger(s)]);
}

function stripLeadingZeros(bytes: Uint8Array): Uint8Array {
	let start = 0;
	while (start < bytes.byteLength - 1 && bytes[start] === 0 && !(bytes[start + 1] & 0x80)) {
		start++;
	}
	return bytes.slice(start);
}

export function derLength(len: number): Uint8Array {
	if (len < 0x80) return new Uint8Array([len]);
	const bytes: number[] = [];
	let n = len;
	while (n > 0) {
		bytes.unshift(n & 0xff);
		n >>>= 8;
	}
	return new Uint8Array([0x80 | bytes.length, ...bytes]);
}

export function derTaggedRaw(tag: number, body: Uint8Array): Uint8Array {
	const lenBytes = derLength(body.byteLength);
	const out = new Uint8Array(1 + lenBytes.byteLength + body.byteLength);
	out[0] = tag;
	out.set(lenBytes, 1);
	out.set(body, 1 + lenBytes.byteLength);
	return out;
}

export function derSeq(items: Uint8Array[]): Uint8Array {
	return derTaggedRaw(0x30, concatBytes(items));
}

export function derSet(items: Uint8Array[]): Uint8Array {
	return derTaggedRaw(0x31, concatBytes(items));
}

export function derInteger(bytes: Uint8Array): Uint8Array {
	if (bytes.byteLength > 0 && bytes[0] & 0x80) {
		const padded = new Uint8Array(bytes.byteLength + 1);
		padded[0] = 0x00;
		padded.set(bytes, 1);
		return derTaggedRaw(0x02, padded);
	}
	return derTaggedRaw(0x02, bytes);
}

export function derOctet(bytes: Uint8Array): Uint8Array {
	return derTaggedRaw(0x04, bytes);
}

export function derBitString(bytes: Uint8Array): Uint8Array {
	const out = new Uint8Array(bytes.byteLength + 1);
	out[0] = 0x00;
	out.set(bytes, 1);
	return derTaggedRaw(0x03, out);
}

export function derUtf8(s: string): Uint8Array {
	return derTaggedRaw(0x0c, new TextEncoder().encode(s));
}

export function derTagged(tag: number, body: Uint8Array): Uint8Array {
	return derTaggedRaw(0xa0 | tag, body);
}

export function derOid(arcs: number[]): Uint8Array {
	if (arcs.length < 2) throw new Error("OID needs at least 2 arcs");
	const out: number[] = [arcs[0] * 40 + arcs[1]];
	for (let i = 2; i < arcs.length; i++) {
		let arc = arcs[i];
		const stack: number[] = [arc & 0x7f];
		arc >>>= 7;
		while (arc > 0) {
			stack.unshift((arc & 0x7f) | 0x80);
			arc >>>= 7;
		}
		out.push(...stack);
	}
	return derTaggedRaw(0x06, new Uint8Array(out));
}

export function concatBytes(chunks: Uint8Array[]): Uint8Array {
	let total = 0;
	for (const c of chunks) total += c.byteLength;
	const out = new Uint8Array(total);
	let off = 0;
	for (const c of chunks) {
		out.set(c, off);
		off += c.byteLength;
	}
	return out;
}

export function derToPem(der: Uint8Array, label: string): string {
	const b64 = Buffer.from(der).toString("base64");
	const lines: string[] = [];
	for (let i = 0; i < b64.length; i += 64) lines.push(b64.slice(i, i + 64));
	return `-----BEGIN ${label}-----\n${lines.join("\n")}\n-----END ${label}-----\n`;
}

export function b64urlDecode(s: string): Uint8Array {
	const pad = "=".repeat((4 - (s.length % 4)) % 4);
	const b64 = (s + pad).replace(/-/g, "+").replace(/_/g, "/");
	return new Uint8Array(Buffer.from(b64, "base64"));
}
