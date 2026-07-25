// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

// Pair-link parser for solstone QR payloads. Dispatch on the decoded version
// byte first so relay and direct layouts cannot cross-read one another.

import { decode } from "./crockford32";

export interface RelayPairLink {
	kind: "relay";
	instanceId: string;
	totp: string;
	nonce: string;
	caFpTag: number;
	caFp: Uint8Array;
	relayOrigin: string | null;
}

export interface DirectPairLink {
	kind: "direct";
	addrType: 0x01;
	candidates: readonly string[];
	port: number;
	nonce: string;
	caFp: Uint8Array;
}

export type PairLink = RelayPairLink | DirectPairLink;

export function looksLikePairLink(s: string): boolean {
	try {
		const url = new URL(s);
		return (
			url.protocol === "https:" &&
			url.hostname === "go.solstone.app" &&
			url.pathname === "/p" &&
			url.hash.length > 1
		);
	} catch {
		return false;
	}
}

export function parsePairLink(s: string): PairLink {
	const url = new URL(s);
	const fragment = url.hash.slice(1);
	if (!fragment) throw new Error("pair link missing fragment");

	const bytes = decode(fragment);
	if (bytes.byteLength === 0) throw new Error("pair link payload is empty");

	const version = bytes[0];
	if (version === 0x03) return parseRelay(bytes);
	if (version === 0x04) return parseDirectSingle(bytes);
	if (version === 0x05) return parseDirectMulti(bytes);
	throw new Error(`unsupported pair-link version: 0x${version.toString(16).padStart(2, "0")}`);
}

function parseRelay(bytes: Uint8Array): RelayPairLink {
	if (bytes.byteLength < 54) {
		throw new Error(
			`malformed relay pair link: expected at least 54 bytes, got ${bytes.byteLength}`,
		);
	}

	const selector = bytes[53];
	const expectedLength = selector === 0 ? 54 : 54 + selector;
	if (bytes.byteLength !== expectedLength) {
		throw new Error(
			`malformed relay pair link: selector ${selector} requires ${expectedLength} bytes, got ${bytes.byteLength}`,
		);
	}

	const totpInt = (bytes[17] << 16) | (bytes[18] << 8) | bytes[19];
	return {
		kind: "relay",
		instanceId: uuidFromRaw(bytes.slice(1, 17)),
		totp: String(totpInt).padStart(6, "0"),
		nonce: hex(bytes.slice(20, 36)),
		caFpTag: bytes[36],
		caFp: bytes.slice(37, 53),
		relayOrigin: selector === 0 ? null : new TextDecoder().decode(bytes.slice(54, 54 + selector)),
	};
}

function parseDirectSingle(bytes: Uint8Array): DirectPairLink {
	if (bytes.byteLength !== 40) {
		throw new Error(`malformed direct pair link: expected 40 bytes, got ${bytes.byteLength}`);
	}
	assertDirectAddrType(bytes[1]);
	return {
		kind: "direct",
		addrType: 0x01,
		candidates: [ipv4FromBytes(bytes.slice(2, 6))],
		port: (bytes[6] << 8) | bytes[7],
		nonce: hex(bytes.slice(8, 24)),
		caFp: bytes.slice(24, 40),
	};
}

function parseDirectMulti(bytes: Uint8Array): DirectPairLink {
	if (bytes.byteLength < 3) {
		throw new Error("malformed multi-candidate direct pair link: expected at least 3 bytes");
	}
	assertDirectAddrType(bytes[1]);
	const count = bytes[2];
	if (count < 1 || count > 4) {
		throw new Error("malformed multi-candidate direct pair link: count must be 1 through 4");
	}
	const expectedLength = 5 + 4 * count + 32;
	if (bytes.byteLength !== expectedLength) {
		throw new Error(
			`malformed multi-candidate direct pair link: expected ${expectedLength} bytes, got ${bytes.byteLength}`,
		);
	}

	const candidates: string[] = [];
	for (let i = 0; i < count; i++) {
		const offset = 5 + 4 * i;
		candidates.push(ipv4FromBytes(bytes.slice(offset, offset + 4)));
	}
	const nonceOffset = 5 + 4 * count;
	return {
		kind: "direct",
		addrType: 0x01,
		candidates,
		port: (bytes[3] << 8) | bytes[4],
		nonce: hex(bytes.slice(nonceOffset, nonceOffset + 16)),
		caFp: bytes.slice(nonceOffset + 16, nonceOffset + 32),
	};
}

function assertDirectAddrType(addrType: number): asserts addrType is 0x01 {
	if (addrType !== 0x01) {
		throw new Error("malformed direct pair link: unsupported address type");
	}
}

function ipv4FromBytes(bytes: Uint8Array): string {
	return Array.from(bytes).join(".");
}

function uuidFromRaw(bytes: Uint8Array): string {
	if (bytes.byteLength !== 16) {
		throw new Error(`raw UUID must be 16 bytes, got ${bytes.byteLength}`);
	}
	const h = hex(bytes);
	return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

function hex(bytes: Uint8Array): string {
	return Buffer.from(bytes).toString("hex");
}
