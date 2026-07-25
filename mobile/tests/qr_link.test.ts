// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import { describe, expect, test } from "bun:test";

import { decode, encode } from "../src/crockford32";
import { looksLikePairLink, parsePairLink } from "../src/qr_link";

const WELL_KNOWN_FRAGMENT =
	"0C938NKR28T5CY0J6HB7G4HMASW03RJ004HMASW9NF6YY0938NKRKAYDXW0XXBDYXZ5FXENY04HMASW9NF6YY00";
const WELL_KNOWN_HEX =
	"031234567812345678123456781234567801e2400123456789abcdef0123456789abcdef01deadbeefcafebabe0123456789abcdef00";
const CUSTOM_FRAGMENT =
	"0C938NKR28T5CY0J6HB7G4HMASW03RJ004HMASW9NF6YY0938NKRKAYDXW0XXBDYXZ5FXENY04HMASW9NF6YY5B8EHT70WST5WQQ4SBCC5WJWSBRC5PQ0V35";
const CUSTOM_HEX =
	"031234567812345678123456781234567801e2400123456789abcdef0123456789abcdef01deadbeefcafebabe0123456789abcdef1568747470733a2f2f72656c61792e6578616d706c65";
const DIRECT_FRAGMENT = "0G0W000258DSX8DJRFAEBXG7308J4CT4ANK7F26YNPZEZJQYQAZ028T5CY4TQKFF";

describe("pair QR links", () => {
	test("Crockford decode matches relay byte vectors", () => {
		expect(hex(decode(WELL_KNOWN_FRAGMENT))).toBe(WELL_KNOWN_HEX);
		expect(decode(WELL_KNOWN_FRAGMENT).byteLength).toBe(54);
		expect(hex(decode(CUSTOM_FRAGMENT))).toBe(CUSTOM_HEX);
		expect(decode(CUSTOM_FRAGMENT).byteLength).toBe(75);
	});

	test("Crockford encode round-trips relay fragments", () => {
		expect(encode(decode(WELL_KNOWN_FRAGMENT))).toBe(WELL_KNOWN_FRAGMENT);
		expect(encode(decode(CUSTOM_FRAGMENT))).toBe(CUSTOM_FRAGMENT);
	});

	test("parsePairLink extracts well-known relay fields", () => {
		const link = parsePairLink(`https://go.solstone.app/p#${WELL_KNOWN_FRAGMENT}`);
		expect(link.kind).toBe("relay");
		if (link.kind !== "relay") throw new Error("expected relay link");
		expect(link.instanceId).toBe("12345678-1234-5678-1234-567812345678");
		expect(link.totp).toBe("123456");
		expect(link.nonce).toBe("0123456789abcdef0123456789abcdef");
		expect(Array.from(link.caFp)).toEqual(
			Array.from(hexToBytes("deadbeefcafebabe0123456789abcdef")),
		);
		expect(link.relayOrigin).toBeNull();
	});

	test("parsePairLink extracts custom relay origin", () => {
		const link = parsePairLink(`https://go.solstone.app/p#${CUSTOM_FRAGMENT}`);
		expect(link.kind).toBe("relay");
		if (link.kind !== "relay") throw new Error("expected relay link");
		expect(link.relayOrigin).toBe("https://relay.example");
	});

	test("parsePairLink dispatches version 0x04 as direct", () => {
		expect(encode(decode(DIRECT_FRAGMENT))).toBe(DIRECT_FRAGMENT);
		const link = parsePairLink(`https://go.solstone.app/p#${DIRECT_FRAGMENT}`);
		expect(link.kind).toBe("direct");
		if (link.kind !== "direct") throw new Error("expected direct link");
		expect(link.addrType).toBe(1);
		expect(link.candidates).toEqual(["192.0.2.42"]);
		expect("ipv4" in link).toBe(false);
		expect(link.port).toBe(7070);
		expect(link.nonce).toBe("a1b2c3d4e5f607181122334455667788");
		expect(Array.from(link.caFp)).toEqual(
			Array.from(hexToBytes("deadbeefcafebabe0123456789abcdef")),
		);
	});

	test("parsePairLink decodes 0x05 counts 1 through 4 at their variable offsets", () => {
		const addresses = ["10.0.0.1", "172.16.0.2", "192.168.0.3", "100.64.0.4"];
		for (let count = 1; count <= 4; count++) {
			const bytes = buildMultiBytes(addresses.slice(0, count));
			const link = parsePairLink(`https://go.solstone.app/p#${encode(bytes)}`);
			expect(link.kind).toBe("direct");
			if (link.kind !== "direct") throw new Error("expected direct link");
			expect(link.addrType).toBe(1);
			expect(link.candidates).toEqual(addresses.slice(0, count));
			expect(link.port).toBe(7070);
			expect(link.nonce).toBe("a1b2c3d4e5f607181122334455667788");
			expect(hex(link.caFp)).toBe("deadbeefcafebabe0123456789abcdef");
		}
	});

	test("parsePairLink refuses malformed 0x05 counts before offset decoding", () => {
		for (const count of [0, 5, 255]) {
			expect(() => parsePairLink(linkFromBytes(new Uint8Array([0x05, 0x01, count])))).toThrow(
				"count must be 1 through 4",
			);
		}
	});

	test("parsePairLink bounds-checks the 0x05 header before reading count", () => {
		for (const bytes of [new Uint8Array([0x05]), new Uint8Array([0x05, 0x01])]) {
			expect(() => parsePairLink(linkFromBytes(bytes))).toThrow("expected at least 3 bytes");
		}
	});

	test("parsePairLink requires the exact 0x05 length", () => {
		const bytes = buildMultiBytes(["10.0.0.1", "192.168.0.2"]);
		expect(() => parsePairLink(linkFromBytes(bytes.slice(0, -1)))).toThrow("expected 45 bytes");
		const extended = new Uint8Array(bytes.byteLength + 1);
		extended.set(bytes);
		expect(() => parsePairLink(linkFromBytes(extended))).toThrow("expected 45 bytes");
	});

	test("parsePairLink rejects non-IPv4 direct address types", () => {
		const single = decode(DIRECT_FRAGMENT);
		single[1] = 0x02;
		expect(() => parsePairLink(linkFromBytes(single))).toThrow("unsupported address type");

		const multi = buildMultiBytes(["10.0.0.1"]);
		multi[1] = 0x02;
		expect(() => parsePairLink(linkFromBytes(multi))).toThrow("unsupported address type");
	});

	test("parsePairLink rejects old direct version 0x02", () => {
		expect(() =>
			parsePairLink(
				"https://go.solstone.app/p#080W000258DSX8DJRFAEBXG733FAVFQFSBZBNFG14D2PF2DBSQQG",
			),
		).toThrow("unsupported pair-link version: 0x02");
	});

	test("looksLikePairLink identifies go.solstone.app pair URLs only", () => {
		expect(looksLikePairLink(`https://go.solstone.app/p#${WELL_KNOWN_FRAGMENT}`)).toBe(true);
		expect(looksLikePairLink("https://192.168.1.10:8443/pair?token=x")).toBe(false);
	});
});

function hex(bytes: Uint8Array): string {
	return Buffer.from(bytes).toString("hex");
}

function hexToBytes(s: string): Uint8Array {
	return new Uint8Array(Buffer.from(s, "hex"));
}

function linkFromBytes(bytes: Uint8Array): string {
	return `https://go.solstone.app/p#${encode(bytes)}`;
}

function buildMultiBytes(addresses: readonly string[]): Uint8Array {
	const bytes = new Uint8Array(5 + 4 * addresses.length + 32);
	bytes.set([0x05, 0x01, addresses.length, 0x1b, 0x9e]);
	for (const [index, address] of addresses.entries()) {
		bytes.set(
			address.split(".").map((part) => Number(part)),
			5 + 4 * index,
		);
	}
	const nonceOffset = 5 + 4 * addresses.length;
	bytes.set(hexToBytes("a1b2c3d4e5f607181122334455667788"), nonceOffset);
	bytes.set(hexToBytes("deadbeefcafebabe0123456789abcdef"), nonceOffset + 16);
	return bytes;
}
