// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import { describe, expect, test } from "bun:test";
import { X509Certificate } from "node:crypto";

import {
	PinningError,
	assertCaPin,
	assertDirectCaPin,
	caCertDerFp16,
	caCertSpkiFp16,
	spkiFp16,
} from "../src/spki";
import { CA_CERT_DER_FP16_HEX, CA_PEM, LEAF_PEM } from "./cert_fixtures";

const CA_FP16_HEX = "616a75b8113d89062796b4f591d1165f";
const CA_SPKI_DER_HEX =
	"3059301306072a8648ce3d020106082a8648ce3d030107034200043ed1477e38da335b5fc5e2257cdc28961b7b0a8ce45a7a2994df6cfcb1a877ac470fdf1db556f7e4e673cd7614afe9f01b999590f72f9235ad00d6a7e57d8807";

const OTHER_PEM = `-----BEGIN CERTIFICATE-----
MIIBkDCCATagAwIBAgIUY7EBjiURm3clg8F1yDA8evEnMaowCgYIKoZIzj0EAwIw
FDESMBAGA1UEAwwJc3BsIG90aGVyMB4XDTI2MDUyOTIyMjc0NloXDTM2MDUyNjIy
Mjc0NlowFDESMBAGA1UEAwwJc3BsIG90aGVyMFkwEwYHKoZIzj0CAQYIKoZIzj0D
AQcDQgAEgpEJm2ZuYFwXcjaD1xAWctp4asnXSM5E1d1NnzAUWVzqD0q5aMtfXqq0
Zo0v/s4R9bJBfSiZwUQjiClwqwzh16NmMGQwHQYDVR0OBBYEFGaYsjRy4JFe4kWb
0ql3LNBa5pCqMB8GA1UdIwQYMBaAFGaYsjRy4JFe4kWb0ql3LNBa5pCqMBIGA1Ud
EwEB/wQIMAYBAf8CAQAwDgYDVR0PAQH/BAQDAgGGMAoGCCqGSM49BAMCA0gAMEUC
IAbi3RV63AAMmZU/Xe3CzbwSjjxa8pmef3nWmncW4Xz7AiEA2+LBauywQpqbZGge
moxtYtbu52dSrQUiI3VWBY3CeMM=
-----END CERTIFICATE-----`;

describe("SPKI pinning", () => {
	test("computes CA cert SPKI fingerprint", () => {
		expect(hex(caCertSpkiFp16(CA_PEM))).toBe(CA_FP16_HEX);
	});

	test("spkiFp16 works on raw SPKI DER", () => {
		expect(hex(spkiFp16(hexToBytes(CA_SPKI_DER_HEX)))).toBe(CA_FP16_HEX);
	});

	test("assertCaPin accepts a leaf signed by the pinned CA", () => {
		expect(() =>
			assertCaPin({
				caPem: CA_PEM,
				expectedFp16: hexToBytes(CA_FP16_HEX),
				peerLeaf: new X509Certificate(LEAF_PEM),
			}),
		).not.toThrow();
	});

	test("assertCaPin rejects a wrong SPKI fingerprint", () => {
		expect(() =>
			assertCaPin({
				caPem: CA_PEM,
				expectedFp16: hexToBytes("00000000000000000000000000000000"),
				peerLeaf: new X509Certificate(LEAF_PEM),
			}),
		).toThrow(PinningError);
	});

	test("assertCaPin rejects a leaf not signed by the pinned CA", () => {
		expect(() =>
			assertCaPin({
				caPem: CA_PEM,
				expectedFp16: hexToBytes(CA_FP16_HEX),
				peerLeaf: new X509Certificate(OTHER_PEM),
			}),
		).toThrow(PinningError);
	});
});

describe("LAN-direct (cert-DER) pinning", () => {
	test("computes CA cert-DER fingerprint", () => {
		expect(hex(caCertDerFp16(CA_PEM))).toBe(CA_CERT_DER_FP16_HEX);
	});

	test("cert-DER and SPKI fingerprints differ (separate pin domains)", () => {
		expect(hex(caCertDerFp16(CA_PEM))).not.toBe(hex(caCertSpkiFp16(CA_PEM)));
	});

	test("assertDirectCaPin accepts a leaf signed by the pinned CA", () => {
		expect(() =>
			assertDirectCaPin({
				caPem: CA_PEM,
				expectedFp16: hexToBytes(CA_CERT_DER_FP16_HEX),
				peerLeaf: new X509Certificate(LEAF_PEM),
			}),
		).not.toThrow();
	});

	test("assertDirectCaPin rejects a wrong cert-DER fingerprint", () => {
		expect(() =>
			assertDirectCaPin({
				caPem: CA_PEM,
				expectedFp16: hexToBytes("00000000000000000000000000000000"),
				peerLeaf: new X509Certificate(LEAF_PEM),
			}),
		).toThrow(PinningError);
	});

	test("assertDirectCaPin rejects an SPKI fingerprint (wrong domain)", () => {
		expect(() =>
			assertDirectCaPin({
				caPem: CA_PEM,
				expectedFp16: hexToBytes(CA_FP16_HEX),
				peerLeaf: new X509Certificate(LEAF_PEM),
			}),
		).toThrow(PinningError);
	});

	test("assertDirectCaPin rejects a leaf not signed by the pinned CA", () => {
		expect(() =>
			assertDirectCaPin({
				caPem: CA_PEM,
				expectedFp16: hexToBytes(CA_CERT_DER_FP16_HEX),
				peerLeaf: new X509Certificate(OTHER_PEM),
			}),
		).toThrow(PinningError);
	});

	test("assertDirectCaPin rejects a missing peer leaf", () => {
		expect(() =>
			assertDirectCaPin({
				caPem: CA_PEM,
				expectedFp16: hexToBytes(CA_CERT_DER_FP16_HEX),
				peerLeaf: undefined,
			}),
		).toThrow(PinningError);
	});
});

function hex(bytes: Uint8Array): string {
	return Buffer.from(bytes).toString("hex");
}

function hexToBytes(s: string): Uint8Array {
	return new Uint8Array(Buffer.from(s, "hex"));
}
