// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import { describe, expect, it } from "vitest";
import {
	canonicalizeOwnerPurgeJson,
	ownerPurgeIntegrityFrame,
	ownerPurgeRequestDigest,
} from "../src/purge";
import { base64UrlEncode } from "../src/tokens";

describe("owner-purge v1 canonical conformance", () => {
	it("matches the retained relay-v1 canonical request, digest, frame, and HMAC", async () => {
		const request = {
			version: 1,
			key_version: 1,
			operation_id: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
			service: "relay",
			association_snapshot: {
				instance_ids: [
					"00000000-0000-4000-8000-000000000001",
					"00000000-0000-4000-8000-000000000002",
				],
			},
			request_digest: "ou_NS2c8cDEtGWNwlKWjQ3lwxlWcBWu8pTlV2ql20i4",
			issued_at: 2000000000000,
			expires_at: 2000000300000,
		};
		const expectedCanonical =
			'{"association_snapshot":{"instance_ids":["00000000-0000-4000-8000-000000000001","00000000-0000-4000-8000-000000000002"]},"expires_at":2000000300000,"issued_at":2000000000000,"key_version":1,"operation_id":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","request_digest":"ou_NS2c8cDEtGWNwlKWjQ3lwxlWcBWu8pTlV2ql20i4","service":"relay","version":1}';
		expect(canonicalizeOwnerPurgeJson(request)).toBe(expectedCanonical);
		expect(await ownerPurgeRequestDigest(1, 1, "relay", request.association_snapshot)).toBe(
			"ou_NS2c8cDEtGWNwlKWjQ3lwxlWcBWu8pTlV2ql20i4",
		);
		const frame = ownerPurgeIntegrityFrame(
			"solpbc-owner-purge-v1:relay:request",
			expectedCanonical,
		);
		expect(await hmac(frame, "owner-purge-v1-fixture-test-key")).toBe(
			"pM1F4bARL-0ncsRvNTmFadoIwYZSXjFB0LdKTar_gG8",
		);
	});

	it("matches the support UTF-8 byte-vector", async () => {
		const snapshot = {
			portal_principal: "fixture-principal-utf8",
			verified_emails: ["álpha@example.test"],
		};
		const expectedCanonical =
			'{"association_snapshot":{"portal_principal":"fixture-principal-utf8","verified_emails":["álpha@example.test"]},"expires_at":2000000300000,"issued_at":2000000000000,"key_version":2,"operation_id":"CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC","request_digest":"32nZxoKc0q_2WakrM4Z25NZH5cKEWc-9PUhYdD97d3E","service":"support","version":1}';
		const expectedFrameHex = [
			"0000000000000025736f6c7062632d6f776e65722d70757267652d76313a737570706f72743a7265717565737400000000000001517b226173736f63",
			"696174696f6e5f736e617073686f74223a7b22706f7274616c5f7072696e636970616c223a22666978747572652d7072696e636970616c2d75746638",
			"222c2276657269666965645f656d61696c73223a5b22c3a16c706861406578616d706c652e74657374225d7d2c22657870697265735f6174223a3230",
			"30303030303330303030302c226973737565645f6174223a323030303030303030303030302c226b65795f76657273696f6e223a322c226f70657261",
			"74696f6e5f6964223a2243434343434343434343434343434343434343434343434343434343434343434343434343434343434343222c2272657175",
			"6573745f646967657374223a2233326e5a786f4b6330715f3257616b724d345a32354e5a4835634b4557632d395055685964443937643345222c2273",
			"657276696365223a22737570706f7274222c2276657273696f6e223a317d",
		].join("");
		const request = {
			version: 1,
			key_version: 2,
			operation_id: "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
			service: "support",
			association_snapshot: snapshot,
			request_digest: "32nZxoKc0q_2WakrM4Z25NZH5cKEWc-9PUhYdD97d3E",
			issued_at: 2000000000000,
			expires_at: 2000000300000,
		};
		expect(canonicalizeOwnerPurgeJson(request)).toBe(expectedCanonical);
		expect(
			toHex(ownerPurgeIntegrityFrame("solpbc-owner-purge-v1:support:request", expectedCanonical)),
		).toBe(expectedFrameHex);
		expect(await ownerPurgeRequestDigest(1, 2, "support", snapshot)).toBe(
			"32nZxoKc0q_2WakrM4Z25NZH5cKEWc-9PUhYdD97d3E",
		);
	});
});

async function hmac(frame: Uint8Array, secret: string): Promise<string> {
	const key = await crypto.subtle.importKey(
		"raw",
		new TextEncoder().encode(secret),
		{ name: "HMAC", hash: "SHA-256" },
		false,
		["sign"],
	);
	return base64UrlEncode(new Uint8Array(await crypto.subtle.sign("HMAC", key, frame)));
}

function toHex(bytes: Uint8Array): string {
	return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}
