// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import { describe, expect, it } from "vitest";
import fixture from "../../proto/purge-v1-fixtures.json";
import {
	canonicalizeInstances,
	sha256FingerprintText,
	verifyPurgeConfirmEnvelope,
	verifyPurgeEnvelope,
} from "../src/purge";
import { genSigningKeypair, signClaims, tamperCompactJwsSignature } from "./fixtures";

const NOW = 2_000_000_000;

function id(value: number): string {
	return value.toString(16).padStart(10, "a");
}

function purgeClaims(overrides: Record<string, unknown> = {}): Record<string, unknown> {
	return {
		iss: "spl-portal",
		aud: "spl-relay-purge",
		ver: "1",
		typ: "purge",
		op: "unit-purge-operation",
		instances: [id(1)],
		iat: NOW - 60,
		exp: NOW + 300,
		...overrides,
	};
}

function confirmClaims(overrides: Record<string, unknown> = {}): Record<string, unknown> {
	return {
		iss: "spl-portal",
		aud: "spl-relay-purge",
		ver: "1",
		typ: "purge-confirm",
		op: "unit-purge-operation",
		snapshot_digest: `sha256:${"a".repeat(64)}`,
		state: "complete",
		iat: NOW - 60,
		exp: NOW + 300,
		...overrides,
	};
}

describe("portal purge pure helpers", () => {
	it("canonicalizes exact IDs by deduplicating and sorting after validation", () => {
		expect(canonicalizeInstances([])).toEqual({ ok: true, instances: [] });
		expect(canonicalizeInstances([id(2), id(1), id(2)])).toEqual({
			ok: true,
			instances: [id(1), id(2)],
		});
		expect(canonicalizeInstances(["not-an-instance-id"])).toEqual({
			ok: false,
			reason: "malformed",
		});
	});

	it("applies the 100-ID cap only after deduplication", () => {
		const oneHundred = Array.from({ length: 100 }, (_, value) => id(value));
		expect(canonicalizeInstances(oneHundred)).toMatchObject({ ok: true });
		expect(canonicalizeInstances([...oneHundred, id(101)])).toEqual({
			ok: false,
			reason: "too_many",
		});
		expect(canonicalizeInstances(Array.from({ length: 101 }, () => id(1)))).toEqual({
			ok: true,
			instances: [id(1)],
		});
	});

	it("renders operation and snapshot digests as lowercase SHA-256 fingerprints", async () => {
		const operationHash = await sha256FingerprintText("hello");
		const snapshotDigest = await sha256FingerprintText(JSON.stringify([id(1)]));
		expect(operationHash).toBe(
			"sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
		);
		expect(snapshotDigest).toMatch(/^sha256:[0-9a-f]{64}$/);
		expect(snapshotDigest).not.toBe(operationHash);
	});
});

describe("portal purge compact EdDSA JWT validation", () => {
	it("accepts a genuine envelope and rejects signature and kid changes", async () => {
		const keypair = await genSigningKeypair("purge-unit-kid");
		const envelope = await signClaims(keypair.privateJwkRaw, purgeClaims());
		expect(await verifyPurgeEnvelope(envelope, keypair.jwksPublicRaw, NOW)).toMatchObject({
			ok: true,
		});

		const tampered = tamperCompactJwsSignature(envelope);
		expect(tampered).not.toBe(envelope);
		expect(await verifyPurgeEnvelope(tampered, keypair.jwksPublicRaw, NOW)).toEqual({
			ok: false,
			reason: "untrusted",
		});

		const unknownKeypair = await genSigningKeypair("different-kid");
		expect(await verifyPurgeEnvelope(envelope, unknownKeypair.jwksPublicRaw, NOW)).toEqual({
			ok: false,
			reason: "untrusted",
		});
	});

	it("refuses wrong type, issuer, audience, and invalid common times", async () => {
		const keypair = await genSigningKeypair();
		for (const claims of [
			purgeClaims({ typ: "purge-confirm" }),
			purgeClaims({ iss: "another-portal" }),
			purgeClaims({ aud: "another-audience" }),
			purgeClaims({ iat: NOW + 1 }),
			purgeClaims({ iat: NOW, exp: NOW }),
			purgeClaims({ iat: NOW - 1, exp: NOW + 7 * 24 * 60 * 60 + 1 }),
			purgeClaims({ op: 7 }),
			purgeClaims({ op: "é".repeat(129) }),
		]) {
			const envelope = await signClaims(keypair.privateJwkRaw, claims);
			expect(await verifyPurgeEnvelope(envelope, keypair.jwksPublicRaw, NOW)).toMatchObject({
				ok: false,
			});
		}
	});

	it("enforces the independent five-minute confirmation lifetime and type separation", async () => {
		const keypair = await genSigningKeypair();
		const tooLong = await signClaims(
			keypair.privateJwkRaw,
			confirmClaims({ iat: NOW - 1, exp: NOW + 300 }),
		);
		expect(await verifyPurgeConfirmEnvelope(tooLong, keypair.jwksPublicRaw, NOW)).toEqual({
			ok: false,
			reason: "untrusted",
		});

		const includesTargets = await signClaims(
			keypair.privateJwkRaw,
			confirmClaims({ instances: [id(1)] }),
		);
		expect(await verifyPurgeConfirmEnvelope(includesTargets, keypair.jwksPublicRaw, NOW)).toEqual({
			ok: false,
			reason: "untrusted",
		});

		const wrongType = await signClaims(keypair.privateJwkRaw, purgeClaims());
		expect(await verifyPurgeConfirmEnvelope(wrongType, keypair.jwksPublicRaw, NOW)).toEqual({
			ok: false,
			reason: "untrusted",
		});

		const { snapshot_digest: _snapshotDigest, ...missingSnapshotDigestClaims } = confirmClaims();
		for (const claims of [
			missingSnapshotDigestClaims,
			confirmClaims({ snapshot_digest: "0".repeat(64) }),
			confirmClaims({ state: "retryable" }),
		]) {
			const envelope = await signClaims(keypair.privateJwkRaw, claims);
			expect(await verifyPurgeConfirmEnvelope(envelope, keypair.jwksPublicRaw, NOW)).toEqual({
				ok: false,
				reason: "untrusted",
			});
		}
	});

	it("verifies every static v1 fixture without committing its private key", async () => {
		expect(fixture.version).toBe("1");
		expect(fixture.vectors.map((vector) => vector.name)).toEqual([
			"valid_purge",
			"valid_purge_replay",
			"altered_snapshot_replay",
			"expired_purge",
			"too_many_instances",
			"tampered_signature",
			"legacy_confirm_refused",
			"valid_confirm",
			"confirm_replay",
			"confirmed_submit_replay",
			"confirm_purge_typed_attestation_refused",
			"confirm_retryable",
			"confirm_original_expired",
			"purge_retryable_binding_expired",
			"purge_complete_binding_expired",
			"purge_confirmed_binding_expired",
			"confirm_retryable_binding_expired",
			"confirm_complete_binding_expired",
			"confirm_confirmed_binding_expired",
			"confirm_absent_not_complete",
			"fault_then_retry",
		]);

		for (const vector of fixture.vectors) {
			if (vector.route === "purge") {
				const result = await verifyPurgeEnvelope(
					vector.envelope,
					fixture.portal_jwks_public,
					fixture.now,
				);
				if (vector.name === "expired_purge") {
					expect(result).toEqual({ ok: false, reason: "expired" });
				} else if (vector.name === "tampered_signature") {
					expect(result).toEqual({ ok: false, reason: "untrusted" });
				} else {
					expect(result).toMatchObject({ ok: true });
				}
				continue;
			}

			if (!("confirmation" in vector) || typeof vector.confirmation !== "string") {
				throw new Error(`confirm fixture missing confirmation: ${vector.name}`);
			}
			const original = await verifyPurgeEnvelope(
				vector.envelope,
				fixture.portal_jwks_public,
				fixture.now,
			);
			const confirmation = await verifyPurgeConfirmEnvelope(
				vector.confirmation,
				fixture.portal_jwks_public,
				fixture.now,
			);
			if (
				vector.name === "legacy_confirm_refused" ||
				vector.name === "confirm_purge_typed_attestation_refused"
			) {
				expect(original).toMatchObject({ ok: true });
				expect(confirmation).toEqual({ ok: false, reason: "untrusted" });
			} else if (vector.name === "confirm_original_expired") {
				expect(original).toEqual({ ok: false, reason: "expired" });
				expect(confirmation).toMatchObject({ ok: true });
			} else {
				expect(original).toMatchObject({ ok: true });
				expect(confirmation).toMatchObject({ ok: true });
			}
		}
	});
});
