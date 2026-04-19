// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import { describe, expect, it } from "vitest";
import { fingerprintDer, verifyAttestation } from "../src/attestation";
import { genCaKeypair, genClientCertDer, mintAttestation } from "./fixtures";

describe("verifyAttestation", () => {
	it("accepts a well-formed home-signed attestation", async () => {
		const ca = await genCaKeypair();
		const certDer = await genClientCertDer();
		const fp = await fingerprintDer(certDer);
		const attestation = await mintAttestation({
			caPrivateKey: ca.privateKey,
			instanceId: "inst-1",
			deviceFp: fp,
		});
		const r = await verifyAttestation({
			attestation,
			caPubkeyPem: ca.pubPem,
			expectedInstanceId: "inst-1",
			expectedDeviceFp: fp,
		});
		expect(r.ok).toBe(true);
	});

	it("rejects an attestation signed by a different CA", async () => {
		const realCa = await genCaKeypair();
		const attackerCa = await genCaKeypair();
		const certDer = await genClientCertDer();
		const fp = await fingerprintDer(certDer);
		const attestation = await mintAttestation({
			caPrivateKey: attackerCa.privateKey,
			instanceId: "inst-1",
			deviceFp: fp,
		});
		const r = await verifyAttestation({
			attestation,
			caPubkeyPem: realCa.pubPem,
			expectedInstanceId: "inst-1",
			expectedDeviceFp: fp,
		});
		expect(r).toEqual({ ok: false, reason: "bad_signature" });
	});

	it("rejects an attestation whose device_fp doesn't match the computed fingerprint", async () => {
		const ca = await genCaKeypair();
		const cert1 = await genClientCertDer("a");
		const cert2 = await genClientCertDer("b");
		const fp1 = await fingerprintDer(cert1);
		const fp2 = await fingerprintDer(cert2);
		expect(fp1).not.toBe(fp2);
		const attestation = await mintAttestation({
			caPrivateKey: ca.privateKey,
			instanceId: "inst-1",
			deviceFp: fp1,
		});
		const r = await verifyAttestation({
			attestation,
			caPubkeyPem: ca.pubPem,
			expectedInstanceId: "inst-1",
			expectedDeviceFp: fp2,
		});
		expect(r).toEqual({ ok: false, reason: "fp_mismatch" });
	});

	it("rejects an attestation for a different instance_id", async () => {
		const ca = await genCaKeypair();
		const certDer = await genClientCertDer();
		const fp = await fingerprintDer(certDer);
		const attestation = await mintAttestation({
			caPrivateKey: ca.privateKey,
			instanceId: "inst-1",
			deviceFp: fp,
		});
		const r = await verifyAttestation({
			attestation,
			caPubkeyPem: ca.pubPem,
			expectedInstanceId: "inst-2",
			expectedDeviceFp: fp,
		});
		expect(r.ok).toBe(false);
	});

	it("rejects an expired attestation", async () => {
		const ca = await genCaKeypair();
		const certDer = await genClientCertDer();
		const fp = await fingerprintDer(certDer);
		const now = Math.floor(Date.now() / 1000);
		const attestation = await mintAttestation({
			caPrivateKey: ca.privateKey,
			instanceId: "inst-1",
			deviceFp: fp,
			now: now - 600,
			exp: now - 300,
		});
		const r = await verifyAttestation({
			attestation,
			caPubkeyPem: ca.pubPem,
			expectedInstanceId: "inst-1",
			expectedDeviceFp: fp,
			now,
		});
		expect(r).toEqual({ ok: false, reason: "expired" });
	});

	it("rejects an attestation with > 5 minute lifetime", async () => {
		const ca = await genCaKeypair();
		const certDer = await genClientCertDer();
		const fp = await fingerprintDer(certDer);
		const now = Math.floor(Date.now() / 1000);
		const attestation = await mintAttestation({
			caPrivateKey: ca.privateKey,
			instanceId: "inst-1",
			deviceFp: fp,
			now,
			exp: now + 3600, // an hour — over the 5 min cap
		});
		const r = await verifyAttestation({
			attestation,
			caPubkeyPem: ca.pubPem,
			expectedInstanceId: "inst-1",
			expectedDeviceFp: fp,
			now,
		});
		expect(r).toEqual({ ok: false, reason: "too_long_lived" });
	});

	it("rejects an attestation with wrong audience", async () => {
		const ca = await genCaKeypair();
		const certDer = await genClientCertDer();
		const fp = await fingerprintDer(certDer);
		const attestation = await mintAttestation({
			caPrivateKey: ca.privateKey,
			instanceId: "inst-1",
			deviceFp: fp,
			overrideAudience: "not-spl-relay",
		});
		const r = await verifyAttestation({
			attestation,
			caPubkeyPem: ca.pubPem,
			expectedInstanceId: "inst-1",
			expectedDeviceFp: fp,
		});
		expect(r).toEqual({ ok: false, reason: "wrong_audience" });
	});
});
