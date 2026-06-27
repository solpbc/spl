// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

// Pair flow — mobile side.
//
// 1. Generate an ECDSA-P256 keypair locally (mode 0600 on the private-key file).
// 2. Build a CSR carrying the public key.
// 3. POST to the home's local HTTPS pair URL, pinning the home's self-signed
//    CA cert (pin fingerprint optionally provided out-of-band).
// 4. Receive { client_cert, ca_chain, instance_id, home_label, home_attestation }.
// 5. Forward the home_attestation to spl-relay /enroll/device and store the
//    resulting device_token alongside the local keypair.

import { webcrypto } from "node:crypto";
import { chmod, readFile, writeFile } from "node:fs/promises";

import { buildCsr, jwkToPkcs8Pem } from "./_csr_internal";
import { type RefreshAction, classifyRefreshOutcome } from "./device_token";

export interface PairingState {
	instance_id: string;
	home_label: string;
	relay_endpoint: string;
	ca_chain: string[];
	client_cert: string;
	client_key_pem: string;
	device_token: string;
	fingerprint: string;
}

export async function loadPairing(path: string): Promise<PairingState> {
	const raw = await readFile(path, "utf-8");
	return JSON.parse(raw) as PairingState;
}

export async function tryLoadPairing(path: string): Promise<PairingState | null> {
	try {
		return await loadPairing(path);
	} catch (err) {
		if (isEnoent(err)) return null;
		throw err;
	}
}

export async function savePairing(path: string, state: PairingState): Promise<void> {
	await writeFile(path, `${JSON.stringify(state, null, 2)}\n`);
	await chmod(path, 0o600);
}

export interface PairInput {
	lanUrl: string;
	deviceLabel: string;
	relayEndpoint: string;
	/** Optional: SHA-256 fingerprint of the home's self-signed TLS cert (hex). */
	caFingerprint?: string;
	/** Test-only: bypass TLS verification for the LAN call. Never in production. */
	insecureSkipLanVerify?: boolean;
}

export interface PairResult {
	state: PairingState;
}

export async function pair(input: PairInput): Promise<PairResult> {
	const nonce = new URL(input.lanUrl).searchParams.get("token");
	if (!nonce) throw new Error(`pair URL missing ?token=: ${input.lanUrl}`);

	const { publicKey, privateKey } = (await webcrypto.subtle.generateKey(
		{ name: "ECDSA", namedCurve: "P-256" },
		true,
		["sign", "verify"],
	)) as CryptoKeyPair;
	const publicJwk = (await webcrypto.subtle.exportKey("jwk", publicKey)) as Record<string, string>;
	const privateJwk = (await webcrypto.subtle.exportKey("jwk", privateKey)) as Record<
		string,
		string
	>;

	const clientKeyPem = jwkToPkcs8Pem(privateJwk);
	const csrPem = await buildCsr(input.deviceLabel, publicJwk, privateKey);

	const body = JSON.stringify({
		nonce,
		csr: csrPem,
		device_label: input.deviceLabel,
	});
	const pairResponse = await httpsPost(input.lanUrl, body, {
		caFingerprint: input.caFingerprint,
		insecureSkipVerify: input.insecureSkipLanVerify,
	});
	if (pairResponse.status !== 200) {
		throw new Error(`pair failed: HTTP ${pairResponse.status}: ${pairResponse.body}`);
	}
	const pairJson = JSON.parse(pairResponse.body) as {
		client_cert: string;
		ca_chain: string[];
		instance_id: string;
		home_label: string;
		home_attestation: string;
		fingerprint: string;
	};

	const { device_token } = await enrollDevice(input.relayEndpoint, {
		instance_id: pairJson.instance_id,
		home_attestation: pairJson.home_attestation,
	});

	const state: PairingState = {
		instance_id: pairJson.instance_id,
		home_label: pairJson.home_label,
		relay_endpoint: input.relayEndpoint.replace(/\/+$/, ""),
		ca_chain: pairJson.ca_chain,
		client_cert: pairJson.client_cert,
		client_key_pem: clientKeyPem,
		device_token,
		fingerprint: pairJson.fingerprint,
	};
	return { state };
}

export function buildEnrollBody(p: { instance_id: string; home_attestation: string }): {
	instance_id: string;
	home_attestation: string;
} {
	return { instance_id: p.instance_id, home_attestation: p.home_attestation };
}

export async function enrollDevice(
	relayEndpoint: string,
	p: { instance_id: string; home_attestation: string },
): Promise<{ device_token: string }> {
	const enroll = await httpsPost(
		`${relayEndpoint.replace(/\/+$/, "")}/enroll/device`,
		JSON.stringify(buildEnrollBody(p)),
		{},
	);
	if (enroll.status !== 200) {
		throw new Error(`/enroll/device failed: HTTP ${enroll.status}: ${enroll.body}`);
	}
	return JSON.parse(enroll.body) as { device_token: string };
}

export async function refreshDeviceToken(
	endpoint: string,
	currentToken: string,
): Promise<{ action: RefreshAction; token?: string }> {
	let refresh: HttpResponse;
	try {
		refresh = await httpsPost(
			`${endpoint.replace(/\/+$/, "")}/token/refresh`,
			JSON.stringify({ device_token: currentToken }),
			{},
		);
	} catch {
		return { action: "keep_existing" };
	}

	const action = classifyRefreshOutcome(refresh.status);
	if (action !== "use_new_token") return { action };

	try {
		const body = JSON.parse(refresh.body) as { device_token?: unknown };
		if (typeof body.device_token === "string" && body.device_token) {
			return { action: "use_new_token", token: body.device_token };
		}
	} catch {}
	return { action: "keep_existing" };
}

export type PairGuardDecision = "first-time" | "already-connected" | "reconnect";

export function decidePairAction(
	scannedInstanceId: string | null,
	storedInstanceId: string | null,
): PairGuardDecision {
	if (storedInstanceId === null) return "first-time";
	if (scannedInstanceId === storedInstanceId) return "already-connected";
	return "reconnect";
}

export function pairSummaryLine(
	decision: PairGuardDecision,
	homeLabel: string,
	instanceId: string,
): string {
	switch (decision) {
		case "first-time":
			return `Paired with ${homeLabel} (instance ${instanceId}).`;
		case "already-connected":
			return `Already connected to ${homeLabel} (instance ${instanceId}) — no new pairing needed.`;
		case "reconnect":
			return `Reconnected to ${homeLabel} (instance ${instanceId}).`;
	}
}

export interface HttpsOpts {
	caFingerprint?: string;
	insecureSkipVerify?: boolean;
}

export interface HttpResponse {
	status: number;
	body: string;
}

export async function httpsPost(url: string, body: string, opts: HttpsOpts): Promise<HttpResponse> {
	const https = await import("node:https");
	const http = await import("node:http");
	const crypto = await import("node:crypto");

	return new Promise((resolve, reject) => {
		const parsed = new URL(url);
		const isHttps = parsed.protocol === "https:";
		const client = isHttps ? https : http;
		const options = {
			method: "POST",
			hostname: parsed.hostname,
			port: parsed.port || (isHttps ? 443 : 80),
			path: parsed.pathname + parsed.search,
			headers: {
				"content-type": "application/json",
				"content-length": Buffer.byteLength(body).toString(),
			},
			...(isHttps
				? {
						rejectUnauthorized: !(opts.caFingerprint !== undefined || opts.insecureSkipVerify),
						checkServerIdentity: opts.caFingerprint
							? (_: string, cert: { raw: Buffer }) => {
									const digest = crypto.createHash("sha256").update(cert.raw).digest("hex");
									if (digest.toLowerCase() !== opts.caFingerprint?.toLowerCase()) {
										return new Error(
											`CA fingerprint mismatch: got ${digest}, pinned ${opts.caFingerprint}`,
										);
									}
									return undefined;
								}
							: undefined,
					}
				: {}),
		};
		const req = client.request(options, (res) => {
			const chunks: Buffer[] = [];
			res.on("data", (c: Buffer) => chunks.push(c));
			res.on("end", () => {
				resolve({
					status: res.statusCode ?? 0,
					body: Buffer.concat(chunks).toString("utf-8"),
				});
			});
		});
		req.on("error", reject);
		req.write(body);
		req.end();
	});
}

function isEnoent(err: unknown): boolean {
	return (
		typeof err === "object" &&
		err !== null &&
		"code" in err &&
		(err as { code?: unknown }).code === "ENOENT"
	);
}
