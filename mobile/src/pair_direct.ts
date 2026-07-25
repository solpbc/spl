// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

// LAN-direct (v0x04/v0x05) pair flow. Candidate TLS sessions are prepared in
// wire order, but the nonce-bearing request is invoked exactly once, outside
// the preparation loop. Bun pins the returned CA to the live peer leaf after
// the response because node:tls does not expose the CA chain at handshake time.

import { webcrypto } from "node:crypto";

import { buildCsr, jwkToPkcs8Pem } from "./_csr_internal";
import { type DirectTunnelConfig, type TunnelSession, openDirectTunnel } from "./dial";
import { assertDirectCandidatesAdmitted } from "./direct_address_policy";
import { DIRECT_CANDIDATES_EXHAUSTED_MESSAGE } from "./direct_pair_messages";
import { type HttpRequest, type HttpResponse, httpRequest } from "./http_client";
import {
	type PairGuardDecision,
	type PairingState,
	decidePairAction,
	enrollDevice,
	savePairing,
} from "./pair";
import type { DirectPairLink } from "./qr_link";
import { assertDirectCaPin } from "./spki";

const CANDIDATE_DEADLINE_MS = 10_000;
const TEARDOWN_DEADLINE_MS = 10_000;
const MALFORMED_RESPONSE_MESSAGE = "direct pair response was malformed";

export interface DirectPairDeps {
	openTunnel(config: DirectTunnelConfig): Promise<TunnelSession>;
	request(mux: TunnelSession["mux"], request: HttpRequest): Promise<HttpResponse>;
	enrollDevice(
		relayEndpoint: string,
		input: { instance_id: string; home_attestation: string },
	): Promise<{ device_token: string }>;
	savePairing(path: string, state: PairingState): Promise<void>;
	generateKeyPair(): Promise<CryptoKeyPair>;
	setTimer(delayMs: number, callback: () => void): () => void;
}

export interface DirectPairInput {
	link: DirectPairLink;
	deviceLabel: string;
	relayEndpoint: string;
	statePath: string;
	storedInstanceId: string | null;
	deps?: Partial<DirectPairDeps>;
}

export interface DirectPairResult {
	state: PairingState;
	decision: PairGuardDecision;
	saved: boolean;
}

export class DirectCandidatesExhaustedError extends Error {
	constructor() {
		super(DIRECT_CANDIDATES_EXHAUSTED_MESSAGE);
		this.name = "DirectCandidatesExhaustedError";
	}
}

const DEFAULT_DEPS: DirectPairDeps = {
	openTunnel: openDirectTunnel,
	request: httpRequest,
	enrollDevice,
	savePairing,
	async generateKeyPair() {
		return (await webcrypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
			"sign",
			"verify",
		])) as CryptoKeyPair;
	},
	setTimer(delayMs, callback) {
		const timer = setTimeout(callback, delayMs);
		return () => clearTimeout(timer);
	},
};

export function dedupeDirectCandidates(candidates: readonly string[]): readonly string[] {
	return Array.from(new Set(candidates));
}

export async function pairDirect(input: DirectPairInput): Promise<DirectPairResult> {
	const deps: DirectPairDeps = { ...DEFAULT_DEPS, ...input.deps };
	const relay = input.relayEndpoint.replace(/\/+$/, "");
	const { candidates, port, nonce, caFp } = input.link;

	assertDirectCandidatesAdmitted(candidates);
	const uniqueCandidates = dedupeDirectCandidates(candidates);
	const session = await prepareFirstCandidate(uniqueCandidates, port, deps);
	if (!session) throw new DirectCandidatesExhaustedError();

	let clientKeyPem: string;
	let csrPem: string;
	try {
		const { publicKey, privateKey } = await deps.generateKeyPair();
		const publicJwk = (await webcrypto.subtle.exportKey("jwk", publicKey)) as Record<
			string,
			string
		>;
		const privateJwk = (await webcrypto.subtle.exportKey("jwk", privateKey)) as Record<
			string,
			string
		>;
		clientKeyPem = jwkToPkcs8Pem(privateJwk);
		csrPem = await buildCsr(input.deviceLabel, publicJwk, privateKey);
	} catch (err) {
		await closeSessionWithinDeadline(session, deps);
		throw err;
	}

	const request: HttpRequest = {
		method: "POST",
		path: `/app/network/pair?token=${encodeURIComponent(nonce)}`,
		headers: { "content-type": "application/json" },
		body: JSON.stringify({ csr: csrPem, device_label: input.deviceLabel }),
	};
	let pairJson: PairResponse;
	try {
		// Commit point: request invocation emits OPEN with the request bytes inline;
		// everything below is terminal and no later candidate can be tried.
		const pairResponse = await deps.request(session.mux, request);
		if (pairResponse.status !== 200) {
			throw new Error(`direct pair failed: HTTP ${pairResponse.status}`);
		}
		pairJson = parsePairResponse(pairResponse.body);
		assertDirectCaPin({
			caPem: pairJson.ca_chain[0],
			expectedFp16: caFp,
			peerLeaf: session.peerLeaf,
		});
	} catch (err) {
		await closeSessionWithinDeadline(session, deps);
		throw err;
	}

	// After commit there is no later candidate to protect; do not discard the
	// signed result merely because the socket never confirms teardown.
	await closeSessionWithinDeadline(session, deps);

	const { device_token } = await deps.enrollDevice(relay, {
		instance_id: pairJson.instance_id,
		home_attestation: pairJson.home_attestation,
	});
	const state: PairingState = {
		instance_id: pairJson.instance_id,
		home_label: pairJson.home_label,
		relay_endpoint: relay,
		ca_chain: pairJson.ca_chain,
		client_cert: pairJson.client_cert,
		client_key_pem: clientKeyPem,
		device_token,
		fingerprint: pairJson.fingerprint,
	};
	const decision = decidePairAction(state.instance_id, input.storedInstanceId);
	const saved = decision !== "already-connected";
	if (saved) await deps.savePairing(input.statePath, state);
	return { state, decision, saved };
}

async function prepareFirstCandidate(
	candidates: readonly string[],
	port: number,
	deps: DirectPairDeps,
): Promise<TunnelSession | null> {
	for (const host of candidates) {
		const controller = new AbortController();
		let opener: Promise<TunnelSession>;
		try {
			// Contract: rejection means no session was constructed or every partial
			// transport resource has completed teardown.
			opener = deps.openTunnel({ host, port, signal: controller.signal });
		} catch {
			continue;
		}
		const outcome = opener.then<SettledOpenOutcome, SettledOpenOutcome>(
			(session) => ({ kind: "opened", session }),
			() => ({ kind: "failed" }),
		);
		const deadline = createDeadline(CANDIDATE_DEADLINE_MS, deps);
		const first = await Promise.race([
			outcome,
			deadline.elapsed.then<OpenOutcome>(() => ({ kind: "deadline" })),
		]);
		deadline.cancel();

		if (first.kind === "opened") return first.session;
		if (first.kind === "failed") continue;

		controller.abort();
		const cleanupAcknowledged = outcome.then(async (late) => {
			if (late.kind === "failed") return true;
			return await closeAcknowledgement(late.session);
		});
		if (!(await acknowledgementWithinDeadline(cleanupAcknowledged, deps))) {
			throw new DirectCandidatesExhaustedError();
		}
	}
	return null;
}

type OpenOutcome =
	| { kind: "opened"; session: TunnelSession }
	| { kind: "failed" }
	| { kind: "deadline" };

type SettledOpenOutcome = Exclude<OpenOutcome, { kind: "deadline" }>;

async function closeSessionWithinDeadline(
	session: TunnelSession,
	deps: DirectPairDeps,
): Promise<boolean> {
	return await acknowledgementWithinDeadline(closeAcknowledgement(session), deps);
}

function closeAcknowledgement(session: TunnelSession): Promise<boolean> {
	return Promise.resolve()
		.then(() => session.close())
		.then(
			() => true,
			() => false,
		);
}

async function acknowledgementWithinDeadline(
	acknowledgement: Promise<boolean>,
	deps: DirectPairDeps,
): Promise<boolean> {
	const deadline = createDeadline(TEARDOWN_DEADLINE_MS, deps);
	const result = await Promise.race([
		acknowledgement.then((confirmed) => ({ kind: "acknowledged" as const, confirmed })),
		deadline.elapsed.then(() => ({ kind: "deadline" as const })),
	]);
	deadline.cancel();
	return result.kind === "acknowledged" && result.confirmed;
}

function createDeadline(
	delayMs: number,
	deps: DirectPairDeps,
): { elapsed: Promise<void>; cancel(): void } {
	let cancel = () => {};
	const elapsed = new Promise<void>((resolve) => {
		cancel = deps.setTimer(delayMs, resolve);
	});
	return { elapsed, cancel };
}

function parsePairResponse(body: Uint8Array): PairResponse {
	let parsed: unknown;
	try {
		parsed = JSON.parse(new TextDecoder().decode(body));
	} catch {
		throw new Error(MALFORMED_RESPONSE_MESSAGE);
	}
	if (!isRecord(parsed)) throw new Error(MALFORMED_RESPONSE_MESSAGE);

	const { ca_chain, client_cert, instance_id, home_label, home_attestation, fingerprint } = parsed;
	if (!isStringArray(ca_chain) || ca_chain.length === 0) {
		throw new Error(MALFORMED_RESPONSE_MESSAGE);
	}
	if (
		typeof client_cert !== "string" ||
		typeof instance_id !== "string" ||
		typeof home_label !== "string" ||
		typeof home_attestation !== "string" ||
		typeof fingerprint !== "string"
	) {
		throw new Error(MALFORMED_RESPONSE_MESSAGE);
	}
	return { client_cert, ca_chain, instance_id, home_label, home_attestation, fingerprint };
}

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null;
}

function isStringArray(value: unknown): value is string[] {
	return Array.isArray(value) && value.every((item) => typeof item === "string");
}

interface PairResponse {
	client_cert: string;
	ca_chain: string[];
	instance_id: string;
	home_label: string;
	home_attestation: string;
	fingerprint: string;
}
