// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import type { Env } from "../../src/env";
import relay, { InstanceDO } from "../../src/index";

export { InstanceDO };

const RACE_GATE_HEADER = "x-test-owner-purge-race-gate";
const RACE_GATE_ARRIVALS_HEADER = "x-test-owner-purge-race-gate-arrivals";
const PURGE_OPERATION_INSERT =
	"INSERT INTO purge_operations (operation_id_hash, request_digest, disposition, expires_at) VALUES (?, ?, 'retryable', ?) ON CONFLICT(operation_id_hash) DO NOTHING";
const PURGE_OPERATION_CONFIRM =
	"UPDATE purge_operations SET disposition = 'confirmed' WHERE operation_id_hash = ? AND disposition = 'complete' AND expires_at > ?";

type RaceGateMode = "insert" | "confirm-expire";

export default {
	async fetch(request: Request, env: Env): Promise<Response> {
		const mode = request.headers.get(RACE_GATE_HEADER);
		if (!isRaceGateMode(mode)) {
			return relay.fetch(request, env);
		}

		const gate = new RaceGate();
		const gatedEnv = { ...env, DB: gatedDatabase(env.DB, gate, mode) };
		const responses = await Promise.all([
			relay.fetch(request.clone(), gatedEnv),
			relay.fetch(request, gatedEnv),
		]);
		return responseWithGateArrivals(responses, gate.arrivals);
	},

	async scheduled(controller: ScheduledController, env: Env, ctx: ExecutionContext): Promise<void> {
		return relay.scheduled(controller, env, ctx);
	},
} satisfies ExportedHandler<Env>;

class RaceGate {
	#arrivals = 0;
	#release!: () => void;
	#released: Promise<void>;

	constructor() {
		this.#released = new Promise<void>((resolve) => {
			this.#release = resolve;
		});
	}

	get arrivals(): number {
		return this.#arrivals;
	}

	async arrive(): Promise<void> {
		this.#arrivals += 1;
		if (this.#arrivals === 2) this.#release();
		await this.#released;
	}
}

function gatedDatabase(database: D1Database, gate: RaceGate, mode: RaceGateMode): D1Database {
	return new Proxy(database, {
		get(target, property, receiver) {
			if (property !== "prepare") {
				const value = Reflect.get(target, property, receiver);
				return typeof value === "function" ? value.bind(target) : value;
			}
			return (query: string): D1PreparedStatement => {
				const statement = target.prepare(query);
				if (mode === "insert" && query === PURGE_OPERATION_INSERT) {
					return gatedStatement(statement, gate);
				}
				if (mode === "confirm-expire" && query === PURGE_OPERATION_CONFIRM) {
					return gatedStatement(statement, gate, async ([operationHash, now]) => {
						if (typeof operationHash !== "string" || typeof now !== "number") {
							throw new Error("confirm race gate received invalid update bindings");
						}
						await database
							.prepare("UPDATE purge_operations SET expires_at = ? WHERE operation_id_hash = ?")
							.bind(now, operationHash)
							.run();
					});
				}
				return statement;
			};
		},
	});
}

function gatedStatement(
	statement: D1PreparedStatement,
	gate: RaceGate,
	beforeRun?: (values: unknown[]) => Promise<void>,
	values: unknown[] = [],
): D1PreparedStatement {
	return new Proxy(statement, {
		get(target, property, receiver) {
			if (property === "bind") {
				return (...values: unknown[]): D1PreparedStatement =>
					gatedStatement(target.bind(...values), gate, beforeRun, values);
			}
			if (property === "run") {
				return async <T = Record<string, unknown>>(): Promise<D1Result<T>> => {
					await gate.arrive();
					if (beforeRun) await beforeRun(values);
					return target.run<T>();
				};
			}
			const value = Reflect.get(target, property, receiver);
			return typeof value === "function" ? value.bind(target) : value;
		},
	});
}

function isRaceGateMode(value: string | null): value is RaceGateMode {
	return value === "insert" || value === "confirm-expire";
}

async function responseWithGateArrivals(
	responses: Response[],
	arrivals: number,
): Promise<Response> {
	const headers = new Headers({ "content-type": "application/json; charset=utf-8" });
	headers.set(RACE_GATE_ARRIVALS_HEADER, String(arrivals));
	return new Response(
		JSON.stringify({ responses: await Promise.all(responses.map(raceResponse)) }),
		{
			status: 200,
			headers,
		},
	);
}

async function raceResponse(response: Response): Promise<{ status: number; body: unknown }> {
	return { status: response.status, body: await response.json() };
}
