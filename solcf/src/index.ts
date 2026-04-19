// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

// Entry point for the solcf Worker.
//
// This file is a scaffold placeholder. The real Worker wires up
// /session/listen, /session/dial, /tunnel/<id> routes and hands the
// upgraded WebSockets to the InstanceDO for pairing.
//
// Non-negotiable invariant: this Worker must NEVER read, parse, store,
// or forward the payload of a relayed frame. See ../AGENTS.md §3.

export interface Env {
	INSTANCE: DurableObjectNamespace;
	ENVIRONMENT: string;
}

export default {
	async fetch(_request: Request, _env: Env): Promise<Response> {
		return new Response("solcf — scaffold", {
			status: 200,
			headers: { "content-type": "text/plain; charset=utf-8" },
		});
	},
} satisfies ExportedHandler<Env>;

// InstanceDO — one Durable Object per home solstone instance.
// Will hold the listen WS and pair incoming dial WSes into blind byte relays.
// Scaffold stub only — the real implementation lands with the MVP build.
export class InstanceDO implements DurableObject {
	constructor(
		_state: DurableObjectState,
		_env: Env,
	) {}

	async fetch(_request: Request): Promise<Response> {
		return new Response("InstanceDO — scaffold", { status: 200 });
	}
}
