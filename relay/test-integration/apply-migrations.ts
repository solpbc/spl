// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import { applyD1Migrations, env } from "cloudflare:test";
import { migrations } from "./migrations";

declare global {
	var __splRelayD1Migrations: Promise<void> | undefined;
}

export function applyRelayD1Migrations(): Promise<void> {
	globalThis.__splRelayD1Migrations ??= applyD1Migrations(env.DB, migrations).catch((err) => {
		const msg = err instanceof Error ? err.message : String(err);
		if (/UNIQUE constraint failed: d1_migrations\.name/i.test(msg)) return;
		throw err;
	});
	return globalThis.__splRelayD1Migrations;
}
