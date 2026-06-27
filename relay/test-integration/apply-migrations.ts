// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import { applyD1Migrations, env } from "cloudflare:test";
import { migrations } from "./migrations";

declare global {
	var __splRelayD1Migrations: Promise<void> | undefined;
}

export function applyRelayD1Migrations(): Promise<void> {
	globalThis.__splRelayD1Migrations ??= applyD1Migrations(env.DB, migrations);
	return globalThis.__splRelayD1Migrations;
}
