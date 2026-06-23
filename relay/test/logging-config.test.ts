// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const wranglerToml = readFileSync(join(process.cwd(), "wrangler.toml"), "utf8");

function tomlSection(name: string): string {
	const marker = `[${name}]`;
	const start = wranglerToml.indexOf(marker);
	expect(start).toBeGreaterThanOrEqual(0);
	const bodyStart = start + marker.length;
	const rest = wranglerToml.slice(bodyStart);
	const nextSection = rest.search(/\n\[/);
	return nextSection === -1 ? rest : rest.slice(0, nextSection);
}

describe("Worker logging config", () => {
	it("keeps Workers Logs custom logs on but disables URL-bearing invocation logs", () => {
		expect(tomlSection("observability")).toMatch(/\benabled\s*=\s*true\b/);
		expect(tomlSection("observability.logs")).toMatch(/\binvocation_logs\s*=\s*false\b/);
		expect(tomlSection("env.production.observability")).toMatch(/\benabled\s*=\s*true\b/);
		expect(tomlSection("env.production.observability.logs")).toMatch(
			/\binvocation_logs\s*=\s*false\b/,
		);
	});
});
