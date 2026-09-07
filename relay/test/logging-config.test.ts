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
	it("disables retained logs, traces, and URL-bearing invocation logs", () => {
		expect(tomlSection("observability")).toMatch(/\benabled\s*=\s*false\b/);
		expect(tomlSection("observability.logs")).toMatch(/\binvocation_logs\s*=\s*false\b/);
		expect(tomlSection("env.production.observability")).toMatch(/\benabled\s*=\s*false\b/);
		expect(tomlSection("env.production.observability.logs")).toMatch(
			/\binvocation_logs\s*=\s*false\b/,
		);
		for (const prefix of ["", "env.production."]) {
			for (const kind of ["logs", "traces"]) {
				const section = tomlSection(`${prefix}observability.${kind}`);
				expect(section).toMatch(/\benabled\s*=\s*false\b/);
				expect(section).toMatch(/\bpersist\s*=\s*false\b/);
				expect(section).toMatch(/\bdestinations\s*=\s*\[\s*\]/);
			}
		}
	});
});
