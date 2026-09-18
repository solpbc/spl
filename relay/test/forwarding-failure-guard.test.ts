// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import { readFileSync } from "node:fs";
import { join } from "node:path";
import ts from "typescript";
import { describe, expect, it } from "vitest";

const sourcePath = join(process.cwd(), "src", "instance-do.ts");
const sourceText = readFileSync(sourcePath, "utf8");
const sourceFile = ts.createSourceFile(
	sourcePath,
	sourceText,
	ts.ScriptTarget.Latest,
	true,
	ts.ScriptKind.TS,
);

function forwardingSendCatch(): ts.CatchClause | undefined {
	let result: ts.CatchClause | undefined;

	function visit(node: ts.Node): void {
		if (
			ts.isCallExpression(node) &&
			ts.isPropertyAccessExpression(node.expression) &&
			ts.isElementAccessExpression(node.expression.expression) &&
			node.expression.expression.expression.getText(sourceFile) === "peers" &&
			node.expression.expression.argumentExpression.getText(sourceFile) === "0" &&
			node.expression.name.text === "send" &&
			node.arguments.length === 1 &&
			node.arguments[0].getText(sourceFile) === "message"
		) {
			let current: ts.Node | undefined = node;
			while (current && !ts.isTryStatement(current)) current = current.parent;
			result = current?.catchClause;
			return;
		}
		ts.forEachChild(node, visit);
	}

	visit(sourceFile);
	return result;
}

describe("forwarding failure guard", () => {
	it("logs a fixed classification and closes both tunnel peers after send throws", () => {
		const clause = forwardingSendCatch();
		expect(clause, "forwarding peers[0].send(message) must remain guarded").toBeDefined();

		const body = clause?.block.getText(sourceFile) ?? "";
		expect(body).toMatch(
			/log\(\{\s*event:\s*"internal_error",\s*reason:\s*"forward_send_failed"\s*\}\)/,
		);
		expect(body).toMatch(
			/this\.closeTunnel\(tunnelId,\s*CLOSE_CODE_INTERNAL_ERROR,\s*"forward_send_failed"\)/,
		);
	});
});
