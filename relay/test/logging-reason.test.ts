// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import { describe, expect, it } from "vitest";
import type { CloseReason, LogFields } from "../src/logging";

const authored: LogFields["reason"] = "listen_replaced";
const closeAuthored: LogFields["reason"] = "ws_error";
const attestation: LogFields["reason"] = "attestation_expired";
const close: CloseReason = "peer_closed";
// @ts-expect-error General authored reasons are not close classifications.
const badClose: CloseReason = "listen_replaced";
// @ts-expect-error Novel reasons are rejected at the logging boundary.
const novel: LogFields["reason"] = "totally-made-up-reason";

describe("logging reason types", () => {
	it("keeps runtime test discovery satisfied", () => {
		expect([authored, closeAuthored, attestation, close, badClose, novel]).toHaveLength(6);
	});
});
