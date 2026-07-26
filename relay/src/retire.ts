// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import { INSTANCE_ID_RE, hasValidBearer } from "./entitlement";
import type { Env } from "./env";
import { json } from "./http";
import type { RetireInstanceResult } from "./instance-do";
import { type RetirementComponent, log } from "./logging";

const ROUTE = "/admin/instances";

type RetirementState = "retired" | "already_retired" | "absent";

interface RetirementChecks {
	entry_denial_verified: boolean;
	sockets_closed: boolean;
	devices_revoked: boolean;
	entitlement_cleared: boolean;
	pending_grants_cleared: boolean;
	tombstone_verified: boolean;
}

interface InstanceStateRow {
	revoked_at: number | null;
}

interface PairingOwnerRow {
	do_id: string;
}

export async function handleRetireInstance(
	request: Request,
	env: Env,
	instanceId: string,
): Promise<Response> {
	if (!env.GRANT_SECRET) return json({ error: "relay not provisioned" }, 503);

	if (!hasValidBearer(request, env.GRANT_SECRET)) {
		log({ event: "unauthorized", route: ROUTE, reason: "bad_bearer" });
		return json({ error: "unauthorized" }, 401);
	}
	if (!INSTANCE_ID_RE.test(instanceId)) return json({ error: "bad instance_id" }, 400);

	const checks = emptyChecks();
	let failedComponent: RetirementComponent | undefined;
	const fail = (component: RetirementComponent): void => {
		failedComponent ??= component;
	};

	let initial: InstanceStateRow | null;
	try {
		initial = await env.DB.prepare("SELECT revoked_at FROM instances WHERE instance_id = ?")
			.bind(instanceId)
			.first<InstanceStateRow>();
	} catch {
		return failureResponse(instanceId, checks, "retired_state");
	}

	if (!initial) return retireAbsent(env, instanceId);

	const now = Math.floor(Date.now() / 1000);
	let state: Exclude<RetirementState, "absent"> = "already_retired";
	let retiredAt = initial.revoked_at ?? now;
	let authorityEstablished = initial.revoked_at !== null;

	if (initial.revoked_at === null) {
		try {
			const result = await env.DB.prepare(
				"UPDATE instances SET revoked_at = ? WHERE instance_id = ? AND revoked_at IS NULL",
			)
				.bind(now, instanceId)
				.run();
			authorityEstablished = result.meta.changes > 0;
			state = authorityEstablished ? "retired" : "already_retired";
		} catch {
			return failureResponse(instanceId, checks, "retired_state");
		}
	}

	try {
		const committed = await env.DB.prepare("SELECT revoked_at FROM instances WHERE instance_id = ?")
			.bind(instanceId)
			.first<InstanceStateRow>();
		if (committed?.revoked_at !== null && committed?.revoked_at !== undefined) {
			retiredAt = committed.revoked_at;
			authorityEstablished = true;
		} else {
			fail("retired_state");
		}
	} catch {
		fail("retired_state");
	}

	// A lost conditional race without a readable committed tombstone has no
	// timestamp to propagate. Do not create a derived DO marker until D1 is
	// confirmed authoritative.
	if (!authorityEstablished) {
		return failureResponse(instanceId, checks, failedComponent ?? "retired_state");
	}

	let owners: PairingOwnerRow[] = [];
	let registryRead = false;
	try {
		const result = await env.DB.prepare("SELECT do_id FROM pairing_owners WHERE instance_id = ?")
			.bind(instanceId)
			.all<PairingOwnerRow>();
		owners = result.results;
		registryRead = true;
	} catch {
		fail("rk_do_cleanup");
	}

	let socketCount = 0;
	let instanceMarkerVerified = false;
	let instanceCleanupComplete = false;
	try {
		const stub = env.INSTANCE.get(env.INSTANCE.idFromName(instanceId));
		const result = await stub.retireInstance(instanceId, retiredAt);
		socketCount += result.socketCount;
		instanceMarkerVerified = result.markerVerified;
		instanceCleanupComplete = isDoCleanupComplete(result);
		if (!instanceCleanupComplete) fail("instance_do_cleanup");
	} catch {
		fail("instance_do_cleanup");
	}

	let rkMarkersVerified = registryRead;
	let rkCleanupComplete = registryRead;
	let registryDeletesComplete = registryRead;
	for (const owner of owners) {
		let result: RetireInstanceResult | null = null;
		try {
			const stub = env.INSTANCE.get(env.INSTANCE.idFromString(owner.do_id));
			result = await stub.retireInstance(instanceId, retiredAt);
			socketCount += result.socketCount;
		} catch {
			rkMarkersVerified = false;
			rkCleanupComplete = false;
			registryDeletesComplete = false;
			fail("rk_do_cleanup");
			continue;
		}
		if (!result) {
			rkMarkersVerified = false;
			rkCleanupComplete = false;
			registryDeletesComplete = false;
			fail("rk_do_cleanup");
			continue;
		}

		rkMarkersVerified &&= result.markerVerified;
		const cleanupComplete = isDoCleanupComplete(result);
		rkCleanupComplete &&= cleanupComplete;
		if (!cleanupComplete) {
			registryDeletesComplete = false;
			fail("rk_do_cleanup");
			continue;
		}

		try {
			await env.DB.prepare("DELETE FROM pairing_owners WHERE instance_id = ? AND do_id = ?")
				.bind(instanceId, owner.do_id)
				.run();
		} catch {
			registryDeletesComplete = false;
			fail("rk_registry_clear");
		}
	}

	let deviceMutationComplete = false;
	try {
		await env.DB.prepare(
			"UPDATE devices SET revoked_at = COALESCE(revoked_at, ?) WHERE instance_id = ?",
		)
			.bind(retiredAt, instanceId)
			.run();
		deviceMutationComplete = true;
	} catch {
		fail("device_revocation");
	}

	let entitlementMutationComplete = false;
	try {
		await env.DB.prepare("UPDATE instances SET entitled_until = NULL WHERE instance_id = ?")
			.bind(instanceId)
			.run();
		entitlementMutationComplete = true;
	} catch {
		fail("entitlement_clear");
	}

	let pendingMutationComplete = false;
	try {
		await env.DB.prepare("DELETE FROM pending_grants WHERE instance_id = ?").bind(instanceId).run();
		pendingMutationComplete = true;
	} catch {
		fail("pending_grant_clear");
	}

	let authorityVerified = false;
	let entitlementVerified = false;
	try {
		const row = await env.DB.prepare(
			"SELECT revoked_at, entitled_until FROM instances WHERE instance_id = ?",
		)
			.bind(instanceId)
			.first<{ revoked_at: number | null; entitled_until: number | null }>();
		authorityVerified = row?.revoked_at === retiredAt;
		entitlementVerified = row !== null && row.entitled_until === null;
		if (!authorityVerified || !entitlementVerified) fail("verification");
	} catch {
		fail("verification");
	}

	let devicesVerified = false;
	try {
		const row = await env.DB.prepare(
			"SELECT device_jti FROM devices WHERE instance_id = ? AND revoked_at IS NULL LIMIT 1",
		)
			.bind(instanceId)
			.first<{ device_jti: string }>();
		devicesVerified = row === null;
		if (!devicesVerified) fail("verification");
	} catch {
		fail("verification");
	}

	let pendingVerified = false;
	try {
		const row = await env.DB.prepare("SELECT instance_id FROM pending_grants WHERE instance_id = ?")
			.bind(instanceId)
			.first<{ instance_id: string }>();
		pendingVerified = row === null;
		if (!pendingVerified) fail("verification");
	} catch {
		fail("verification");
	}

	let registryVerified = false;
	try {
		const row = await env.DB.prepare(
			"SELECT do_id FROM pairing_owners WHERE instance_id = ? LIMIT 1",
		)
			.bind(instanceId)
			.first<PairingOwnerRow>();
		registryVerified = row === null;
		if (!registryVerified) fail("verification");
	} catch {
		fail("verification");
	}

	checks.entry_denial_verified = authorityVerified && instanceMarkerVerified && rkMarkersVerified;
	checks.sockets_closed = instanceCleanupComplete && rkCleanupComplete;
	checks.devices_revoked = deviceMutationComplete && devicesVerified;
	checks.entitlement_cleared = entitlementMutationComplete && entitlementVerified;
	checks.pending_grants_cleared = pendingMutationComplete && pendingVerified;
	checks.tombstone_verified =
		authorityVerified && registryRead && registryDeletesComplete && registryVerified;

	if (failedComponent || !allChecksVerified(checks)) {
		return failureResponse(instanceId, checks, failedComponent ?? "verification");
	}

	log({ event: "instance_retire", instance_id: instanceId, count: socketCount });
	return json({ state, ...checks });
}

async function retireAbsent(env: Env, instanceId: string): Promise<Response> {
	const checks = emptyChecks();
	let failedComponent: RetirementComponent | undefined;
	let pendingMutationComplete = false;

	try {
		await env.DB.prepare("DELETE FROM pending_grants WHERE instance_id = ?").bind(instanceId).run();
		pendingMutationComplete = true;
	} catch {
		failedComponent = "pending_grant_clear";
	}

	let absentVerified = false;
	try {
		const row = await env.DB.prepare(
			"SELECT instance_id, revoked_at FROM instances WHERE instance_id = ?",
		)
			.bind(instanceId)
			.first<{ instance_id: string; revoked_at: number | null }>();
		// This second, post-mutation read independently proves both that no live
		// instance row exists and that no tombstone was created.
		absentVerified = row === null;
		if (!absentVerified) failedComponent ??= "verification";
	} catch {
		failedComponent ??= "verification";
	}

	let devicesAbsent = false;
	try {
		const row = await env.DB.prepare("SELECT device_jti FROM devices WHERE instance_id = ? LIMIT 1")
			.bind(instanceId)
			.first<{ device_jti: string }>();
		devicesAbsent = row === null;
		if (!devicesAbsent) failedComponent ??= "verification";
	} catch {
		failedComponent ??= "verification";
	}

	let pendingVerified = false;
	try {
		const row = await env.DB.prepare("SELECT instance_id FROM pending_grants WHERE instance_id = ?")
			.bind(instanceId)
			.first<{ instance_id: string }>();
		pendingVerified = row === null;
		if (!pendingVerified) failedComponent ??= "verification";
	} catch {
		failedComponent ??= "verification";
	}

	checks.entry_denial_verified = absentVerified;
	checks.sockets_closed = absentVerified;
	checks.devices_revoked = absentVerified && devicesAbsent;
	checks.entitlement_cleared = absentVerified;
	checks.pending_grants_cleared = pendingMutationComplete && pendingVerified;
	checks.tombstone_verified = absentVerified;

	if (failedComponent || !allChecksVerified(checks)) {
		return failureResponse(instanceId, checks, failedComponent ?? "verification");
	}

	log({ event: "instance_retire", instance_id: instanceId, count: 0 });
	return json({ state: "absent", ...checks });
}

function isDoCleanupComplete(result: RetireInstanceResult): boolean {
	return (
		result.markerVerified && result.socketsClosed && result.pendingCleared && result.alarmCleared
	);
}

function emptyChecks(): RetirementChecks {
	return {
		entry_denial_verified: false,
		sockets_closed: false,
		devices_revoked: false,
		entitlement_cleared: false,
		pending_grants_cleared: false,
		tombstone_verified: false,
	};
}

function allChecksVerified(checks: RetirementChecks): boolean {
	return Object.values(checks).every(Boolean);
}

function failureResponse(
	instanceId: string,
	checks: RetirementChecks,
	component: RetirementComponent,
): Response {
	log({ event: "instance_retire_failed", instance_id: instanceId, reason: component });
	return json({ ...checks, failed_component: component }, 503);
}
