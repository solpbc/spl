-- SPDX-License-Identifier: AGPL-3.0-only
-- Copyright (c) 2026 sol pbc

-- Grant-before-enroll holding table for the opt-in session entitlement gate.
-- The account worker can POST /admin/entitlement before the home has enrolled;
-- the comp/scout path never re-pushes that grant, so treating the 0-row
-- instances UPDATE as a hard miss would silently drop paid access. We keep
-- that metadata here and claim it when the home enrolls.
--
-- No sweeper/TTL is needed: an unclaimed orphan row is harmless and contains
-- only the instance id plus grant expiry. updated_at is informative only.
-- Lookups are by primary key, so no additional index is needed.
CREATE TABLE IF NOT EXISTS pending_grants (
	instance_id    TEXT PRIMARY KEY,
	entitled_until INTEGER NOT NULL,
	updated_at     INTEGER NOT NULL
);
