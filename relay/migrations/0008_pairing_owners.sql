-- SPDX-License-Identifier: AGPL-3.0-only
-- Copyright (c) 2026 sol pbc

-- Retirement registry for RK-addressed Durable Objects. do_id is the opaque,
-- one-way idFromName(RK) result, not RK itself; public routes never accept it
-- as an RK credential. Each row lives only as long as sockets owned by that
-- authenticated instance remain in the Durable Object.
CREATE TABLE IF NOT EXISTS pairing_owners (
	instance_id   TEXT NOT NULL,
	do_id         TEXT NOT NULL,
	registered_at INTEGER NOT NULL,
	PRIMARY KEY (instance_id, do_id)
);
