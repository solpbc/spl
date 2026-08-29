-- SPDX-License-Identifier: AGPL-3.0-only
-- Copyright (c) 2026 sol pbc

-- Replace the completion timestamp with a bounded confirmed state. The replay
-- binding still stores only opaque-operation and target-snapshot fingerprints.
CREATE TABLE purge_operations_0009 (
	operation_id_hash TEXT PRIMARY KEY,
	snapshot_digest  TEXT NOT NULL,
	state            TEXT NOT NULL CHECK (state IN ('retryable', 'complete', 'confirmed')),
	expires_at       INTEGER NOT NULL
);

INSERT INTO purge_operations_0009 (operation_id_hash, snapshot_digest, state, expires_at)
SELECT operation_id_hash, snapshot_digest, state, expires_at
FROM purge_operations;

DROP TABLE purge_operations;

ALTER TABLE purge_operations_0009 RENAME TO purge_operations;
