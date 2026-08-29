-- SPDX-License-Identifier: AGPL-3.0-only
-- Copyright (c) 2026 sol pbc

-- Sole replay binding for portal owner-purge v1. It stores only hashes of the
-- portal operation id and canonical relay-instance snapshot; no portal-owner
-- association, raw operation id, target id, receipt, or payload bytes.
-- expires_at is copied from the initial purge envelope and is immutable.
-- completed_at records the first successful completion so completed bindings
-- can be hard-deleted lazily seven days later when no confirmation arrives.
CREATE TABLE IF NOT EXISTS purge_operations (
	operation_id_hash TEXT PRIMARY KEY,
	snapshot_digest  TEXT NOT NULL,
	state            TEXT NOT NULL CHECK (state IN ('retryable', 'complete')),
	expires_at       INTEGER NOT NULL,
	completed_at     INTEGER,
	CHECK (
		(state = 'retryable' AND completed_at IS NULL) OR
		(state = 'complete' AND completed_at IS NOT NULL)
	)
);
