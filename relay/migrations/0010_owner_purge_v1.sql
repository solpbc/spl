-- SPDX-License-Identifier: AGPL-3.0-only
-- Copyright (c) 2026 sol pbc

-- Canonical owner-purge v1 bindings retain only an opaque operation fingerprint,
-- a canonical request digest, disposition, and immutable request expiry. Legacy
-- snapshot digests cannot be converted into canonical request digests, so no
-- legacy row is carried into this new wire contract.
CREATE TABLE purge_operations_0010 (
	operation_id_hash TEXT PRIMARY KEY,
	request_digest    TEXT NOT NULL,
	disposition       TEXT NOT NULL CHECK (disposition IN ('retryable', 'complete', 'confirmed')),
	expires_at        INTEGER NOT NULL
);

INSERT INTO purge_operations_0010 (operation_id_hash, request_digest, disposition, expires_at)
SELECT operation_id_hash, snapshot_digest, state, expires_at
FROM purge_operations
WHERE 0;

DROP TABLE purge_operations;

ALTER TABLE purge_operations_0010 RENAME TO purge_operations;
