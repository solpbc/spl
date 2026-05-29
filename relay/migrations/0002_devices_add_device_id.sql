-- SPDX-License-Identifier: AGPL-3.0-only
-- Copyright (c) 2026 sol pbc

-- Add device_id to devices: backs the device token's sub=device:<device_id>.
-- Persisting it lets /enroll/device re-mint a byte-identical device token on
-- a retried request (idempotency) instead of failing replay defense.
-- Nullable: pre-migration rows read back NULL and are not re-mintable.
ALTER TABLE devices ADD COLUMN device_id TEXT;
