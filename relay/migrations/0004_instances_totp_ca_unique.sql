-- SPDX-License-Identifier: AGPL-3.0-only
-- Copyright (c) 2026 sol pbc

-- Optional base32 secret stored at rest for off-LAN pairing (L5);
-- inert — nothing validates a TOTP code this lode.
ALTER TABLE instances ADD COLUMN totp_secret TEXT;

-- A CA fingerprint backs at most one instance; cross-instance collisions
-- surface at INSERT.
CREATE UNIQUE INDEX IF NOT EXISTS idx_instances_ca_fp ON instances(ca_fp);
