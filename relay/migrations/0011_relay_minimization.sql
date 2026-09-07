-- SPDX-License-Identifier: AGPL-3.0-only
-- Copyright (c) 2026 sol pbc
-- Deploy row-free writers and drain old enrollment attempts before applying.
DROP TABLE devices;
ALTER TABLE instances DROP COLUMN home_label;
