-- SPDX-License-Identifier: AGPL-3.0-only
-- Copyright (c) 2026 sol pbc
-- Rename the listen-token jti column: account_token_jti → service_token_jti (naming only; data-preserving).
ALTER TABLE instances RENAME COLUMN account_token_jti TO service_token_jti;
