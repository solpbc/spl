-- SPDX-License-Identifier: AGPL-3.0-only
-- Copyright (c) 2026 sol pbc
-- iat of the newest accepted /enroll/home possession proof. Non-null means the
-- instance has proven possession of its CA key, after which /enroll/home
-- refuses unsigned calls and session routes accept only the current
-- service_token_jti. See ../proto/tokens.md § proof of possession.
ALTER TABLE instances ADD COLUMN proof_iat INTEGER;
