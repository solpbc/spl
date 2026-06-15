-- SPDX-License-Identifier: AGPL-3.0-only
-- Copyright (c) 2026 sol pbc

-- Paid-tier expiry for the opt-in session entitlement gate. Overwritten on
-- each grant; NULL means no active entitlement. Lookups are by instance PK, so
-- no index is needed.
ALTER TABLE instances ADD COLUMN entitled_until INTEGER;
