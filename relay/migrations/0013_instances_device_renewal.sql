-- SPDX-License-Identifier: AGPL-3.0-only
-- Copyright (c) 2026 sol pbc
-- When the instance's home first declared, on POST /token/access, that it
-- renews its own devices' relay access (header SPL-Device-Renewal: home).
-- Non-null means POST /token/refresh renews nothing for the instance, so a
-- device the home has removed loses relay reach once its access expires. A
-- later /token/access without the header clears it. See
-- ../proto/tokens.md § renewal comes from the home.
ALTER TABLE instances ADD COLUMN device_renewal_at INTEGER;
