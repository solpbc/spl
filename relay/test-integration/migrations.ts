// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

// Shared D1 migration fixture for the integration test suite. Mirrors
// migrations/0001_init.sql — kept in sync by hand, which is fine because
// the schema is small and the tests exercise the live behavior.

export const migrations = [
	{
		name: "0001_init",
		queries: [
			`CREATE TABLE IF NOT EXISTS instances (
				instance_id       TEXT PRIMARY KEY,
				ca_fp             TEXT NOT NULL,
				ca_pubkey_pem     TEXT NOT NULL,
				home_label        TEXT,
				created_at        INTEGER NOT NULL,
				account_token_jti TEXT NOT NULL,
				rotated_at        INTEGER,
				revoked_at        INTEGER
			)`,
			`CREATE TABLE IF NOT EXISTS devices (
				device_jti       TEXT PRIMARY KEY,
				instance_id      TEXT NOT NULL,
				device_fp        TEXT NOT NULL,
				device_label     TEXT,
				created_at       INTEGER NOT NULL,
				revoked_at       INTEGER,
				attestation_jti  TEXT NOT NULL UNIQUE,
				FOREIGN KEY (instance_id) REFERENCES instances(instance_id)
			)`,
			"CREATE INDEX IF NOT EXISTS idx_devices_instance ON devices(instance_id)",
			"CREATE INDEX IF NOT EXISTS idx_devices_fp ON devices(instance_id, device_fp)",
		],
	},
];
