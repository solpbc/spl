-- SPDX-License-Identifier: AGPL-3.0-only
-- Copyright (c) 2026 sol pbc

-- spl-relay D1 schema — rendezvous metadata only. Never payload bytes.
-- See ../proto/tokens.md §storage for the shape this mirrors.

CREATE TABLE IF NOT EXISTS instances (
  instance_id       TEXT    PRIMARY KEY,
  ca_fp             TEXT    NOT NULL,
  ca_pubkey_pem     TEXT    NOT NULL,       -- ECDSA-P256 SPKI PEM; used to verify home attestations at /enroll/device
  home_label        TEXT,
  created_at        INTEGER NOT NULL,       -- unix seconds
  account_token_jti TEXT    NOT NULL,       -- current; rotated on re-enroll
  rotated_at        INTEGER,                -- unix seconds of last rotation
  revoked_at        INTEGER                 -- unix seconds if instance was revoked
);

CREATE TABLE IF NOT EXISTS devices (
  device_jti       TEXT    PRIMARY KEY,     -- jti of the issued device token
  instance_id      TEXT    NOT NULL,
  device_fp        TEXT    NOT NULL,        -- sha256:<hex> of the mobile client cert
  device_label     TEXT,
  created_at       INTEGER NOT NULL,
  revoked_at       INTEGER,
  attestation_jti  TEXT    NOT NULL UNIQUE, -- single-use: replay defense against re-use of the same attestation blob
  FOREIGN KEY (instance_id) REFERENCES instances(instance_id)
);

CREATE INDEX IF NOT EXISTS idx_devices_instance ON devices(instance_id);
CREATE INDEX IF NOT EXISTS idx_devices_fp ON devices(instance_id, device_fp);
