-- DevShield Commercial API v0.1 — tenant isolation is enforced by every application query.
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS tenants (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended')),
  daily_scan_limit INTEGER NOT NULL DEFAULT 50 CHECK (daily_scan_limit >= 0),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS api_keys (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  key_hash TEXT NOT NULL UNIQUE CHECK (length(key_hash) = 64),
  label TEXT NOT NULL,
  scopes TEXT NOT NULL DEFAULT 'scans:read scans:write',
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked')),
  expires_at TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_api_keys_tenant ON api_keys(tenant_id);

CREATE TABLE IF NOT EXISTS scans (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  idempotency_key TEXT NOT NULL,
  repository TEXT NOT NULL,
  head_sha TEXT,
  risk_level TEXT NOT NULL,
  risk_score REAL NOT NULL,
  findings_count INTEGER NOT NULL,
  scan_day TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE (tenant_id, idempotency_key)
);
CREATE INDEX IF NOT EXISTS idx_scans_usage ON scans(tenant_id, scan_day);
CREATE INDEX IF NOT EXISTS idx_scans_timeline ON scans(tenant_id, created_at DESC, id DESC);
