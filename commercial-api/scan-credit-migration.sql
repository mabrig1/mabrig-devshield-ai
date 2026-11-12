-- Additive, opt-in scan-credit wallet and per-key request-metering extension.
-- Apply only after commercial-api/schema.sql and with backup/migration review.
-- No payment capture or customer self-service is included.
CREATE TABLE IF NOT EXISTS scan_credit_wallets (
  tenant_id TEXT PRIMARY KEY REFERENCES tenants(id),
  remaining INTEGER NOT NULL DEFAULT 0 CHECK (remaining >= 0),
  grants_total INTEGER NOT NULL DEFAULT 0 CHECK (grants_total >= 0),
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS scan_credit_grants (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  amount INTEGER NOT NULL CHECK (amount BETWEEN 1 AND 1000000),
  reference TEXT NOT NULL CHECK (length(reference) BETWEEN 3 AND 128),
  issued_by TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_scan_credit_grants_tenant ON scan_credit_grants(tenant_id, created_at);
CREATE TABLE IF NOT EXISTS scan_credit_debits (
  scan_id TEXT PRIMARY KEY REFERENCES scans(id),
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  remaining_after INTEGER NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_scan_credit_debits_tenant ON scan_credit_debits(tenant_id, created_at);
CREATE TABLE IF NOT EXISTS api_key_request_buckets (
  key_id TEXT NOT NULL REFERENCES api_keys(id),
  minute_bucket TEXT NOT NULL,
  attempts INTEGER NOT NULL CHECK (attempts BETWEEN 1 AND 1000000),
  PRIMARY KEY (key_id, minute_bucket)
);
CREATE TRIGGER IF NOT EXISTS scan_grant_add_credit AFTER INSERT ON scan_credit_grants
BEGIN
  INSERT INTO scan_credit_wallets (tenant_id, remaining, grants_total)
    VALUES (NEW.tenant_id, NEW.amount, NEW.amount)
    ON CONFLICT (tenant_id) DO UPDATE
      SET remaining = remaining + NEW.amount,
          grants_total = grants_total + NEW.amount, updated_at = CURRENT_TIMESTAMP;
END;
-- AFTER INSERT fires only when a new scan is actually stored, not on duplicate
-- INSERT .. ON CONFLICT DO NOTHING. Aborting here rolls back the scan insert too.
CREATE TRIGGER IF NOT EXISTS scan_new_record_debit AFTER INSERT ON scans
WHEN EXISTS (SELECT 1 FROM scan_credit_wallets WHERE tenant_id = NEW.tenant_id)
BEGIN
  SELECT CASE WHEN (
    SELECT remaining FROM scan_credit_wallets WHERE tenant_id = NEW.tenant_id
  ) < 1 THEN RAISE(ABORT, 'scan_credit_exhausted') END;
  UPDATE scan_credit_wallets SET remaining = remaining - 1,
    updated_at = CURRENT_TIMESTAMP WHERE tenant_id = NEW.tenant_id;
  INSERT INTO scan_credit_debits (scan_id, tenant_id, remaining_after)
    SELECT NEW.id, NEW.tenant_id, remaining
    FROM scan_credit_wallets WHERE tenant_id = NEW.tenant_id;
END;
