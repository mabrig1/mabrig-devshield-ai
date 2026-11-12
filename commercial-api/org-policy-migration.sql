-- Apply after the existing commercial-api/schema.sql on an operator-selected D1 database.
-- Tenant is resolved from the authenticated key; never from the request JSON or query.
CREATE TABLE IF NOT EXISTS org_policies (
  tenant_id TEXT PRIMARY KEY NOT NULL REFERENCES tenants(id),
  revision INTEGER NOT NULL DEFAULT 1 CHECK (revision >= 1),
  policy_json TEXT NOT NULL,
  policy_sha256 TEXT NOT NULL CHECK (length(policy_sha256) = 64),
  updated_by_key_id TEXT REFERENCES api_keys(id),
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS org_policy_audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  revision INTEGER NOT NULL,
  action TEXT NOT NULL CHECK (action IN ('created', 'updated')),
  actor_key_id TEXT REFERENCES api_keys(id),
  policy_sha256 TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_org_policy_audit ON org_policy_audit(tenant_id, id DESC);
CREATE TRIGGER IF NOT EXISTS trg_org_policy_created AFTER INSERT ON org_policies
BEGIN
  INSERT INTO org_policy_audit (tenant_id, revision, action, actor_key_id, policy_sha256)
  VALUES (NEW.tenant_id, NEW.revision, 'created', NEW.updated_by_key_id, NEW.policy_sha256);
END;
CREATE TRIGGER IF NOT EXISTS trg_org_policy_updated AFTER UPDATE ON org_policies
BEGIN
  INSERT INTO org_policy_audit (tenant_id, revision, action, actor_key_id, policy_sha256)
  VALUES (NEW.tenant_id, NEW.revision, 'updated', NEW.updated_by_key_id, NEW.policy_sha256);
END;
