// Organization policy contract: a tenant-scoped control plane foundation.
// No policy is enforced in customer repositories until a trusted client opts in.
const REPO = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;
const SETTINGS = {
  policy: new Set(['balanced', 'strict', 'secrets-only']),
  failOn: new Set(['none', 'critical', 'high', 'medium', 'low']),
  dependencySeverity: new Set(['critical', 'high', 'medium', 'low']),
  legalComplianceMode: new Set(['off', 'advisory', 'enforce'])
};
function plain(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype;
}
export function normalizeOrgPolicy(value) {
  if (!plain(value) || Object.keys(value).some(k => !['schemaVersion', 'name', 'repositories', 'controls'].includes(k))) {
    throw new Error('Unexpected organization policy fields');
  }
  if (value.schemaVersion !== 1 || typeof value.name !== 'string' || !/^[A-Za-z0-9_.-]{1,64}$/.test(value.name)) {
    throw new Error('Invalid policy schemaVersion or name');
  }
  if (!Array.isArray(value.repositories) || value.repositories.length < 1 || value.repositories.length > 100) {
    throw new Error('Specify 1–100 explicit repositories');
  }
  const repositories = [...new Set(value.repositories)];
  if (repositories.length !== value.repositories.length || repositories.some(v => typeof v !== 'string' || !REPO.test(v) || v.includes('..'))) {
    throw new Error('Invalid or duplicate repository');
  }
  if (!plain(value.controls) || !Object.keys(value.controls).length || Object.keys(value.controls).length > 10) {
    throw new Error('Invalid policy controls');
  }
  for (const [key, setting] of Object.entries(value.controls)) {
    if (Object.hasOwn(SETTINGS, key)) {
      if (typeof setting !== 'string' || !SETTINGS[key].has(setting)) throw new Error('Invalid control: ' + key);
    } else if (key === 'riskExceptionMaxDays') {
      if (!Number.isSafeInteger(setting) || setting < 1 || setting > 90) throw new Error('Invalid riskExceptionMaxDays');
    } else if (key === 'riskExceptionAllowCritical') {
      if (typeof setting !== 'boolean') throw new Error('Invalid riskExceptionAllowCritical');
    } else throw new Error('Unknown control: ' + key);
  }
  return { schemaVersion: 1, name: value.name, repositories: repositories.sort(), controls: { ...value.controls } };
}

export async function readOrgPolicy(db, tenantId) {
  return db.prepare('SELECT revision, policy_json, policy_sha256, updated_at FROM org_policies WHERE tenant_id = ?')
    .bind(tenantId).first();
}

export async function writeOrgPolicy(db, principal, policy, expectedRevision, hash) {
  const json = JSON.stringify(policy);
  let row;
  if (expectedRevision === 0) {
    row = await db.prepare(`
      INSERT INTO org_policies (tenant_id, revision, policy_json, policy_sha256, updated_by_key_id)
      VALUES (?, 1, ?, ?, ?) ON CONFLICT (tenant_id) DO NOTHING RETURNING revision
    `).bind(principal.tenant_id, json, hash, principal.key_id).first();
  } else {
    row = await db.prepare(`
      UPDATE org_policies SET revision = revision + 1, policy_json = ?, policy_sha256 = ?,
        updated_by_key_id = ?, updated_at = CURRENT_TIMESTAMP
      WHERE tenant_id = ? AND revision = ? RETURNING revision
    `).bind(json, hash, principal.key_id, principal.tenant_id, expectedRevision).first();
  }
  return row ? Number(row.revision) : null;
}
