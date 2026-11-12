import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { normalizeOrgPolicy, readOrgPolicy, writeOrgPolicy } from '../worker/src/org-policy.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const migrate = fs.readFileSync(join(here, '../org-policy-migration.sql'), 'utf8');
function db() {
  const raw = new DatabaseSync(':memory:');
  raw.exec('CREATE TABLE tenants (id TEXT PRIMARY KEY); CREATE TABLE api_keys (id TEXT PRIMARY KEY);');
  raw.exec("INSERT INTO tenants VALUES ('tenant-a'), ('tenant-b'); INSERT INTO api_keys VALUES ('a'), ('b');");
  raw.exec(migrate);
  return { raw, prepare(sql) { return { bind(...values) { return { async first() { return raw.prepare(sql).get(...values) || null; } }; } }; } };
}
const doc = (name = 'team') => ({ schemaVersion: 1, name, repositories: ['acme/api', 'acme/web'], controls: { failOn: 'high', riskExceptionMaxDays: 14, riskExceptionAllowCritical: false } });

test('validates strict policy pack and rejects dangerous input', () => {
  assert.equal(normalizeOrgPolicy(doc()).repositories.length, 2);
  for (const change of [
    d => d.repositories.push('../secrets'),
    d => d.controls.failOn = 'anything',
    d => Object.defineProperty(d.controls, '__proto__', { value: 'bad', enumerable: true }),
    d => d.repositories = ['acme/api', 'acme/api'],
    d => d.controls.riskExceptionMaxDays = 365,
    d => d.credentials = { password: 'secret' }
  ]) {
    const item = doc(); change(item);
    assert.throws(() => normalizeOrgPolicy(item));
  }
});

test('tenant-scoped versioning and SQL-trigger audit trail', async () => {
  const database = db();
  try {
    const a = { tenant_id: 'tenant-a', key_id: 'a' };
    const b = { tenant_id: 'tenant-b', key_id: 'b' };
    assert.equal(await writeOrgPolicy(database, a, normalizeOrgPolicy(doc()), 0, 'a'.repeat(64)), 1);
    assert.equal(await writeOrgPolicy(database, a, normalizeOrgPolicy(doc('second')), 0, 'b'.repeat(64)), null);
    assert.equal(await writeOrgPolicy(database, a, normalizeOrgPolicy(doc('second')), 1, 'b'.repeat(64)), 2);
    assert.equal(await writeOrgPolicy(database, a, normalizeOrgPolicy(doc()), 1, 'c'.repeat(64)), null);
    assert.equal(await readOrgPolicy(database, 'tenant-b'), null);
    assert.equal(await writeOrgPolicy(database, b, normalizeOrgPolicy(doc()), 0, 'd'.repeat(64)), 1);
    assert.equal((await readOrgPolicy(database, 'tenant-a')).revision, 2);
    assert.equal((await readOrgPolicy(database, 'tenant-b')).revision, 1);
    const audit = database.raw.prepare('SELECT tenant_id, revision, action, actor_key_id FROM org_policy_audit ORDER BY id').all();
    assert.deepEqual(audit.map(x => [x.tenant_id, x.revision, x.action, x.actor_key_id]), [
      ['tenant-a', 1, 'created', 'a'], ['tenant-a', 2, 'updated', 'a'], ['tenant-b', 1, 'created', 'b']
    ]);
  } finally { database.raw.close(); }
});
