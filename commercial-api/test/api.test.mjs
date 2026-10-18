import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import worker, { normalizeScan } from '../worker/src/index.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const schema = readFileSync(join(here, '../schema.sql'), 'utf8');
const key = () => 'dsc_test_' + randomBytes(32).toString('base64url');
function database() {
  const db = new DatabaseSync(':memory:');
  db.exec(schema);
  return {
    raw: db,
    prepare(sql) {
      return {
        bind(...values) {
          return {
            async first() { return db.prepare(sql).get(...values) || null; },
            async all() { return { results: db.prepare(sql).all(...values) }; }
          };
        }
      };
    }
  };
}

function fixture(runId = '1024') {
  return {
    schemaVersion: 1,
    tool: { name: 'MABRIG DevShield AI', version: '3.2.0' },
    repository: { fullName: 'mabrig1/example', private: true, id: 999 },
    revision: { headSha: 'a'.repeat(40), pullRequestNumber: 7 },
    delivery: { runId, runAttempt: '1' },
    summary: { riskLevel: 'high', riskScore: 42, findings: 1 },
    findings: [{
      fingerprint: 'fingerprint-1', rule: 'injection', severity: 'high',
      category: 'injection', file: 'src/app.js', line: 4, status: 'new',
      confidence: 'high', message: 'Potential injection', remediation: 'Review input handling'
    }]
  };
}
async function send(env, path, token, method = 'GET', payload = null, extraHeaders = {}) {
  const headers = { ...extraHeaders };
  if (token) headers.authorization = 'Bearer ' + token;
  if (payload !== null) headers['content-type'] = 'application/json';
  return worker.fetch(new Request('https://api.example.test' + path, {
    method, headers, body: payload === null ? undefined : JSON.stringify(payload)
  }), env);
}
function tenantSetup({ limit = 1 } = {}) {
  const db = database();
  const a = key(), b = key(), readOnly = key();
  for (const [id, name] of [['ta', 'Acme'], ['tb', 'Beta']]) {
    db.raw.prepare('INSERT INTO tenants (id, name, daily_scan_limit) VALUES (?, ?, ?)')
      .run(id, name, limit);
  }
  for (const [id, tid, rawKey, scopes] of [
    ['a', 'ta', a, 'scans:read scans:write'], ['b', 'tb', b, 'scans:read scans:write'],
    ['r', 'ta', readOnly, 'scans:read']
  ]) {
    db.raw.prepare('INSERT INTO api_keys (id, tenant_id, key_hash, label, scopes) VALUES (?, ?, ?, ?, ?)')
      .run(id, tid, createHash('sha256').update(rawKey).digest('hex'), 'test', scopes);
  }
  return { env: { DB: db }, a, b, readOnly, db };
}

test('scan normalization strips unnecessary metadata and refuses source fields', () => {
  const f = fixture();
  f.repository.unrelated = 'not collected';
  f.extra = { fullSource: 'not collected' };
  const sanitized = normalizeScan(f);
  assert.equal(sanitized.extra, undefined);
  assert.equal(sanitized.repository.unrelated, undefined);
  assert.equal(sanitized.findings[0].file, 'src/app.js');
  f.findings[0].source = 'const secret = abc';
  assert.throws(() => normalizeScan(f), /Unrecognized finding field/);
});

test('authenticated ingestion, deduplication, quota, and tenant isolation', async () => {
  const { env, a, b, readOnly } = tenantSetup();
  const unauthorized = await send(env, '/api/v1/scans', null, 'POST', fixture());
  assert.equal(unauthorized.status, 401);
  const readForbidden = await send(env, '/api/v1/scans', readOnly, 'POST', fixture());
  assert.equal(readForbidden.status, 403);

  const created = await send(env, '/api/v1/scans', a, 'POST', fixture());
  assert.equal(created.status, 201);
  const { id } = await created.json();
  assert.match(id, /^[0-9a-f-]{36}$/);
  const duplicate = await send(env, '/api/v1/scans', a, 'POST', fixture());
  assert.equal(duplicate.status, 200);
  assert.deepEqual(await duplicate.json(), { id, status: 'duplicate' });

  const usage = await send(env, '/v1/usage', a);
  assert.equal((await usage.json()).scansUsed, 1);
  const detail = await send(env, '/v1/scans/' + id, a);
  assert.equal((await detail.json()).report.repository.fullName, 'mabrig1/example');

  const blocked = await send(env, '/api/v1/scans', a, 'POST', fixture('other-run'));
  assert.equal(blocked.status, 429);
  assert.equal((await blocked.json()).error, 'quota_exceeded');

  const otherTenant = await send(env, '/v1/scans/' + id, b);
  assert.equal(otherTenant.status, 404);
  const list = await send(env, '/v1/scans', b);
  assert.deepEqual((await list.json()).scans, []);
  const otherUsage = await send(env, '/v1/usage', b);
  assert.equal((await otherUsage.json()).scansUsed, 0);
});

test('rejects malformed content, missing idempotency and inactive credentials', async () => {
  const { env, a, db } = tenantSetup();
  const f = fixture();
  f.delivery.runId = null;
  let resp = await send(env, '/v1/scans', a, 'POST', f);
  assert.equal(resp.status, 422);
  resp = await send(env, '/v1/scans', a, 'POST', f, { 'idempotency-key': 'mobile-call-0001' });
  assert.equal(resp.status, 201);

  resp = await send(env, '/v1/scans', a, 'POST', fixture(), { 'idempotency-key': 'bad' });
  assert.equal(resp.status, 422);
  const big = 'x'.repeat(270000);
  resp = await worker.fetch(new Request('https://api.example.test/api/v1/scans', {
    method: 'POST', headers: { authorization: 'Bearer ' + a, 'content-type': 'application/json' },
    body: JSON.stringify({ junk: big })
  }), env);
  assert.equal(resp.status, 413);

  db.raw.prepare("UPDATE tenants SET status = 'suspended' WHERE id = 'ta'").run();
  resp = await send(env, '/v1/usage', a);
  assert.equal(resp.status, 401);
});
