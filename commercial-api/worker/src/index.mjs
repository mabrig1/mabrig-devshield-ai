// DevShield Commercial API MVP — Cloudflare Worker + D1.
// Intentionally stores metadata and structured findings only, never source text or diffs.
const MAX_BODY_BYTES = 262144;
const MAX_FINDINGS = 250;
const MAX_PAGE_SIZE = 50;
const ALLOWED_SEVERITIES = new Set(['critical', 'high', 'medium', 'low', 'info']);
const ALLOWED_RISKS = new Set(['critical', 'high', 'medium', 'low']);
const SAFE_REPO = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;
const ALLOWED_FINDING_KEYS = new Set([
  'fingerprint', 'rule', 'severity', 'category', 'file', 'line', 'status',
  'confidence', 'cwe', 'message', 'remediation', 'dependency'
]);
const ALLOWED_DEPENDENCY_KEYS = new Set([
  'package', 'version', 'ecosystem', 'license', 'advisoryId', 'advisoryUrl'
]);

function json(value, status = 200, extra = {}) {
  return new Response(JSON.stringify(value), {
    status,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'no-store',
      'x-content-type-options': 'nosniff',
      'referrer-policy': 'no-referrer',
      ...extra
    }
  });
}

class ApiError extends Error {
  constructor(status, code, message) {
    super(message);
    this.status = status;
    this.code = code;
  }
}
const bad = (status, code, message) => { throw new ApiError(status, code, message); };
function boundedString(value, limit, name, { required = false } = {}) {
  if (value == null && !required) return null;
  if (typeof value !== 'string' || (required && !value.trim()) || value.length > limit) {
    bad(422, 'invalid_payload', 'Invalid ' + name);
  }
  return value;
}
const object = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
function safeObject(value, name) {
  if (!object(value)) bad(422, 'invalid_payload', 'Expected object: ' + name);
  return value;
}
function optionalString(v, limit, name) {
  return boundedString(v, limit, name);
}
function sanitizeFinding(f) {
  safeObject(f, 'finding');
  for (const key of Object.keys(f)) {
    if (!ALLOWED_FINDING_KEYS.has(key)) bad(422, 'invalid_payload', 'Unrecognized finding field');
  }
  const out = {
    fingerprint: optionalString(f.fingerprint, 128, 'fingerprint'),
    rule: optionalString(f.rule, 120, 'rule'),
    severity: optionalString(f.severity, 20, 'severity'),
    category: optionalString(f.category, 80, 'category'),
    file: optionalString(f.file, 500, 'file'),
    line: f.line == null ? null : f.line,
    status: optionalString(f.status, 32, 'status'),
    confidence: optionalString(f.confidence, 40, 'confidence'),
    cwe: optionalString(f.cwe, 80, 'cwe'),
    message: optionalString(f.message, 500, 'message'),
    remediation: optionalString(f.remediation, 1000, 'remediation')
  };
  if (out.severity && !ALLOWED_SEVERITIES.has(out.severity)) {
    bad(422, 'invalid_payload', 'Invalid finding severity');
  }
  if (out.line != null && (!Number.isSafeInteger(out.line) || out.line < 0)) {
    bad(422, 'invalid_payload', 'Invalid finding line');
  }
  if (f.dependency != null) {
    safeObject(f.dependency, 'dependency');
    for (const key of Object.keys(f.dependency)) {
      if (!ALLOWED_DEPENDENCY_KEYS.has(key)) bad(422, 'invalid_payload', 'Unrecognized dependency field');
    }
    out.dependency = {};
    for (const key of ALLOWED_DEPENDENCY_KEYS) {
      out.dependency[key] = optionalString(f.dependency[key], 300, 'dependency.' + key);
    }
  }
  return out;
}

export function normalizeScan(input) {
  safeObject(input, 'scan');
  if (input.schemaVersion !== 1) bad(422, 'invalid_payload', 'Unsupported scan schemaVersion');
  const repository = safeObject(input.repository, 'repository');
  const summary = safeObject(input.summary, 'summary');
  const fullName = boundedString(repository.fullName, 255, 'repository.fullName', { required: true });
  if (!SAFE_REPO.test(fullName) || fullName.includes('..')) bad(422, 'invalid_payload', 'Invalid repository.fullName');
  const riskLevel = boundedString(summary.riskLevel, 20, 'summary.riskLevel', { required: true });
  if (!ALLOWED_RISKS.has(riskLevel)) bad(422, 'invalid_payload', 'Invalid risk level');
  const riskScore = summary.riskScore;
  if (typeof riskScore !== 'number' || !Number.isFinite(riskScore) || riskScore < 0 || riskScore > 1000000) {
    bad(422, 'invalid_payload', 'Invalid risk score');
  }
  if (!Array.isArray(input.findings) || input.findings.length > MAX_FINDINGS) {
    bad(422, 'invalid_payload', 'Expected findings array with at most 250 items');
  }
  const headSha = optionalString(input.revision?.headSha, 80, 'revision.headSha');
  const runId = optionalString(input.delivery?.runId, 80, 'delivery.runId');
  const runAttempt = optionalString(input.delivery?.runAttempt, 20, 'delivery.runAttempt');
  const findings = input.findings.map(sanitizeFinding);
  return {
    schemaVersion: 1,
    toolVersion: optionalString(input.tool?.version, 32, 'tool.version'),
    repository: {
      fullName,
      id: repository.id == null ? null : String(repository.id).slice(0, 80),
      private: typeof repository.private === 'boolean' ? repository.private : null
    },
    revision: { headSha, pullRequestNumber: Number.isSafeInteger(input.revision?.pullRequestNumber) ? input.revision.pullRequestNumber : null },
    delivery: { runId, runAttempt },
    summary: { riskLevel, riskScore, findings: findings.length },
    findings
  };
}

async function hash(value) {
  const bytes = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value));
  return Array.from(new Uint8Array(bytes), b => b.toString(16).padStart(2, '0')).join('');
}

function bearer(req) {
  const auth = req.headers.get('authorization') || '';
  const m = /^Bearer (dsc_(?:live|test)_[A-Za-z0-9_-]{32,96})$/.exec(auth);
  if (!m) bad(401, 'unauthorized', 'Valid bearer API key required');
  return m[1];
}

async function authenticate(req, env, permission) {
  if (!env.DB) bad(503, 'unavailable', 'Database not configured');
  const keyHash = await hash(bearer(req));
  const record = await env.DB.prepare(`
    SELECT k.tenant_id, k.scopes, t.daily_scan_limit
    FROM api_keys k JOIN tenants t ON t.id = k.tenant_id
    WHERE k.key_hash = ? AND k.status = 'active' AND t.status = 'active'
      AND (k.expires_at IS NULL OR k.expires_at > CURRENT_TIMESTAMP)
  `).bind(keyHash).first();
  if (!record) bad(401, 'unauthorized', 'Invalid or inactive API key');
  if (!String(record.scopes || '').split(/\s+/).includes(permission)) {
    bad(403, 'forbidden', 'API key lacks required scope');
  }
  return record;
}

async function readBoundedJson(req) {
  if (!/^application\/json(?:\s*;|$)/i.test(req.headers.get('content-type') || '')) {
    bad(415, 'unsupported_media_type', 'Content-Type must be application/json');
  }
  const length = Number(req.headers.get('content-length'));
  if (Number.isFinite(length) && length > MAX_BODY_BYTES) bad(413, 'too_large', 'Payload exceeds 256 KiB');
  if (!req.body) bad(400, 'invalid_json', 'Request body required');
  const reader = req.body.getReader();
  const chunks = [];
  let size = 0;
  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > MAX_BODY_BYTES) {
        await reader.cancel();
        bad(413, 'too_large', 'Payload exceeds 256 KiB');
      }
      chunks.push(value);
    }
  } finally { reader.releaseLock(); }
  const data = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) { data.set(chunk, offset); offset += chunk.byteLength; }
  try { return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(data)); }
  catch { bad(400, 'invalid_json', 'Malformed JSON'); }
}

function getIdempotencyKey(req, scan) {
  const fromHeader = req.headers.get('idempotency-key');
  if (fromHeader !== null) {
    if (!/^[A-Za-z0-9_.:-]{8,128}$/.test(fromHeader)) {
      bad(422, 'invalid_idempotency_key', 'Invalid Idempotency-Key');
    }
    return fromHeader;
  }
  if (scan.delivery.runId) {
    return ['github', scan.repository.fullName, scan.delivery.runId, scan.delivery.runAttempt || '1'].join(':');
  }
  bad(422, 'idempotency_required', 'Provide Idempotency-Key or GitHub run metadata');
}

async function getExisting(db, tenantId, idempotencyKey) {
  return db.prepare(`SELECT id FROM scans WHERE tenant_id = ? AND idempotency_key = ?`)
    .bind(tenantId, idempotencyKey).first();
}

async function ingest(req, env, principal) {
  const payload = normalizeScan(await readBoundedJson(req));
  const key = getIdempotencyKey(req, payload);
  const existing = await getExisting(env.DB, principal.tenant_id, key);
  if (existing) return json({ id: existing.id, status: 'duplicate' }, 200);
  const id = crypto.randomUUID();
  const day = new Date().toISOString().slice(0, 10);
  const limit = Number(principal.daily_scan_limit);
  if (!Number.isSafeInteger(limit) || limit < 1) bad(403, 'subscription_inactive', 'No scan allowance');
  const result = await env.DB.prepare(`
    INSERT INTO scans (id, tenant_id, idempotency_key, repository, head_sha,
                       risk_level, risk_score, findings_count, scan_day, payload_json)
    SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
    WHERE (SELECT COUNT(*) FROM scans WHERE tenant_id = ? AND scan_day = ?) < ?
    ON CONFLICT (tenant_id, idempotency_key) DO NOTHING RETURNING id
  `).bind(id, principal.tenant_id, key, payload.repository.fullName, payload.revision.headSha,
    payload.summary.riskLevel, payload.summary.riskScore, payload.summary.findings,
    day, JSON.stringify(payload), principal.tenant_id, day, limit).first();
  if (!result) {
    const duplicate = await getExisting(env.DB, principal.tenant_id, key);
    if (duplicate) return json({ id: duplicate.id, status: 'duplicate' });
    bad(429, 'quota_exceeded', 'Daily scan allowance exceeded');
  }
  return json({ id: result.id, status: 'created' }, 201);
}

async function listScans(req, env, principal) {
  const url = new URL(req.url);
  const n = Number(url.searchParams.get('limit') || 20);
  if (!Number.isInteger(n) || n < 1 || n > MAX_PAGE_SIZE) bad(400, 'invalid_limit', 'limit must be 1..50');
  const rows = await env.DB.prepare(`
    SELECT id, repository, head_sha AS headSha, risk_level AS riskLevel,
           risk_score AS riskScore, findings_count AS findingsCount, created_at AS createdAt
    FROM scans WHERE tenant_id = ? ORDER BY created_at DESC, id DESC LIMIT ?
  `).bind(principal.tenant_id, n).all();
  return json({ scans: rows.results || [] });
}

async function getScan(env, principal, id) {
  if (!/^[0-9a-f-]{36}$/i.test(id)) bad(404, 'not_found', 'Scan not found');
  const scan = await env.DB.prepare(`
    SELECT id, created_at, payload_json FROM scans WHERE tenant_id = ? AND id = ?
  `).bind(principal.tenant_id, id).first();
  if (!scan) bad(404, 'not_found', 'Scan not found');
  return json({ id: scan.id, createdAt: scan.created_at, report: JSON.parse(scan.payload_json) });
}

async function getUsage(env, principal) {
  const day = new Date().toISOString().slice(0, 10);
  const usage = await env.DB.prepare(`
    SELECT COUNT(*) AS used FROM scans WHERE tenant_id = ? AND scan_day = ?
  `).bind(principal.tenant_id, day).first();
  return json({ date: day, scansUsed: Number(usage?.used || 0), dailyScanLimit: Number(principal.daily_scan_limit) });
}

export async function handleRequest(req, env) {
  const url = new URL(req.url);
  const path = url.pathname.replace(/^\/api(?=\/v1\/)/, '');
  if (url.pathname === '/health' && req.method === 'GET') {
    return json({ ok: true, component: 'DevShield Commercial API', version: '0.1.0' });
  }
  if (!path.startsWith('/v1/')) return json({ error: 'not_found' }, 404);
  if (path === '/v1/scans' && req.method === 'POST') {
    return ingest(req, env, await authenticate(req, env, 'scans:write'));
  }
  if (path === '/v1/scans' && req.method === 'GET') {
    return listScans(req, env, await authenticate(req, env, 'scans:read'));
  }
  if (path === '/v1/usage' && req.method === 'GET') {
    return getUsage(env, await authenticate(req, env, 'scans:read'));
  }
  if (path.startsWith('/v1/scans/') && req.method === 'GET') {
    return getScan(env, await authenticate(req, env, 'scans:read'), path.slice('/v1/scans/'.length));
  }
  return json({ error: 'not_found' }, 404);
}

export default {
  async fetch(req, env) {
    try { return await handleRequest(req, env); }
    catch (error) {
      if (error instanceof ApiError) return json({ error: error.code, message: error.message }, error.status);
      // Never expose SQL errors, credentials, or stack traces to API clients.
      console.error('DevShield API request failed', error?.name || 'Error');
      return json({ error: 'internal_error', message: 'Request could not be completed' }, 500);
    }
  }
};
