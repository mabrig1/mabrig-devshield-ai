// Privacy-first, explicit opt-in bridge from local deterministic scans to DevShield Cloud.
// Never submit source text, code snippets, diffs, filenames or relative file paths.
import crypto from 'node:crypto';
import net from 'node:net';

const MODES = new Set([
  'full', 'staged-diff', 'preflight', 'dependency-inventory',
  'api-agent-trust', 'legal-compliance', 'waap-policy', 'security-graph'
]);
const PRIORITY = { low: 1, medium: 2, high: 3, critical: 4, info: 0 };
const MAX_REPORT_BYTES = 256 * 1024;
const MAX_FINDINGS = 250;
const REPO = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;
const KEY = /^dsc_(?:live|test)_[A-Za-z0-9_-]{32,96}$/;

function validRepo(repo) {
  if (typeof repo !== 'string' || repo.length > 255 || !REPO.test(repo) ||
      repo.includes('..') || repo.startsWith('-')) throw Error('Invalid repository name; use owner/repository');
  return repo;
}
function fingerprint(f, secret) {
  // Stable private correlation only: the original relative path never leaves the device.
  return crypto.createHmac('sha256', secret)
    .update(JSON.stringify([String(f.rule || ''), String(f.file || ''), f.line || 0, f.severity]))
    .digest('hex');
}
export function buildCloudReport(localReport, { repository, idempotencyKey = crypto.randomUUID(), fingerprintKey } = {}) {
  if (typeof fingerprintKey !== 'string' || !KEY.test(fingerprintKey)) {
    throw Error('Cloud API key required for private HMAC fingerprints');
  }
  validRepo(repository);
  if (!localReport || !MODES.has(localReport.mode) || localReport.complete !== true ||
      !Array.isArray(localReport.findings) || localReport.findings.length > MAX_FINDINGS ||
      localReport.summary?.capped === true) {
    throw Error('Local scan is incomplete, unsupported or too large; upload refused');
  }
  const findings = localReport.findings.map(f => {
    if (!f || typeof f.rule !== 'string' || f.rule.length > 120 ||
        !Object.hasOwn(PRIORITY, f.severity) ||
        typeof f.category !== 'string' || f.category.length > 80) {
      throw Error('Invalid local finding; upload refused');
    }
    return {
      fingerprint: fingerprint(f, fingerprintKey),
      rule: f.rule,
      severity: f.severity,
      category: f.category,
      // All free-text messages, paths, source lines, dependencies, evidence,
      // graph nodes and WAAP routes are deliberately omitted.
      confidence: ['heuristic', 'contextual', 'direct', 'high', 'medium', 'low']
        .includes(f.confidence) ? f.confidence : 'heuristic'
    };
  });
  if (typeof idempotencyKey !== 'string' ||
      !/^[A-Za-z0-9_.:-]{8,128}$/.test(idempotencyKey)) {
    throw Error('Invalid idempotency key');
  }
  const score = findings.reduce((sum, f) => Math.min(100, sum + (PRIORITY[f.severity] || 0) * 5), 0);
  const highest = findings.reduce((n, f) => Math.max(n, PRIORITY[f.severity] || 0), 0);
  const riskLevel = Object.keys(PRIORITY).find(k => PRIORITY[k] === highest && k !== 'info') || 'low';
  const payload = {
    schemaVersion: 1,
    scanType: localReport.mode,
    tool: { version: '3.2.0' },
    repository: { fullName: repository },
    revision: { headSha: null },
    delivery: { runId: null },
    summary: { riskLevel, riskScore: score },
    findings
  };
  const encoded = JSON.stringify(payload);
  if (Buffer.byteLength(encoded, 'utf8') > MAX_REPORT_BYTES) throw Error('Report exceeds cloud byte cap');
  return { payload, idempotencyKey, privacy: {
    sourceUploaded: false, pathsUploaded: false, messagesUploaded: false,
    graphUploaded: false, apiKeyIncludedInReport: false
  }, bytes: Buffer.byteLength(encoded, 'utf8') };
}
export function cloudEndpoint(origin, mode) {
  if (!MODES.has(mode)) throw Error('Unsupported cloud report mode');
  let url;
  try { url = new URL(origin); } catch { throw Error('Cloud API endpoint must be a valid HTTPS origin'); }
  // Reject potentially credential-leaking redirects, internal endpoints and URL tricks.
  const host = url.hostname.toLowerCase();
  if (url.protocol !== 'https:' || url.username || url.password ||
      url.port && url.port !== '443' || url.search || url.hash ||
      url.pathname !== '/' || net.isIP(host) ||
      host === 'localhost' || host.endsWith('.localhost') ||
      host.endsWith('.local') || host.endsWith('.internal') ||
      host.endsWith('.invalid') || !host.includes('.') ||
      !/^[a-z0-9.-]+$/.test(host)) {
    throw Error('Cloud API endpoint must be an HTTPS public DNS origin without credentials, ports, paths or query');
  }
  return url.origin + '/v1/scan-reports/' + mode;
}

function ensureKeys(value, keys, name) {
  if (!value || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype ||
      Object.keys(value).some(k => !keys.includes(k)) ||
      keys.some(k => !Object.hasOwn(value, k))) {
    throw Error('Privacy contract violated: unexpected ' + name + ' fields');
  }
}
export function validatePrivateCloudPayload(prepared) {
  if (!prepared || typeof prepared !== 'object') throw Error('Prepared report required');
  const data = prepared.payload;
  ensureKeys(data, ['schemaVersion', 'scanType', 'tool', 'repository', 'revision', 'delivery', 'summary', 'findings'], 'report');
  if (data.schemaVersion !== 1 || !MODES.has(data.scanType)) throw Error('Unsupported report type');
  ensureKeys(data.tool, ['version'], 'tool');
  ensureKeys(data.repository, ['fullName'], 'repository');
  validRepo(data.repository.fullName);
  ensureKeys(data.revision, ['headSha'], 'revision');
  ensureKeys(data.delivery, ['runId'], 'delivery');
  if (data.revision.headSha !== null || data.delivery.runId !== null) {
    throw Error('Unexpected revision or delivery metadata');
  }
  ensureKeys(data.summary, ['riskLevel', 'riskScore'], 'summary');
  if (!['critical', 'high', 'medium', 'low'].includes(data.summary.riskLevel) ||
      !Number.isSafeInteger(data.summary.riskScore) ||
      data.summary.riskScore < 0 || data.summary.riskScore > 100) {
    throw Error('Invalid summary');
  }
  if (!Array.isArray(data.findings) || data.findings.length > MAX_FINDINGS) {
    throw Error('Invalid findings count');
  }
  for (const item of data.findings) {
    ensureKeys(item, ['fingerprint', 'rule', 'severity', 'category', 'confidence'], 'finding');
    if (!/^[0-9a-f]{64}$/.test(item.fingerprint) ||
        typeof item.rule !== 'string' || !item.rule || item.rule.length > 120 ||
        typeof item.category !== 'string' || item.category.length > 80 ||
        !Object.hasOwn(PRIORITY, item.severity) ||
        !['heuristic', 'contextual', 'direct', 'high', 'medium', 'low'].includes(item.confidence)) {
      throw Error('Invalid private finding');
    }
  }
  if (typeof prepared.idempotencyKey !== 'string' ||
      !/^[A-Za-z0-9_.:-]{8,128}$/.test(prepared.idempotencyKey)) {
    throw Error('Invalid idempotency key');
  }
  if (Buffer.byteLength(JSON.stringify(data), 'utf8') > MAX_REPORT_BYTES) {
    throw Error('Report exceeds cloud byte cap');
  }
  return true;
}
export async function uploadCloudReport(prepared, {
  origin, apiKey, fetchImpl = fetch, timeoutMs = 10000
} = {}) {
  validatePrivateCloudPayload(prepared);
  const url = cloudEndpoint(origin, prepared.payload.scanType);
  if (typeof apiKey !== 'string' || !KEY.test(apiKey)) throw Error('Set a valid DevShield Cloud API key');
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1000 || timeoutMs > 30000)
    throw Error('Invalid upload timeout');
  const bytes = Buffer.byteLength(JSON.stringify(prepared.payload), 'utf8');
  if (bytes > MAX_REPORT_BYTES) throw Error('Report exceeds cloud byte cap');
  // Never send raw scanner output. Only a previously prepared allowlisted payload.
  const response = await fetchImpl(url, {
    method: 'POST',
    headers: {
      authorization: 'Bearer ' + apiKey,
      'content-type': 'application/json',
      'idempotency-key': prepared.idempotencyKey
    },
    body: JSON.stringify(prepared.payload),
    redirect: 'error',
    signal: AbortSignal.timeout(timeoutMs)
  });
  if (!response || ![200, 201].includes(response.status)) {
    // Do not print response bodies; they may echo sensitive headers at a hostile endpoint.
    throw Error('Cloud API rejected report (HTTP ' + (response?.status || 'unknown') + ')');
  }
  const body = await response.json();
  if (!body || !['created', 'duplicate'].includes(body.status) ||
      typeof body.id !== 'string' || !/^[0-9a-f-]{36}$/i.test(body.id)) {
    throw Error('Unexpected cloud response');
  }
  return { id: body.id, status: body.status, httpStatus: response.status };
}
