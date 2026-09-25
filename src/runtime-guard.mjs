import fs from 'node:fs';
import path from 'node:path';
import net from 'node:net';
import { lookup } from 'node:dns/promises';
import { request as httpRequest } from 'node:http';
import { request as httpsRequest } from 'node:https';

export const RUNTIME_PROBES = Object.freeze([
  ['xss', 'XSS-shaped marker', '<script>devshield_runtime_probe</script>'],
  ['sqli', 'SQLi-shaped marker', "' OR 'devshield'='devshield' --"],
  ['path-traversal', 'Traversal-shaped marker', '../../../../devshield-runtime-probe.txt']
].map(([category, label, value]) => ({ id: category, category, label, value })));

const BLOCK = new Set([403, 406, 418, 429]);
const REJECT = new Set([400, 405, 413, 415, 422]);
const bool = (v, d = false) => v == null || v === '' ? d : String(v).toLowerCase() === 'true';
const int = (v, min, max, d) => { const n = Number.parseInt(v, 10); return Number.isFinite(n) ? Math.max(min, Math.min(max, n)) : d; };
const stripIpBrackets = value => String(value || '').replace(/^\[|\]$/g, '');
const normalizeIp = value => stripIpBrackets(value).toLowerCase().replace(/^::ffff:/, '');

export function isPrivateIp(ip) {
  const normalized = stripIpBrackets(ip);
  const family = net.isIP(normalized);
  if (family === 4) {
    const [a, b] = normalized.split('.').map(Number);
    return a === 10 || a === 127 || a === 0 || a >= 224 ||
      (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127);
  }
  if (family === 6) {
    const v = normalized.toLowerCase().split('%')[0];
    return v === '::' || v === '::1' || /^(fc|fd|fe[89ab]|ff)/.test(v) ||
      /^::ffff:(127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(v);
  }
  return false;
}

export function sanitizeTarget(raw) {
  const u = new URL(String(raw));
  u.username = ''; u.password = ''; u.search = ''; u.hash = '';
  return u.toString();
}

export async function resolveRuntimeAddress(raw, { allowPrivate = false, lookupFn = lookup } = {}) {
  const u = raw instanceof URL ? raw : new URL(String(raw));
  const hostname = stripIpBrackets(u.hostname).toLowerCase();
  const literalFamily = net.isIP(hostname);
  if (literalFamily) {
    if (!allowPrivate && isPrivateIp(hostname)) throw new Error('runtime-target points to a private or non-routable IP');
    return { address: hostname, family: literalFamily };
  }

  const addresses = await lookupFn(hostname, { all: true, verbatim: true });
  if (!addresses?.length) throw new Error('runtime-target hostname did not resolve');
  const normalized = addresses
    .map(item => ({ address: stripIpBrackets(item?.address), family: Number(item?.family) || net.isIP(stripIpBrackets(item?.address)) }))
    .filter(item => item.address && (item.family === 4 || item.family === 6));
  if (!normalized.length) throw new Error('runtime-target hostname did not resolve to an IP address');
  if (!allowPrivate && normalized.some(item => isPrivateIp(item.address))) {
    throw new Error('runtime-target resolves to a private or non-routable IP');
  }
  return normalized[0];
}

export async function validateRuntimeTarget(raw, { allowHttp = false, allowPrivate = false, lookupFn = lookup } = {}) {
  if (!raw || !String(raw).trim()) throw new Error('runtime-target is required');
  let u;
  try { u = new URL(String(raw).trim()); } catch { throw new Error('runtime-target must be an absolute URL'); }
  if (!['http:', 'https:'].includes(u.protocol)) throw new Error('runtime-target must use http or https');
  if (u.protocol === 'http:' && !allowHttp) throw new Error('runtime-target must use https unless runtime-allow-http=true');
  if (u.username || u.password) throw new Error('runtime-target must not embed credentials');
  const h = stripIpBrackets(u.hostname).toLowerCase();
  if (!allowPrivate && (h === 'localhost' || h.endsWith('.localhost') || h.endsWith('.local'))) throw new Error('runtime-target is local');
  await resolveRuntimeAddress(u, { allowPrivate, lookupFn });
  return u;
}

const outcome = status => BLOCK.has(status) ? 'blocked' : REJECT.has(status) ? 'rejected' : 'passed-through';
const probeUrl = (target, probe) => { const u = new URL(target); u.searchParams.set('__devshield_probe', probe.id); u.searchParams.set('q', probe.value); return u; };

function pinnedLookup(resolved) {
  return (_hostname, options, callback) => {
    let opts = options;
    let cb = callback;
    if (typeof options === 'function') {
      cb = options;
      opts = {};
    }
    if (opts?.all) cb(null, [{ address: resolved.address, family: resolved.family }]);
    else cb(null, resolved.address, resolved.family);
  };
}

async function pinnedRequest(url, { timeoutMs, headers, resolved }) {
  const u = url instanceof URL ? url : new URL(String(url));
  const requestImpl = u.protocol === 'https:' ? httpsRequest : httpRequest;
  return new Promise((resolve, reject) => {
    const req = requestImpl({
      protocol: u.protocol,
      hostname: stripIpBrackets(u.hostname),
      port: u.port || undefined,
      path: `${u.pathname || '/'}${u.search || ''}`,
      method: 'GET',
      headers,
      agent: false,
      lookup: pinnedLookup(resolved),
      servername: u.protocol === 'https:' && !net.isIP(stripIpBrackets(u.hostname)) ? stripIpBrackets(u.hostname) : undefined,
      timeout: timeoutMs
    }, res => {
      const actual = normalizeIp(res.socket?.remoteAddress || '');
      const expected = normalizeIp(resolved.address);
      if (actual && expected && actual !== expected) {
        res.destroy();
        reject(new Error('runtime-target connected to an address different from the validated DNS result'));
        return;
      }
      const status = res.statusCode ?? 0;
      res.resume();
      resolve({ status });
    });
    req.on('timeout', () => req.destroy(new Error('runtime-target request timed out')));
    req.on('error', reject);
    req.end();
  });
}

async function hit(url, {
  fetchFn = null, requestFn = null, lookupFn = lookup, allowPrivate = false,
  timeoutMs, authHeader, vercelBypassToken
}) {
  const headers = { 'user-agent': 'MABRIG-DevShield-Runtime-Guard/2.8', 'x-devshield-runtime-probe': '1' };
  if (authHeader) headers.authorization = authHeader;
  if (vercelBypassToken) headers['x-vercel-protection-bypass'] = vercelBypassToken;

  // Custom fetch is retained only as an injectable/testing escape hatch. Normal Action/CLI
  // traffic uses a validated, DNS-pinned Node HTTP(S) request below.
  if (fetchFn) {
    const r = await fetchFn(url, { method: 'GET', headers, redirect: 'manual', signal: AbortSignal.timeout(timeoutMs) });
    try { await r.body?.cancel?.(); } catch {}
    return { status: r.status };
  }

  const resolved = await resolveRuntimeAddress(url, { allowPrivate, lookupFn });
  const send = requestFn || pinnedRequest;
  return send(url, { timeoutMs, headers, resolved });
}

function stateOf(baseline, probes) {
  if ([401, 403].includes(baseline?.status)) return 'inconclusive-auth-gated';
  if (baseline?.status == null) return 'inconclusive-errors';
  if (!probes.length) return 'inconclusive';
  const blocked = probes.filter(x => x.outcome === 'blocked').length;
  if (blocked === probes.length) return 'protected-signals';
  if (blocked) return 'partial-block-signals';
  return 'no-block-signals';
}

function markdown(r) {
  const rows = r.probes.map(p => `| ${p.label} | ${p.status ?? '-'} | ${p.outcome} |`).join('\n') || '| No probes executed | - | inconclusive |';
  return `## MABRIG DevShield Runtime Guard\n\n**State:** ${r.state}  \n**Target:** ${r.target}  \n**DNS pinning:** ${r.policy.dnsPinning ? 'enabled' : 'custom fetch mode'}  \n**Block signals:** ${r.summary.blocked}/${r.summary.total} (${r.summary.blockRate}%)\n\n> Controlled, non-destructive attack-shaped markers are used. A passed-through marker is a WAF coverage signal, not proof of exploitability.\n\n| Probe | HTTP | Outcome |\n| --- | ---: | --- |\n${rows}\n`;
}

function sarif(r) {
  return { version: '2.1.0', $schema: 'https://json.schemastore.org/sarif-2.1.0.json', runs: [{
    tool: { driver: { name: 'MABRIG DevShield Runtime Guard', version: '2.8.0' } },
    results: r.probes.filter(p => ['passed-through', 'error'].includes(p.outcome)).map(p => ({
      ruleId: `runtime-${p.category}`,
      level: p.outcome === 'error' ? 'note' : 'warning',
      message: { text: p.outcome === 'error' ? `${p.label} could not be evaluated: ${p.error}` : `${p.label} was not blocked. This is a runtime-defense signal, not proof of exploitability.` }
    }))
  }] };
}

export async function runRuntimeGuard(options = {}) {
  const {
    target, allowHttp = false, allowPrivate = false, enforce = false, minBlockRate = 100,
    timeoutMs = 8000, fetchFn = null, requestFn = null, lookupFn = lookup, workspace = process.cwd(),
    reportDir = '.devshield', writeSarif = true, authHeader = '', vercelBypassToken = '',
    outputFile = '', summaryFile = ''
  } = options;
  if (fetchFn != null && typeof fetchFn !== 'function') throw new Error('Runtime Guard fetchFn must be a function');
  if (requestFn != null && typeof requestFn !== 'function') throw new Error('Runtime Guard requestFn must be a function');
  const validated = await validateRuntimeTarget(target, { allowHttp, allowPrivate, lookupFn });
  let baseline;
  try {
    baseline = await hit(validated, { fetchFn, requestFn, lookupFn, allowPrivate, timeoutMs, authHeader, vercelBypassToken });
  } catch (e) {
    baseline = { status: null, error: e?.message || String(e) };
  }
  const probes = [];
  if (![401, 403].includes(baseline?.status) && baseline?.status != null) {
    for (const p of RUNTIME_PROBES) {
      try {
        const r = await hit(probeUrl(validated, p), { fetchFn, requestFn, lookupFn, allowPrivate, timeoutMs, authHeader, vercelBypassToken });
        probes.push({ ...p, status: r.status, outcome: outcome(r.status) });
      } catch (e) {
        probes.push({ ...p, status: null, outcome: 'error', error: e?.message || String(e) });
      }
    }
  }
  const blocked = probes.filter(p => p.outcome === 'blocked').length;
  const passedThrough = probes.filter(p => p.outcome === 'passed-through').length;
  const rejected = probes.filter(p => p.outcome === 'rejected').length;
  const errors = probes.filter(p => p.outcome === 'error').length;
  const total = probes.length;
  const blockRate = total ? Math.round(blocked / total * 100) : 0;
  const report = {
    schemaVersion: 1, tool: 'MABRIG DevShield Runtime Guard', version: '2.8.0',
    target: sanitizeTarget(validated), state: stateOf(baseline, probes), baseline, probes,
    summary: { total, blocked, passedThrough, rejected, errors, blockRate, minBlockRate: int(minBlockRate, 0, 100, 100) },
    policy: {
      enforce: Boolean(enforce),
      allowHttp: Boolean(allowHttp),
      allowPrivate: Boolean(allowPrivate),
      dnsPinning: !fetchFn,
      redirects: 'disabled'
    }
  };
  const dir = path.resolve(workspace, reportDir); fs.mkdirSync(dir, { recursive: true });
  const reportPath = path.join(dir, 'runtime-guard.json');
  const sarifPath = path.join(dir, 'runtime-guard.sarif');
  fs.writeFileSync(reportPath, JSON.stringify(report, null, 2) + '\n');
  if (writeSarif) fs.writeFileSync(sarifPath, JSON.stringify(sarif(report), null, 2) + '\n');
  if (summaryFile) fs.appendFileSync(summaryFile, markdown(report) + '\n');
  const rel = f => path.relative(workspace, f).replace(/\\/g, '/');
  const outputs = {
    'runtime-guard-state': report.state, 'runtime-probes': total, 'runtime-blocked': blocked,
    'runtime-passed-through': passedThrough, 'runtime-errors': errors, 'runtime-block-rate': blockRate,
    'runtime-report-file': rel(reportPath), 'runtime-sarif-file': writeSarif ? rel(sarifPath) : ''
  };
  if (outputFile) fs.appendFileSync(outputFile, Object.entries(outputs).map(([k, v]) => `${k}=${v}`).join('\n') + '\n');
  const shouldFail = Boolean(enforce) && (baseline?.status == null || [401, 403].includes(baseline?.status) || errors > 0 || blockRate < int(minBlockRate, 0, 100, 100));
  return { report, outputs, shouldFail };
}

export async function runRuntimeGuardFromEnv() {
  const mode = String(process.env.INPUT_RUNTIME_GUARD || 'off').toLowerCase();
  if (!['off', 'probe'].includes(mode)) throw new Error('runtime-guard must be off or probe');
  if (mode === 'off') return { disabled: true, shouldFail: false };
  return runRuntimeGuard({
    target: process.env.INPUT_RUNTIME_TARGET || '',
    allowHttp: bool(process.env.INPUT_RUNTIME_ALLOW_HTTP), allowPrivate: bool(process.env.INPUT_RUNTIME_ALLOW_PRIVATE),
    enforce: bool(process.env.INPUT_RUNTIME_ENFORCE), minBlockRate: int(process.env.INPUT_RUNTIME_MIN_BLOCK_RATE, 0, 100, 100),
    timeoutMs: int(process.env.INPUT_RUNTIME_TIMEOUT_MS, 1000, 30000, 8000),
    workspace: process.env.GITHUB_WORKSPACE || process.cwd(), reportDir: process.env.INPUT_REPORT_DIR || '.devshield',
    writeSarif: bool(process.env.INPUT_RUNTIME_SARIF, true), authHeader: process.env.INPUT_RUNTIME_AUTH_HEADER || '',
    vercelBypassToken: process.env.INPUT_RUNTIME_VERCEL_BYPASS_TOKEN || '', outputFile: process.env.GITHUB_OUTPUT || '',
    summaryFile: process.env.GITHUB_STEP_SUMMARY || ''
  });
}
