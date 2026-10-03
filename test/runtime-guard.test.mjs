import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { buildAbuseTarget, defenseSignals, isPrivateIp, resolveRuntimeAddress, runRuntimeGuard, sanitizeTarget, validateRuntimeTarget } from '../src/runtime-guard.mjs';

function response(status, headers = {}) {
  return {
    status,
    statusText: '',
    headers: { get: key => headers[String(key).toLowerCase()] || null },
    body: { cancel: async () => {} }
  };
}

const publicLookup = async () => [{ address: '203.0.113.10', family: 4 }];

test('private IP detection rejects common local ranges', () => {
  assert.equal(isPrivateIp('127.0.0.1'), true);
  assert.equal(isPrivateIp('10.2.3.4'), true);
  assert.equal(isPrivateIp('172.20.1.1'), true);
  assert.equal(isPrivateIp('192.168.1.10'), true);
  assert.equal(isPrivateIp('8.8.8.8'), false);
});

test('target sanitization removes credentials, query, and fragment from reports', () => {
  assert.equal(sanitizeTarget('https://user:pass@example.com/demo?token=secret#x'), 'https://example.com/demo');
});

test('runtime target validation rejects localhost and http by default', async () => {
  await assert.rejects(() => validateRuntimeTarget('https://127.0.0.1'), /private or non-routable/);
  await assert.rejects(() => validateRuntimeTarget('http://example.com', { lookupFn: publicLookup }), /must use https/);
  const target = await validateRuntimeTarget('https://example.com/preview', { lookupFn: publicLookup });
  assert.equal(target.hostname, 'example.com');
});

test('all blocked probes produce protected-signals', async () => {
  const workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'devshield-runtime-'));
  let call = 0;
  const fetchFn = async () => response(call++ === 0 ? 200 : 403);
  const result = await runRuntimeGuard({
    target: 'https://example.com/preview',
    fetchFn,
    lookupFn: publicLookup,
    workspace,
    comment: false
  });
  assert.equal(result.report.state, 'protected-signals');
  assert.equal(result.report.summary.blocked, 3);
  assert.equal(result.report.summary.blockRate, 100);
  assert.equal(result.shouldFail, false);
  assert.equal(fs.existsSync(path.join(workspace, '.devshield/runtime-guard.json')), true);
  assert.equal(fs.existsSync(path.join(workspace, '.devshield/runtime-guard.sarif')), true);
});

test('mixed responses are reported without claiming exploitability', async () => {
  const workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'devshield-runtime-'));
  const statuses = [200, 403, 200, 403];
  let call = 0;
  const result = await runRuntimeGuard({
    target: 'https://example.com/preview',
    fetchFn: async () => response(statuses[call++]),
    lookupFn: publicLookup,
    workspace,
    enforce: true,
    minBlockRate: 100,
    comment: false
  });
  assert.equal(result.report.state, 'partial-block-signals');
  assert.equal(result.report.summary.passedThrough, 1);
  assert.equal(result.report.summary.blocked, 2);
  assert.equal(result.shouldFail, true);
});

test('auth-gated preview is inconclusive and does not fire probes', async () => {
  const workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'devshield-runtime-'));
  let calls = 0;
  const result = await runRuntimeGuard({
    target: 'https://example.com/preview',
    fetchFn: async () => { calls++; return response(401); },
    lookupFn: publicLookup,
    workspace,
    comment: false
  });
  assert.equal(calls, 1);
  assert.equal(result.report.state, 'inconclusive-auth-gated');
  assert.equal(result.report.summary.total, 0);
});


test('resolveRuntimeAddress returns a validated public address', async () => {
  const resolved = await resolveRuntimeAddress('https://example.com/preview', { lookupFn: publicLookup });
  assert.deepEqual(resolved, { address: '203.0.113.10', family: 4 });
});

test('Runtime Guard rejects DNS rebinding to a private address before connecting', async () => {
  const workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'devshield-runtime-'));
  let lookupCalls = 0;
  let requestCalls = 0;
  const lookupFn = async () => {
    lookupCalls++;
    return lookupCalls === 1
      ? [{ address: '203.0.113.10', family: 4 }]
      : [{ address: '127.0.0.1', family: 4 }];
  };

  const result = await runRuntimeGuard({
    target: 'https://example.com/preview',
    lookupFn,
    requestFn: async () => {
      requestCalls++;
      return { status: 200 };
    },
    workspace,
    enforce: true
  });

  assert.equal(requestCalls, 0);
  assert.equal(result.report.state, 'inconclusive-errors');
  assert.match(result.report.baseline.error, /private or non-routable/);
  assert.equal(result.report.policy.dnsPinning, true);
  assert.equal(result.shouldFail, true);
});

test('Runtime Guard passes the validated address to the pinned request transport', async () => {
  const workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'devshield-runtime-'));
  const resolvedAddresses = [];
  let calls = 0;
  const result = await runRuntimeGuard({
    target: 'https://example.com/preview',
    lookupFn: publicLookup,
    requestFn: async (_url, { resolved }) => {
      resolvedAddresses.push(resolved.address);
      return { status: calls++ === 0 ? 200 : 403 };
    },
    workspace
  });

  assert.deepEqual(resolvedAddresses, [
    '203.0.113.10',
    '203.0.113.10',
    '203.0.113.10',
    '203.0.113.10'
  ]);
  assert.equal(result.report.state, 'protected-signals');
  assert.equal(result.report.policy.dnsPinning, true);
});

test('custom fetch mode remains injectable and is marked as not DNS-pinned', async () => {
  const workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'devshield-runtime-'));
  const result = await runRuntimeGuard({
    target: 'https://example.com/preview',
    fetchFn: async () => response(401),
    lookupFn: publicLookup,
    workspace
  });
  assert.equal(result.report.policy.dnsPinning, false);
});


test('defenseSignals recognizes rate-limit and challenge headers', () => {
  const headers = {
    get: key => ({
      'cf-mitigated': 'challenge',
      'retry-after': '30',
      'ratelimit-remaining': '0'
    })[String(key).toLowerCase()] || null
  };
  const signals = defenseSignals(429, headers);
  assert(signals.includes('http-429'));
  assert(signals.includes('cloudflare-challenge'));
  assert(signals.includes('retry-after'));
  assert(signals.includes('rate-limit-exhausted'));
});

test('buildAbuseTarget only accepts same-origin absolute paths', () => {
  assert.equal(buildAbuseTarget('https://example.com/preview', '/api/login').toString(), 'https://example.com/api/login');
  assert.throws(() => buildAbuseTarget('https://example.com/preview', 'https://evil.example/x'), /same-origin absolute path/);
  assert.throws(() => buildAbuseTarget('https://example.com/preview', '//evil.example/x'), /same-origin absolute path/);
  assert.throws(() => buildAbuseTarget('https://example.com/preview', '/api/login?token=x'), /must not contain query/);
});

test('bounded abuse probe recognizes a rate-limit response without sending credentials', async () => {
  const workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'devshield-runtime-'));
  let calls = 0;
  const seen = [];
  const result = await runRuntimeGuard({
    target: 'https://example.com/preview',
    fetchFn: async (url, init) => {
      calls++;
      seen.push({ url: String(url), method: init?.method, body: init?.body });
      if (calls === 1) return response(200);
      if (calls <= 4) return response(403);
      if (calls === 5) return response(200);
      if (calls === 6) return response(200);
      return response(429, { 'retry-after': '60' });
    },
    lookupFn: publicLookup,
    workspace,
    abuseProbe: true,
    abusePath: '/api/login',
    abuseRequestCount: 3,
    abuseDelayMs: 100,
    sleepFn: async () => {}
  });

  assert.equal(result.report.abuse.state, 'rate-limit-signal');
  assert.equal(result.report.abuse.summary.total, 3);
  assert.equal(result.report.abuse.requests.at(-1).status, 429);
  assert(seen.every(x => x.method === 'GET'));
  assert(seen.every(x => x.body == null));
  assert(seen.some(x => x.url.includes('/api/login?__devshield_abuse_probe=')));
});

test('bounded abuse probe is capped at 10 sequential requests', async () => {
  const workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'devshield-runtime-'));
  let calls = 0;
  const result = await runRuntimeGuard({
    target: 'https://example.com/preview',
    fetchFn: async () => {
      calls++;
      return response(calls <= 4 ? (calls === 1 ? 200 : 403) : 200);
    },
    lookupFn: publicLookup,
    workspace,
    abuseProbe: true,
    abuseRequestCount: 1000,
    abuseDelayMs: 100,
    sleepFn: async () => {}
  });
  assert.equal(result.report.abuse.summary.total, 10);
});

test('abuse enforcement fails when no rate-limit, challenge, or block signal is observed', async () => {
  const workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'devshield-runtime-'));
  let calls = 0;
  const result = await runRuntimeGuard({
    target: 'https://example.com/preview',
    fetchFn: async () => response(calls++ === 0 ? 200 : calls <= 3 ? 403 : 200),
    lookupFn: publicLookup,
    workspace,
    abuseProbe: true,
    abuseRequestCount: 3,
    abuseDelayMs: 100,
    abuseEnforce: true,
    sleepFn: async () => {}
  });
  assert.equal(result.report.abuse.state, 'no-abuse-control-signal');
  assert.equal(result.shouldFail, true);
});
