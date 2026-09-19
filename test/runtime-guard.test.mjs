import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { isPrivateIp, runRuntimeGuard, sanitizeTarget, validateRuntimeTarget } from '../src/runtime-guard.mjs';

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
