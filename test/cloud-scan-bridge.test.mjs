import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { scanLocal } from '../src/local-scan-api.mjs';
import { buildCloudReport, cloudEndpoint, uploadCloudReport } from '../src/cloud-scan-bridge.mjs';
import { normalizeScan } from '../commercial-api/worker/src/index.mjs';

const key = 'dsc_test_' + 'a'.repeat(44);
const API = 'https://scanner.example.com';
const options = { repository: 'mabrig1/example', fingerprintKey: key, idempotencyKey: 'test-run-20261112-001' };

function tempFixture() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'devshield-bridge-'));
  fs.writeFileSync(path.join(dir, 'build.ps1'), 'powershell.exe -EncodedCommand QUJD\n');
  return dir;
}

test('cloud adapter emits validated schema but never raw source, filenames, paths, messages or graph data', () => {
  const dir = tempFixture();
  try {
    const scanned = scanLocal({ workspace: dir, mode: 'preflight' });
    assert.equal(scanned.complete, true);
    assert.ok(scanned.findings.length > 0);
    const prepared = buildCloudReport(scanned, options);
    const stored = normalizeScan(prepared.payload);
    assert.equal(stored.scanType, 'preflight');
    assert.equal(stored.repository.fullName, options.repository);
    assert.ok(stored.findings.length > 0);
    assert.equal(stored.findings[0].file, null);
    assert.equal(stored.findings[0].message, null);
    assert.equal(stored.findings[0].remediation, null);
    assert.ok(/^[0-9a-f]{64}$/.test(stored.findings[0].fingerprint));
    assert.equal(prepared.privacy.sourceUploaded, false);
    const json = JSON.stringify(prepared.payload);
    for (const fragment of ['build.ps1', 'powershell.exe', 'QUJD', 'file":"', '"graph":', '"waapPolicy":', key]) {
      assert.equal(json.includes(fragment), false, fragment);
    }
    assert.deepEqual(buildCloudReport(scanned, options).payload, prepared.payload);
    assert.notEqual(buildCloudReport(scanned, { ...options, fingerprintKey: 'dsc_test_' + 'b'.repeat(44) }).payload.findings[0].fingerprint,
      prepared.payload.findings[0].fingerprint, 'HMAC fingerprints must depend on the operator secret');
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('unsafe upload and incomplete scans fail closed before network', async () => {
  const dir = tempFixture();
  try {
    const scanned = scanLocal({ workspace: dir, mode: 'preflight' });
    assert.throws(() => buildCloudReport({ ...scanned, complete: false }, options), /incomplete/);
    assert.throws(() => buildCloudReport({ ...scanned, summary: { capped: true } }, options), /incomplete/);
    assert.throws(() => buildCloudReport(scanned, { ...options, fingerprintKey: 'bad' }), /HMAC/);
    assert.throws(() => buildCloudReport(scanned, { ...options, repository: '../../etc' }), /repository/);
    for (const origin of ['http://scanner.example.com', 'https://127.0.0.1', 'https://localhost',
      'https://scanner.example.com/attack', 'https://user:password@scanner.example.com',
      'https://scanner.example.com:444', 'https://scanner.example.com?token=a']) {
      assert.throws(() => cloudEndpoint(origin, scanned.mode), /HTTPS public DNS origin/, origin);
    }
    const prepared = buildCloudReport(scanned, options);
    let networkCalls = 0;
    const fetchImpl = async () => { networkCalls++; return new Response(JSON.stringify({ id: '1234' }), { status: 200 }); };
    await assert.rejects(uploadCloudReport(prepared, { origin: API, apiKey: 'incorrect', fetchImpl }), /API key/);
    assert.equal(networkCalls, 0);
    await assert.rejects(uploadCloudReport(prepared, { origin: API, apiKey: key, fetchImpl }), /Unexpected cloud response/);
    assert.equal(networkCalls, 1);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('opt-in uploader submits metadata over HTTPS with bounded request and idempotency', async () => {
  const dir = tempFixture();
  try {
    const prepared = buildCloudReport(scanLocal({ workspace: dir, mode: 'preflight' }), options);
    const calls = [];
    const fake = async (url, init) => {
      calls.push({ url, init });
      assert.equal(init.redirect, 'error');
      assert.equal(init.method, 'POST');
      assert.equal(init.headers['idempotency-key'], options.idempotencyKey);
      assert.equal(init.headers.authorization, 'Bearer ' + key);
      assert.equal(init.headers['content-type'], 'application/json');
      assert.equal(JSON.parse(init.body).findings[0].file, undefined);
      return new Response(JSON.stringify({ id: '9e654163-6b49-4c1d-b8df-4d0a2eaed953', status: 'created' }), { status: 201 });
    };
    const result = await uploadCloudReport(prepared, { origin: API, apiKey: key, fetchImpl: fake });
    assert.equal(result.status, 'created');
    assert.equal(calls.length, 1);
    assert.equal(calls[0].url, API + '/v1/scan-reports/preflight');
    await assert.rejects(uploadCloudReport(prepared, {
      origin: API, apiKey: key,
      fetchImpl: async () => new Response('do not show secrets', { status: 503 })
    }), /HTTP 503/);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('CLI runs entirely offline without a cloud key when --upload is absent', () => {
  const dir = tempFixture();
  try {
    const exe = new URL('../bin/cloud-scan.mjs', import.meta.url).pathname;
    const out = execFileSync(process.execPath, [exe, '--workspace', dir, '--mode', 'preflight'],
      { env: { ...process.env, DEVSHIELD_CLOUD_API_KEY: '' }, encoding: 'utf8', timeout: 10000 });
    const report = JSON.parse(out);
    assert.equal(report.execution, 'offline-read-only');
    assert.ok(report.findings.some(f => f.rule === 'powershell-encoded-command'));
    assert.ok(out.includes('build.ps1'), 'local output can keep full evidence');
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});


test('uploader refuses manually injected paths, source fields or altered report schema before sending', async () => {
  const dir = tempFixture();
  try {
    const prepared = buildCloudReport(scanLocal({ workspace: dir, mode: 'preflight' }), options);
    let attempts = 0;
    const fake = async () => { attempts++; return new Response('{}', { status: 201 }); };
    const withSource = structuredClone(prepared);
    withSource.payload.findings[0].source = 'secret raw source';
    await assert.rejects(uploadCloudReport(withSource, { origin: API, apiKey: key, fetchImpl: fake }), /Privacy contract/);
    const withPath = structuredClone(prepared);
    withPath.payload.findings[0].file = 'sensitive/private-project.js';
    await assert.rejects(uploadCloudReport(withPath, { origin: API, apiKey: key, fetchImpl: fake }), /Privacy contract/);
    const withKey = structuredClone(prepared);
    withKey.payload.apiKey = key;
    await assert.rejects(uploadCloudReport(withKey, { origin: API, apiKey: key, fetchImpl: fake }), /Privacy contract/);
    const withInvalidId = structuredClone(prepared);
    withInvalidId.idempotencyKey = 'bad';
    await assert.rejects(uploadCloudReport(withInvalidId, { origin: API, apiKey: key, fetchImpl: fake }), /idempotency/);
    assert.equal(attempts, 0, 'all privacy validation must run before network');
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});
