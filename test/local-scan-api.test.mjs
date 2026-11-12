import assert from 'node:assert/strict';
import test from 'node:test';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { once } from 'node:events';
import { createLocalScanServer } from '../src/local-scan-server.mjs';
import { scanLocal, scanSarif } from '../src/local-scan-api.mjs';

const token = 'T'.repeat(48);
function setup() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'devshield-local-api-'));
  fs.writeFileSync(path.join(dir, 'run.ps1'), 'powershell.exe -EncodedCommand QUJD\n');
  fs.writeFileSync(path.join(dir, 'safe.js'), 'export const answer = 42;\n');
  fs.writeFileSync(path.join(dir, 'openapi.json'), JSON.stringify({ openapi: '3.0.3',
    info: { title: 'Test', version: '1.0' }, paths: { '/ping': { get: { responses: { 200: { description: 'ok' } } } } } }));
  return dir;
}

test('offline modes generate structured reports and SARIF; absence of lockfile is explicit', () => {
  const dir = setup();
  try {
    const preflight = scanLocal({ workspace: dir, mode: 'preflight' });
    assert.equal(preflight.execution, 'offline-read-only');
    assert.ok(preflight.findings.some(x => x.rule === 'powershell-encoded-command'));
    const sarif = scanSarif(preflight);
    assert.equal(sarif.version, '2.1.0');
    assert.ok(sarif.runs[0].results.length >= 1);
    assert.equal(scanLocal({ workspace: dir, mode: 'dependency-inventory' }).parts.dependencyInventory.status, 'not-present');
    assert.equal(scanLocal({ workspace: dir, mode: 'waap-policy' }).parts.waapPolicy.status, 'generated');
    const full = scanLocal({ workspace: dir, mode: 'full' });
    assert.ok(full.findings.length >= 1);
    assert.equal(full.parts.securityGraph.status === 'ready' || full.parts.securityGraph.status === 'empty', true);
    assert.throws(() => scanLocal({ workspace: dir, mode: 'unknown' }), /Unsupported/);
    assert.throws(() => scanLocal({ workspace: dir, mode: 'waap-policy', spec: '../outside.json' }), /Unsafe/);
  } finally { fs.rmSync(dir, { force: true, recursive: true }); }
});

test('loopback scan server requires bearer token and never accepts a caller filesystem root', async () => {
  const dir = setup();
  const server = createLocalScanServer({ workspace: dir, token });
  try {
    server.listen(0, '127.0.0.1');
    await once(server, 'listening');
    const url = 'http://127.0.0.1:' + server.address().port;
    let response = await fetch(url + '/v1/capabilities');
    assert.equal(response.status, 401);
    response = await fetch(url + '/v1/capabilities', {
      headers: { authorization: 'Bearer ' + token, origin: 'https://other.example' } });
    assert.equal(response.status, 403);
    response = await fetch(url + '/v1/capabilities', {
      headers: { authorization: 'Bearer ' + token } });
    assert.equal(response.status, 200);
    assert.equal((await response.json()).sourceUpload, false);
    response = await fetch(url + '/v1/scans/preflight', {
      method: 'POST', headers: { authorization: 'Bearer ' + token,
        'content-type': 'application/json' }, body: '{}' });
    assert.equal(response.status, 200);
    assert.ok((await response.json()).findings.length > 0);
    response = await fetch(url + '/v1/scans/preflight', {
      method: 'POST', headers: { authorization: 'Bearer ' + token,
        'content-type': 'application/json' }, body: JSON.stringify({ workspace: '/etc' }) });
    assert.equal(response.status, 422);
    response = await fetch(url + '/v1/scans/preflight', {
      method: 'POST', headers: { authorization: 'Bearer ' + token,
        'content-type': 'application/json' }, body: '{"format":"sarif"}' });
    assert.equal(response.status, 200);
    assert.equal((await response.json()).version, '2.1.0');
    response = await fetch(url + '/v1/scans/staged-diff', {
      method: 'POST', headers: { authorization: 'Bearer ' + token,
        'content-type': 'application/json' }, body: '{}' });
    assert.equal(response.status, 422, 'non-Git root cannot masquerade as staged diff');
  } finally {
    await new Promise(resolve => server.close(resolve));
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('symlinks and malformed/binary OpenAPI inputs are not scanned or read', () => {
  const dir = setup();
  const external = fs.mkdtempSync(path.join(os.tmpdir(), 'devshield-external-'));
  try {
    fs.writeFileSync(path.join(external, 'spec.json'), '{"openapi":"3.0.3","paths":{}}');
    fs.symlinkSync(path.join(external, 'spec.json'), path.join(dir, 'linked.json'));
    assert.throws(() => scanLocal({ workspace: dir, mode: 'waap-policy', spec: 'linked.json' }), /Symbolic/);
    fs.writeFileSync(path.join(dir, 'binary.json'), Buffer.from([0, 0, 0, 0]));
    assert.throws(() => scanLocal({ workspace: dir, mode: 'waap-policy', spec: 'binary.json' }), /Binary/);
  } finally { fs.rmSync(dir, { force: true, recursive: true }); fs.rmSync(external, { force: true, recursive: true }); }
});
