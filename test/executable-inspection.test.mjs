import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { inspectPortableExecutable } from '../src/executable-inspection.mjs';
import { scanEndpoint, endpointSarif } from '../src/endpoint-shield.mjs';

// Entirely synthetic, non-executable metadata fixture; never compiled or run.
function mockPE({ writableCode = true, imported = true, corrupt = false } = {}) {
  const b = Buffer.alloc(0xA00);
  b.write('MZ', 0);
  b.writeUInt32LE(corrupt ? 0xffff0000 : 0x80, 0x3c);
  b.write('PE\u0000\u0000', 0x80, 'latin1');
  b.writeUInt16LE(0x14c, 0x84); // x86 machine
  b.writeUInt16LE(2, 0x86); // two sections
  b.writeUInt16LE(224, 0x94); // optional header length
  b.writeUInt16LE(0x10b, 0x98); // PE32
  b.writeUInt32LE(0x3000, 0x98 + 56);
  b.writeUInt32LE(0x200, 0x98 + 60);
  b.writeUInt32LE(16, 0x98 + 92);
  if (imported) {
    b.writeUInt32LE(0x2000, 0x98 + 96 + 8);
    b.writeUInt32LE(0x100, 0x98 + 96 + 12);
  }
  function section(at, name, virtualAddress, rawAt, flags) {
    b.write(name, at, 'ascii');
    b.writeUInt32LE(0x400, at + 8);
    b.writeUInt32LE(virtualAddress, at + 12);
    b.writeUInt32LE(0x400, at + 16);
    b.writeUInt32LE(rawAt, at + 20);
    b.writeUInt32LE(flags, at + 36);
  }
  section(0x178, '.text', 0x1000, 0x200,
    writableCode ? 0xE0000020 : 0x60000020);
  section(0x178 + 40, '.idata', 0x2000, 0x600, 0x40000040);
  b.fill(0x90, 0x200, 0x600); // benign placeholder bytes, not runnable code
  if (imported) {
    b.writeUInt32LE(0x2060, 0x600); // original thunk
    b.writeUInt32LE(0x2090, 0x600 + 12); // DLL name
    b.writeUInt32LE(0x2060, 0x600 + 16);
    b.writeUInt32LE(0x20B0, 0x660);
    b.writeUInt32LE(0x20D0, 0x664);
    b.write('KERNEL32.dll\u0000', 0x690, 'latin1');
    b.write('WriteProcessMemory\u0000', 0x6B2, 'latin1');
    b.write('CreateRemoteThread\u0000', 0x6D2, 'latin1');
    b.writeUInt16LE(0, 0x6B0);
    b.writeUInt16LE(0, 0x6D0);
  }
  return b;
}

test('PE32 import and section flags produce explainable triage only, no execution', () => {
  const p = inspectPortableExecutable(mockPE());
  assert.equal(p.format, 'PE32');
  assert.equal(p.machine, '0x14c');
  assert.equal(p.sectionCount, 2);
  assert.equal(p.importLibraryCount, 1);
  assert.equal(p.importFunctionCount, 2);
  assert.ok(p.findings.some(f => f.rule === 'pe-writable-executable-section' && f.severity === 'medium'));
  assert.ok(p.findings.some(f => f.rule === 'pe-remote-process-injection-apis' && f.severity === 'high'));
  assert.ok(!JSON.stringify(p).includes('KERNEL32.dll'), 'avoid exporting unreviewed embedded import strings');
});

test('ordinary PE code section is not classified as malicious without heuristics', () => {
  const p = inspectPortableExecutable(mockPE({ writableCode: false, imported: false }));
  assert.equal(p.format, 'PE32');
  assert.equal(p.findings.length, 0);
  assert.equal(p.suspiciousImportNames.length, 0);
});

test('reject malformed, out-of-bounds and unsupported executable headers', () => {
  assert.throws(() => inspectPortableExecutable(Buffer.from('not-an-exe')), /Truncated/);
  assert.throws(() => inspectPortableExecutable(mockPE({ corrupt: true })), /offset/);
  const invalid = mockPE();
  invalid.writeUInt32LE(0xFFFFFFF0, 0x178 + 20);
  assert.throws(() => inspectPortableExecutable(invalid), /section data/);
  const unsupported = mockPE();
  unsupported.writeUInt16LE(0x999, 0x98);
  assert.throws(() => inspectPortableExecutable(unsupported), /optional-header format/);
});

test('on-demand executable scan supports exe and renamed MZ binary, but fails closed on broken PE and ELF', () => {
  const folder = fs.mkdtempSync(path.join(os.tmpdir(), 'devshield-exe-static-'));
  try {
    fs.writeFileSync(path.join(folder, 'sample.exe'), mockPE());
    let report = scanEndpoint(path.join(folder, 'sample.exe'));
    assert.equal(report.complete, true);
    assert.equal(report.executablesInspected, 1);
    assert.equal(report.unsupportedExecutables, 0);
    assert.ok(report.findings.some(f => f.rule === 'pe-remote-process-injection-apis'));
    assert.equal(report.summary.detectsArbitraryMalware, false);
    assert.equal(report.summary.verifiesDigitalSignatures, false);
    assert.equal(report.summary.usesVirusSignatures, false);
    assert.equal(report.summary.status, 'suspicious');
    assert.equal(endpointSarif(report).runs[0].results.length, report.findings.length);
    fs.writeFileSync(path.join(folder, 'renamed.bin'), mockPE());
    report = scanEndpoint(path.join(folder, 'renamed.bin'));
    assert.equal(report.executablesInspected, 1);
    fs.writeFileSync(path.join(folder, 'broken.exe'), Buffer.from([0x4d, 0x5a, 0, 0]));
    report = scanEndpoint(path.join(folder, 'broken.exe'));
    assert.equal(report.complete, false);
    assert.equal(report.unsupportedExecutables, 1);
    assert.equal(report.errors[0].reason, 'invalid-or-unsupported-pe-executable');
    fs.writeFileSync(path.join(folder, 'linux.appimage'), Buffer.from([0x7f, 0x45, 0x4c, 0x46]));
    report = scanEndpoint(path.join(folder, 'linux.appimage'));
    assert.equal(report.complete, false);
    assert.equal(report.errors[0].reason, 'unsupported-binary-format');
  } finally { fs.rmSync(folder, { recursive: true, force: true }); }
});

test('recognizes embedded encoded PowerShell strings only as static indicators', () => {
  const b = mockPE({ writableCode: false, imported: false });
  b.write('powershell.exe -EncodedCommand QVJD', 0x250, 'latin1');
  const report = inspectPortableExecutable(b);
  assert.ok(report.findings.some(f => f.rule === 'pe-embedded-encoded-powershell'));
});
