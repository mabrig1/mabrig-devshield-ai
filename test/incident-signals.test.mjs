import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, readFileSync, symlinkSync, statSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { analyzeIncidentSignals } from '../src/incident-signals.mjs';

test('detects the five video-derived risk categories without claiming breach', () => {
  const report = analyzeIncidentSignals({
    version: 1,
    events: [
      { kind: 'email', dailySent: 15000, baselineDailySent: 300 },
      { kind: 'outbound', approved: false, bytesOut: 9000000 },
      { kind: 'account', userReportedUnknownChange: true },
      { kind: 'process', approved: false, cpuPercent: 91 },
      { kind: 'redirect', expectedHost: 'app.example.org', observedHost: 'phishing.example.net' }
    ]
  });
  assert.equal(report.assessment, 'requires-review');
  assert.equal(report.findings.length, 5);
  assert.deepEqual(new Set(report.findings.map(item => item.rule)), new Set([
    'email-volume-spike', 'outbound-unapproved-transfer',
    'account-unrecognized-activity', 'process-unapproved-high-cpu', 'redirect-host-mismatch'
  ]));
  assert.equal(report.unassessedKinds.length, 0);
  assert.match(report.caveat, /not proof/);
});

test('known approved activity does not trigger warnings', () => {
  const report = analyzeIncidentSignals({
    version: 1,
    approvedRedirectHosts: ['payments.example.org'],
    events: [
      { kind: 'email', dailySent: 300, baselineDailySent: 300, unexpectedSender: false },
      { kind: 'outbound', approved: true, bytesOut: 9000000 },
      { kind: 'account', unrecognizedSession: false },
      { kind: 'process', approved: true, cpuPercent: 99 },
      { kind: 'redirect', expectedHost: 'app.example.org', observedHost: 'payments.example.org' }
    ]
  });
  assert.equal(report.assessment, 'no-alerts-in-supplied-data');
  assert.deepEqual(report.findings, []);
});

test('missing telemetry and small email sample never count as safe', () => {
  const report = analyzeIncidentSignals({ version: 1, events: [
    { kind: 'email', dailySent: 50, baselineDailySent: 1 }
  ] });
  assert.equal(report.assessment, 'insufficient-evidence');
  assert.deepEqual(report.unassessedKinds, ['email','outbound','account','process','redirect']);
});

test('aggregate only: never echo untrusted source, secrets or customer identifiers', () => {
  const secret = 'sensitive-private-token-and-email@example.net';
  const report = analyzeIncidentSignals({ version: 1, events: [
    { kind: 'outbound', approved: false, bytesOut: 20, destination: secret, authToken: secret },
    { kind: 'account', unrecognizedSession: true, customerEmail: secret }
  ] });
  assert.equal(JSON.stringify(report).includes(secret), false);
  assert.ok(report.findings.some(x => x.rule === 'outbound-unapproved-connection'));
});

test('reject malformed source and unsafe redirect policy', () => {
  assert.throws(() => analyzeIncidentSignals({ version: 2, events: [] }), /version 1/);
  assert.throws(() => analyzeIncidentSignals({ version: 1, events: [{ kind: 'secret' }] }), /supported kind/);
  assert.throws(() => analyzeIncidentSignals({
    version: 1, events: [], approvedRedirectHosts: ['*.example.com']
  }), /valid hostnames/);
  assert.throws(() => analyzeIncidentSignals({ version: 1, events: Array.from({ length: 5001 }, () => ({ kind: 'email' })) }), /5000/);
});

test('CLI runs offline and writes a private exclusive report; rejects symlink inputs', () => {
  const folder = mkdtempSync(join(tmpdir(), 'devshield-incident-'));
  try {
    const input = join(folder, 'input.json'), output = join(folder, 'report.json');
    writeFileSync(input, JSON.stringify({ version: 1, events: [
      { kind: 'redirect', expectedHost: 'app.example.org', observedHost: 'unexpected.example.org' }
    ] }));
    const cli = fileURLToPath(new URL('../bin/incident-signals.mjs', import.meta.url));
    const run = args => spawnSync(process.execPath, [cli, ...args], { encoding: 'utf8' });
    const result = run(['--input', input, '--output', output]);
    assert.equal(result.status, 0, result.stderr);
    assert.deepEqual(JSON.parse(readFileSync(output, 'utf8')).findings.map(f => f.rule), ['redirect-host-mismatch']);
    if (process.platform !== 'win32') assert.equal(statSync(output).mode & 0o777, 0o600);
    assert.equal(run(['--input', input, '--output', output]).status, 2, 'Never overwrite prior report');
    const link = join(folder, 'linked.json');
    symlinkSync(input, link);
    assert.equal(run(['--input', link]).status, 2);
  } finally {
    rmSync(folder, { recursive: true, force: true });
  }
});
