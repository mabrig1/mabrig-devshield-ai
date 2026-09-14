import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { createDependencyInventory, inventoryBlocks, inventoryMarkdown } from '../src/dependency-inventory.mjs';

const cli = fileURLToPath(new URL('../bin/inventory.mjs', import.meta.url));
const sri = `sha512-${Buffer.alloc(64, 7).toString('base64')}`;
const archive = { version: '1.2.3', resolved: 'https://registry.npmjs.org/sample/-/sample-1.2.3.tgz', integrity: sri, license: 'MIT' };
const lock = (packages, lockfileVersion = 3) => JSON.stringify({ lockfileVersion, packages: { '': { name: 'app' }, ...packages } });

test('npm v2/v3 retain nested and scoped packages, aliases and evidence', () => {
  for (const format of [2, 3]) {
    const raw = lock({ 'node_modules/@example/pkg': archive, 'node_modules/a/node_modules/b': { ...archive, version: '2.0.0' }, 'node_modules/alias': { ...archive, name: 'actual-package' } }, format);
    const result = createDependencyInventory(raw);
    assert.equal(result.summary.packages, 3);
    assert.equal(result.packages[0].packageUrl, 'pkg:npm/%40example/pkg@1.2.3');
    assert.equal(result.packages[2].name, 'actual-package');
    assert.equal(result.packages[0].evidence.jsonPointer, '/packages/node_modules~1@example~1pkg');
    assert.equal(result.packages[0].integrity.status, 'recorded-unverified');
    assert.equal(result.coverage.vulnerabilityCheck, 'not-performed');
    assert.equal(result.source.sha256.length, 64);
    assert.deepEqual(result, createDependencyInventory(raw));
    assert.match(inventoryMarkdown(result), /does not certify/);
  }
});

test('unsafe HTTP sources gate high; missing metadata gates medium; none never blocks', () => {
  const report = createDependencyInventory(lock({ 'node_modules/pkg': { version: '1.0.0', resolved: 'http://registry.example/pkg.tgz' } }));
  assert.equal(report.summary.bySeverity.high, 1);
  assert.equal(report.summary.bySeverity.medium, 1);
  assert.equal(report.summary.unknownLicenses, 1);
  assert.equal(inventoryBlocks(report, 'high'), true);
  assert.equal(inventoryBlocks(report, 'none'), false);
  assert.equal(inventoryBlocks(report, 'critical'), false);
  assert.throws(() => inventoryBlocks(report, 'typo'));
  const missing = createDependencyInventory(lock({ 'node_modules/pkg': { version: '1.0.0' } }));
  assert.equal(inventoryBlocks(missing, 'high'), false);
  assert.equal(inventoryBlocks(missing, 'medium'), true);
});

test('local links, workspaces and git sources are not falsely required to have tarball integrity', () => {
  const result = createDependencyInventory(lock({
    'node_modules/local': { version: '1.0.0', resolved: 'file:../local' },
    'node_modules/linked': { link: true, resolved: 'packages/linked' },
    'packages/linked': { name: 'linked', version: '1.0.0' },
    'node_modules/gitpkg': { resolved: 'git+ssh://git@example.com/pkg.git#abc' },
    'node_modules/scp': { resolved: 'git@example.com:pkg.git#abc' }
  }));
  assert.equal(result.findings.length, 0);
  assert.equal(result.packages.find(p => p.name === 'scp').source.kind, 'git');
  assert.equal(result.packages.find(p => p.name === 'local').integrity.status, 'not-applicable');
});

test('resolved credentials, query tokens and Git URL versions never enter reports', () => {
  const secret = 'PRIVATE_CREDENTIAL';
  const result = createDependencyInventory(lock({ 'node_modules/pkg': { ...archive, resolved: `https://user:${secret}@example.com/${secret}?token=${secret}#${secret}`, version: `git+https://user:${secret}@example.com/repo.git` } }));
  assert.equal(JSON.stringify(result).includes(secret), false);
  assert.equal(result.packages[0].version, null);
  assert.equal(result.packages[0].packageUrl, null);
});

test('reject malformed input and unsupported formats; detect malformed and weak SRI', () => {
  for (const raw of ['{', 'null', '[]', '{"lockfileVersion":1}', lock({ 'node_modules/pkg': null }), lock({ '../outside': {} })]) assert.throws(() => createDependencyInventory(raw));
  const result = createDependencyInventory(lock({
    'node_modules/invalid': { ...archive, integrity: 'sha512-not-a-digest' },
    'node_modules/short': { ...archive, integrity: 'sha512-YWJj' },
    'node_modules/weak': { ...archive, integrity: `sha1-${Buffer.alloc(20).toString('base64')}` }
  }));
  assert.equal(result.summary.bySeverity.medium, 2);
  assert.equal(result.summary.bySeverity.low, 1);
});

test('CLI writes reports before blocking, prefers shrinkwrap and returns input errors', t => {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), 'devshield-inventory-'));
  t.after(() => fs.rmSync(cwd, { recursive: true, force: true }));
  const run = (...args) => spawnSync(process.execPath, [cli, ...args], { cwd, encoding: 'utf8' });
  assert.equal(run().status, 2); // Missing is not reported as zero safe dependencies.
  fs.writeFileSync(path.join(cwd, 'package-lock.json'), lock({ 'node_modules/safe': archive }));
  assert.equal(run().status, 0);
  fs.writeFileSync(path.join(cwd, 'npm-shrinkwrap.json'), lock({ 'node_modules/risky': { version: '1.0.0', resolved: 'http://example.com/package.tgz' } }));
  assert.equal(run().status, 1);
  const report = JSON.parse(fs.readFileSync(path.join(cwd, '.devshield/dependency-inventory.json')));
  assert.equal(report.source.file, 'npm-shrinkwrap.json');
  assert.equal(report.summary.packages, 1);
  assert.equal(run('--fail-on', 'none').status, 0);
  assert.equal(run('--lockfile', 'package-lock.json').status, 0);
  const scanner = fileURLToPath(new URL('../bin/devshield.mjs', import.meta.url));
  const routed = spawnSync(process.execPath, [scanner, '--inventory', '--lockfile', 'package-lock.json'], { cwd, encoding: 'utf8' });
  assert.equal(routed.status, 0, routed.stderr);
  assert.match(routed.stdout, /dependency evidence/);
  assert.equal(run('--fail-on', 'typo').status, 2);
  assert.equal(run('--unknown', 'x').status, 2);
  assert.equal(run('--lockfile').status, 2);
  assert.equal(run('--report-dir', '../outside').status, 2);
  assert.equal(run('--lockfile', '.devshield/dependency-inventory.json').status, 2);
});

test('CLI refuses input and output symlinks and unsafe input overwrite', t => {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), 'devshield-paths-'));
  t.after(() => fs.rmSync(cwd, { recursive: true, force: true }));
  const run = (...args) => spawnSync(process.execPath, [cli, ...args], { cwd, encoding: 'utf8' });
  const raw = lock({ 'node_modules/pkg': archive });
  fs.writeFileSync(path.join(cwd, 'real.json'), raw);
  fs.symlinkSync('real.json', path.join(cwd, 'package-lock.json'));
  assert.equal(run().status, 2);
  fs.unlinkSync(path.join(cwd, 'package-lock.json'));
  fs.writeFileSync(path.join(cwd, 'package-lock.json'), raw);
  fs.mkdirSync(path.join(cwd, '.devshield'));
  fs.symlinkSync('../real.json', path.join(cwd, '.devshield/dependency-inventory.json'));
  assert.equal(run().status, 2);
  assert.equal(fs.readFileSync(path.join(cwd, 'real.json'), 'utf8'), raw);
  fs.unlinkSync(path.join(cwd, '.devshield/dependency-inventory.json'));
  fs.writeFileSync(path.join(cwd, '.devshield/dependency-inventory.json'), raw);
  assert.equal(run('--lockfile', '.devshield/dependency-inventory.json').status, 2);
  assert.equal(fs.readFileSync(path.join(cwd, '.devshield/dependency-inventory.json'), 'utf8'), raw);
});
