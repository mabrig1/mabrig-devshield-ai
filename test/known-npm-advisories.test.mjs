import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { createDependencyInventory } from '../src/dependency-inventory.mjs';
import {
  parseExactVersion, compareVersions, scanKnownNpmAdvisories,
  knownAdvisoriesSarif, knownAdvisoriesBlock, KNOWN_ADVISORIES, CATALOG_AS_OF
} from '../src/known-npm-advisories.mjs';

const bin = fileURLToPath(new URL('../bin/known-advisories.mjs', import.meta.url));
const sri = 'sha512-' + Buffer.alloc(64, 7).toString('base64');
const pkg = version => ({ version, resolved: 'https://registry.npmjs.org/pkg/-/pkg.tgz', integrity: sri });
const make = packages => JSON.stringify({ name: 'demo', lockfileVersion: 3, packages: {
  '': { dependencies: { next: '^16.4.0' } }, ...packages
} });
const scan = packages => scanKnownNpmAdvisories(createDependencyInventory(make(packages)));
const named = (report, id, name) => report.findings.filter(f => f.advisoryId === id && f.package === name);

test('exact SemVer and prerelease comparisons preserve boundaries', () => {
  assert.equal(compareVersions('16.4.0', '16.4.1'), -1);
  assert.equal(compareVersions('19.1.9', '19.1.10'), -1);
  assert.equal(compareVersions('1.4.0-beta.18', '1.4.0'), -1);
  assert.equal(compareVersions('1.4.0-beta.19', '1.4.0-beta.18'), 1);
  assert.equal(compareVersions('1.4.0-beta.9', '1.4.0-beta.18'), -1);
  assert.equal(compareVersions('1.4.0-beta.18', '1.4.0-beta.18+build.2'), 0);
  assert.equal(compareVersions('11.0.0-alpha.6', '11.0.0-alpha.5'), 1);
  for (const invalid of ['^16.4.0', 'v16.4.0', '16.4', '1.4.0-beta.018', '99999999999.0.0', '1.1.0/something']) {
    assert.equal(parseExactVersion(invalid), null);
  }
  assert.throws(() => compareVersions('nope', '1.0.0'));
});

test('November 2026 React RSC, Next.js and Mongoose affected versions are accurately detected', () => {
  const result = scan({
    'node_modules/next': pkg('16.4.0'),
    'node_modules/react-server-dom-webpack': pkg('19.2.8'),
    'node_modules/react-server-dom-parcel': pkg('19.0.9'),
    'node_modules/mongoose': pkg('8.24.2'),
    'node_modules/mongoose-v9': { ...pkg('9.9.2'), name: 'mongoose' },
    'node_modules/react': pkg('19.2.8')
  });
  assert.equal(named(result, 'GHSA-673q-mjm6-r5xr', 'next').length, 1);
  assert.equal(named(result, 'GHSA-2464-fhr4-w9xw', 'next').length, 1);
  assert.equal(named(result, 'GHSA-xqc2-xf4c-x3h3', 'react-server-dom-webpack').length, 1);
  assert.equal(named(result, 'GHSA-xqc2-xf4c-x3h3', 'react-server-dom-parcel').length, 0);
  assert.equal(named(result, 'GHSA-pcrw-h46h-c93h', 'mongoose').length, 1);
  assert.equal(result.summary.affectedInstallations, 3);
  assert.equal(result.findings.some(f => f.package === 'react'), false);
  assert.match(result.findings[0].preconditions, /Only|Affected|Relevant|Requires/);
  assert.equal(result.coverage.exploitabilityInferred, false);
});

test('Better Auth vulnerable beta, TanStack Start, Storybook and DOMPurify conditional checks', () => {
  const result = scan({
    'node_modules/better-auth': pkg('1.4.0-beta.18'),
    'node_modules/@tanstack/react-start': pkg('1.168.59'),
    'node_modules/@tanstack/start-server-core': pkg('1.169.39'),
    'node_modules/dompurify': pkg('3.4.16'),
    'node_modules/storybook': pkg('10.6.1'),
    'node_modules/@storybook/addon-mcp': pkg('10.6.2')
  });
  assert.equal(named(result, 'GHSA-965c-763c-88jm', 'better-auth').length, 1);
  assert.equal(named(result, 'GHSA-qx66-fv34-fjm8', '@tanstack/react-start').length, 1);
  assert.equal(named(result, 'GHSA-qx66-fv34-fjm8', '@tanstack/start-server-core').length, 0);
  assert.equal(named(result, 'GHSA-cg2g-xh64-v4q7', 'dompurify').length, 1);
  assert.equal(named(result, 'GHSA-f2ph-cmg5-wxc8', 'storybook').length, 1);
  assert.equal(named(result, 'GHSA-f2ph-cmg5-wxc8', '@storybook/addon-mcp').length, 0);
  assert.ok(result.findings.every(f => /https:\/\/github.com\/advisories\/GHSA-/.test(f.advisoryUrl)));
});

test('patched releases, unsupported packages and manifest-only range do not trigger findings', () => {
  const result = scan({
    'node_modules/next': pkg('16.4.1'),
    'node_modules/mongoose': pkg('9.9.2'),
    'node_modules/better-auth': pkg('1.7.7'),
    'node_modules/react-server-dom-turbopack': pkg('19.3.1'),
    'node_modules/dompurify': pkg('3.4.17'),
    'node_modules/@tanstack/vue-start': pkg('1.168.56'),
    'node_modules/storybook': pkg('10.6.2')
  });
  assert.equal(result.summary.advisoryMatches, 0);
  assert.equal(result.status, 'reviewed');
  assert.equal(result.coverage.packageSourceVerified, false);
  assert.equal(result.asOf, CATALOG_AS_OF);
  assert.equal(result.summary.catalogEntries, KNOWN_ADVISORIES.length);
  assert.equal(knownAdvisoriesBlock(result, 'critical'), false);
});

test('npm aliases, nested installations and workspace links are handled without leaking URLs or secrets', () => {
  const secret = 'DO_NOT_DISCLOSE_PRIVATE_TOKEN';
  const raw = make({
    'node_modules/alias': {
      ...pkg('16.4.0'), name: 'next',
      resolved: 'https://user:' + secret + '@example.com/' + secret + '?token=' + secret
    },
    'node_modules/foo/node_modules/next': pkg('16.4.0'),
    'node_modules/mongoose': { version: '8.24.2', resolved: 'file:../local' },
    'node_modules/linked': { link: true, name: 'react-server-dom-webpack', version: '19.2.8' },
    'node_modules/mongoose-unparsed': { name: 'mongoose', version: '^8.24.2' }
  });
  const report = scanKnownNpmAdvisories(createDependencyInventory(raw));
  assert.equal(report.summary.affectedInstallations, 2);
  assert.equal(report.summary.excludedLocalInstallations, 2);
  assert.equal(report.summary.unassessedCandidateVersions, 1);
  assert.equal(report.status, 'incomplete');
  assert.ok(report.findings.every(f => f.package === 'next'));
  assert.ok(!JSON.stringify(report).includes(secret));
  assert.ok(report.findings.every(f => f.evidence.jsonPointer.startsWith('/packages/')));
  assert.deepEqual(report, scanKnownNpmAdvisories(createDependencyInventory(raw)));
});

test('bounded reports make truncation explicit and fail closed in enforcement mode', () => {
  const inventory = createDependencyInventory(make({
    'node_modules/next': pkg('16.4.0'),
    'node_modules/better-auth': pkg('1.6.0')
  }));
  const report = scanKnownNpmAdvisories(inventory, { maxFindings: 1 });
  assert.equal(report.status, 'incomplete');
  assert.equal(report.summary.truncated, true);
  assert.equal(report.findings.length, 1);
  assert.equal(knownAdvisoriesBlock(report, 'none'), true);
  assert.throws(() => scanKnownNpmAdvisories(inventory, { maxFindings: 0 }));
  assert.throws(() => scanKnownNpmAdvisories({ packages: [] }));
});

test('SARIF includes advisory link, stable fingerprint and no pretend source line', () => {
  const report = scan({ 'node_modules/next': pkg('16.4.0') });
  const sarif = knownAdvisoriesSarif(report);
  assert.equal(sarif.version, '2.1.0');
  assert.equal(sarif.runs[0].results.length, 2);
  const r = sarif.runs[0].results[0];
  assert.equal(r.locations[0].physicalLocation.artifactLocation.uri, 'package-lock.json');
  assert.equal(r.locations[0].physicalLocation.region, undefined);
  assert.equal(r.properties.confidence, 'installed-lockfile-version-match-only');
  assert.equal(r.properties.exploitabilityAssessed, false);
});

test('CLI writes JSON+SARIF, advisory never blocks and enforce returns threshold status', t => {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), 'devshield-known-'));
  t.after(() => fs.rmSync(cwd, { recursive: true, force: true }));
  const run = (...args) => spawnSync(process.execPath, [bin, ...args], { cwd, encoding: 'utf8' });
  let r = run();
  assert.equal(r.status, 0);
  let report = JSON.parse(fs.readFileSync(path.join(cwd, '.devshield/known-advisories.json'), 'utf8'));
  assert.equal(report.status, 'not-present');
  assert.equal(run('--mode', 'enforce').status, 2);
  fs.writeFileSync(path.join(cwd, 'package-lock.json'), make({ 'node_modules/mongoose': pkg('8.24.2') }));
  assert.equal(run().status, 0);
  assert.equal(run('--mode', 'enforce', '--fail-on', 'critical').status, 1);
  report = JSON.parse(fs.readFileSync(path.join(cwd, '.devshield/known-advisories.json'), 'utf8'));
  assert.equal(report.summary.advisoryMatches, 1);
  const sarif = JSON.parse(fs.readFileSync(path.join(cwd, '.devshield/known-advisories.sarif'), 'utf8'));
  assert.equal(sarif.runs[0].results[0].ruleId, 'GHSA-pcrw-h46h-c93h');
  fs.writeFileSync(path.join(cwd, 'npm-shrinkwrap.json'), make({ 'node_modules/mongoose': pkg('8.24.3') }));
  assert.equal(run('--mode', 'enforce').status, 0, 'shrinkwrap must take precedence');
  assert.equal(run('--mode', 'surprise').status, 2);
  assert.equal(run('--lockfile', '../other').status, 2);
});

test('CLI rejects unsafe symlink input and report destinations', t => {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), 'devshield-unsafe-'));
  t.after(() => fs.rmSync(cwd, { recursive: true, force: true }));
  const run = (...args) => spawnSync(process.execPath, [bin, ...args], { cwd, encoding: 'utf8' });
  fs.writeFileSync(path.join(cwd, 'real.json'), make({ 'node_modules/mongoose': pkg('8.24.2') }));
  fs.symlinkSync('real.json', path.join(cwd, 'package-lock.json'));
  assert.equal(run('--mode', 'enforce').status, 2);
  fs.unlinkSync(path.join(cwd, 'package-lock.json'));
  fs.symlinkSync('real.json', path.join(cwd, '.devshield'));
  assert.equal(run('--mode', 'enforce', '--lockfile', 'real.json').status, 2);
});
