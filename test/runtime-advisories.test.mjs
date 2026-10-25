import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync, execFileSync } from 'node:child_process';
import { ADVISORY_SNAPSHOT, assessRuntimeVersion, auditRuntimeAdvisories } from '../src/runtime-advisories.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));
const audit = auditRuntimeAdvisories;

for (const [runtime, fixes] of Object.entries({ node: ADVISORY_SNAPSHOT.node.fixed, php: ADVISORY_SNAPSHOT.php.fixed })) {
  for (const fixed of Object.values(fixes)) {
    test(`${runtime} ${fixed}: patch boundary and later patch`, () => {
      const parts = fixed.split('.').map(Number);
      const before = [...parts.slice(0, 2), parts[2] - 1].join('.');
      const after = [...parts.slice(0, 2), parts[2] + 1].join('.');
      assert.equal(assessRuntimeVersion(runtime, before).status, 'below-fixed-release');
      assert.equal(assessRuntimeVersion(runtime, fixed).status, 'meets-listed-fix');
      assert.equal(assessRuntimeVersion(runtime, after).status, 'meets-listed-fix');
    });
  }
}

test('numeric comparison, upstream EOL, prereleases, ranges and unknown branches', () => {
  assert.equal(assessRuntimeVersion('node', '24.9.9').status, 'below-fixed-release');
  assert.equal(assessRuntimeVersion('node', 'v24.22.1').status, 'meets-listed-fix');
  for (const v of ['20.19.0', '23.1.0', '25.1.0']) assert.equal(assessRuntimeVersion('node', v).status, 'unsupported-release');
  assert.equal(assessRuntimeVersion('php', '8.1.34').status, 'unsupported-release');
  for (const v of ['24', '24.x', '>=24.22.1', '^24.22.1', '24.22.1-rc.1', '24.22.1+vendor', '28.0.0', '', null, '9007199254740992.1.0']) {
    assert.equal(assessRuntimeVersion('node', v).status, 'needs-verification');
  }
  assert.equal(assessRuntimeVersion('php', '8.6.0').status, 'needs-verification');
  assert.throws(() => assessRuntimeVersion('ruby', '3.0.0'));
});

test('PHP patch assessment retains the October 23 follow-up caveat', () => {
  const result = assessRuntimeVersion('php', '8.4.27');
  assert.match(result.followUp, /CVE-2026-115560/);
  assert.match(result.limitation, /Vendor backports/);
});

test('version files and tool-versions preserve location', () => {
  assert.equal(audit('.nvmrc', '# comment\n24.22.0\n')[0].line, 2);
  assert.equal(audit('api/.php-version', '8.4.26')[0].severity, 'critical');
  assert.equal(audit('.node-version', '24.22.1').length, 0);
  assert.deepEqual(audit('.tool-versions', 'python 3.12.0\nnodejs 24.22.0 # comment\nphp 8.3.35').map(x => x.line), [2, 3]);
  assert.equal(audit('.nvmrc', 'lts/*')[0].severity, 'medium');
});

test('JSON reads runtime keys, not a package named node or its own version', () => {
  assert.equal(audit('package.json', JSON.stringify({ version: '24.22.0', dependencies: { node: '24.22.0' } })).length, 0);
  assert.equal(audit('package.json', '{"volta/node":"24.22.0"}').length, 0);
  const content = '{\n"version":"24.22.0",\n"volta":{"node":\n"24.22.0"},\n"engines":{"node":">=24"}\n}';
  const findings = audit('app/package.json', content);
  assert.equal(findings[0].line, 4);
  assert.deepEqual(findings[0].relatedLines, [3]);
  assert.equal(findings[0].severity, 'high');
  assert.equal(findings[1].line, 5);
  assert.equal(findings[1].severity, 'medium');
  for (const value of ['24.22.0', '>=24.22.1', '^24.22.1 || ^26.12.1']) {
    assert.equal(audit('package.json', JSON.stringify({ engines: { node: value } }))[0].evidence.status, 'needs-verification');
  }
});

test('Composer compatibility/emulated platform is never proof of installed PHP', () => {
  for (const content of [{ require: { php: '^8.4' } }, { config: { platform: { php: '8.4.27' } } }]) {
    const finding = audit('composer.json', JSON.stringify(content))[0];
    assert.equal(finding.severity, 'medium');
    assert.equal(finding.evidence.deploymentVerified, false);
  }
});

test('malformed, escaped, nested and deeply nested JSON is bounded', () => {
  assert.deepEqual(audit('package.json', '{ "volta": '), []);
  assert.deepEqual(audit('package.json', '{"volta":{"node":"24.22.0","node":"24.22.1"}}'), []);
  assert.equal(audit('package.json', '{"volta":{"n\\u006fde":"24.22.0"}}')[0].severity, 'high');
  assert.deepEqual(audit('package.json', JSON.stringify({ nested: { volta: { node: '24.22.0' } }, array: [null, 1, true, {}] })), []);
  assert.deepEqual(audit('package.json', '['.repeat(100) + '0' + ']'.repeat(100)), []);
});

test('official multi-stage Docker images, SAPI variants and Compose images', () => {
  const issues = audit('Dockerfile', '# FROM php:8.4.26\nFROM --platform=linux/amd64 node:24.22.0-bookworm AS build\nFROM php:8.4.26-fpm-alpine\nFROM build AS final');
  assert.deepEqual(issues.map(x => [x.line, x.severity]), [[2, 'high'], [3, 'critical']]);
  assert.equal(audit('Containerfile', 'FROM docker.io/library/php:8.4.27-fpm').length, 0);
  assert.equal(audit('app.Dockerfile', 'FROM library/node:24.22.1-alpine3.23').length, 0);
  assert.equal(audit('compose.prod.yaml', 'services:\n app:\n  image: "node:24.22.0" # comment')[0].line, 3);
  assert.equal(audit('Dockerfile', 'FROM other/node:24.22.0').length, 0);
  assert.equal(audit('Dockerfile', 'FROM node:24.22.1-rc.1')[0].severity, 'medium');
  assert.equal(audit('Dockerfile', 'FROM node:${NODE_VERSION}')[0].severity, 'medium');
  assert.equal(audit('Dockerfile', 'FROM node:24.22.1@sha256:abc')[0].evidence.context, 'digest');
});

test('LiteLLM requirements distinguish exact artifact references from unresolved requirements', () => {
  assert.equal(audit('requirements.txt', 'litellm==1.107.0')[0].severity, 'critical');
  assert.equal(audit('requirements/prod.txt', 'litellm[proxy]==1.107.0; python_version > "3.10"')[0].severity, 'critical');
  assert.equal(audit('requirements-dev.in', 'litellm>=1.100.0')[0].severity, 'medium');
  assert.equal(audit('requirements.txt', 'litellm==1.106.2').length, 0);
  assert.equal(audit('requirements.txt', '# litellm==1.107.0\nnot-litellm==1.107.0').length, 0);
  assert.equal(audit('requirements.txt', 'litellm-other==1.107.0\nlitellm_proxy==1.107.0').length, 0);
  assert.equal(audit('README.md', 'litellm==1.107.0\nFROM php:8.4.26').length, 0);
});

test('LiteLLM mutable tags are review signals, matching digest is critical, source tag is excluded', () => {
  assert.equal(audit('compose.yml', 'image: ghcr.io/berriai/litellm:v1.107.0')[0].severity, 'critical');
  assert.equal(audit('compose.yml', 'image: ghcr.io/berriai/litellm:latest')[0].severity, 'medium');
  assert.equal(audit('Dockerfile', `FROM berriai/litellm@${ADVISORY_SNAPSHOT.litellm.imageDigest}`)[0].severity, 'critical');
  assert.equal(audit('Dockerfile', 'FROM ghcr.io/berriai/litellm:v1.107.0@sha256:abc')[0].severity, 'medium');
  assert.equal(audit('Dockerfile', 'RUN git clone --branch v1.107.0 https://github.com/BerriAI/litellm').length, 0);
});

test('PHP configuration review is conditional and ignores comments/disabled upload progress', () => {
  assert.equal(audit('php.ini', '; session.serialize_handler=php_binary').length, 0);
  assert.equal(audit('php.ini', 'session.serialize_handler=php').length, 0);
  assert.equal(audit('php.ini', 'session.serialize_handler=php_binary\nsession.serialize_handler=php').length, 0);
  assert.equal(audit('php.ini', 'session.serialize_handler=php_binary\nsession.upload_progress.enabled=0').length, 0);
  const issue = audit('php.ini', 'session.serialize_handler="php_serialize"\nsession.upload_progress.enabled=on')[0];
  assert.equal(issue.severity, 'medium');
  assert.match(issue.message, /additional prerequisite not established/);
  assert.deepEqual(issue.relatedLines, [2]);
  assert.equal(audit('php.ini', 'session.serialize_handler=php_binary\nsession.upload_progress.enabled=off\nsession.upload_progress.enabled=on').length, 1);
});

test('unresolved declarations and image digests have distinct private evidence hashes', () => {
  const first = audit('.nvmrc', '24.x')[0].evidence;
  const second = audit('.nvmrc', '26.x')[0].evidence;
  assert.notEqual(first.declarationHash, second.declarationHash);
  const a = audit('Dockerfile', 'FROM node:24.22.1@sha256:aaa')[0].evidence;
  const b = audit('Dockerfile', 'FROM node:24.22.1@sha256:bbb')[0].evidence;
  assert.notEqual(a.referenceHash, b.referenceHash);
});

function fixture(t, files) {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), 'devshield-advisories-'));
  t.after(() => fs.rmSync(cwd, { recursive: true, force: true }));
  const git = (...args) => execFileSync('git', args, { cwd, stdio: 'pipe' }).toString().trim();
  const write = (file, content) => { fs.mkdirSync(path.dirname(path.join(cwd, file)), { recursive: true }); fs.writeFileSync(path.join(cwd, file), content); };
  git('init', '-q'); git('config', 'user.name', 'DevShield Test'); git('config', 'user.email', 'test@example.invalid');
  for (const [file, content] of Object.entries(files)) write(file, content);
  git('add', '.'); git('commit', '-qm', 'fixture');
  const scan = (options = {}) => {
    const result = spawnSync(process.execPath, [path.join(root, 'src/index.mjs')], {
      cwd, encoding: 'utf8', timeout: 20000,
      env: { PATH: process.env.PATH, HOME: process.env.HOME, GITHUB_WORKSPACE: cwd,
        INPUT_SCAN_SCOPE: 'repository', INPUT_FAIL_ON: 'high', INPUT_COMMENT: 'false',
        INPUT_DEPENDENCY_REVIEW: 'false', INPUT_AGENTIC_MODE: 'off', INPUT_REMEDIATION_MODE: 'off',
        INPUT_DEPENDENCY_AGENTIC: 'off', INPUT_SECURITY_GRAPH: 'off', INPUT_CONTROL_PLANE: 'off',
        INPUT_SECURITY_HISTORY: 'off', INPUT_RISK_EXCEPTIONS: 'off', INPUT_LEGAL_COMPLIANCE: 'off',
        ...options }
    });
    assert.ifError(result.error);
    assert.ok(fs.existsSync(path.join(cwd, '.devshield/devshield-report.json')), result.stderr + result.stdout);
    return { ...result, report: JSON.parse(fs.readFileSync(path.join(cwd, '.devshield/devshield-report.json'))), sarif: JSON.parse(fs.readFileSync(path.join(cwd, '.devshield/devshield.sarif'))) };
  };
  return { cwd, git, write, scan };
}

test('main scanner gates exact declarations, emits source metadata in JSON/SARIF and aligned version', t => {
  const f = fixture(t, { Dockerfile: 'FROM php:8.4.26\n' });
  const result = f.scan();
  assert.equal(result.status, 1);
  assert.equal(result.report.runtimeAdvisorySnapshot, '2026-10-25');
  assert.equal(result.report.tool.version, JSON.parse(fs.readFileSync(path.join(root, 'package.json'))).version);
  const finding = result.report.findings.find(x => x.rule === 'php-october-2026-runtime');
  assert.equal(finding.severity, 'critical');
  assert.equal(finding.runtimeAdvisory.deploymentVerified, false);
  assert.match(result.sarif.runs[0].results[0].properties.runtimeAdvisory.source, /php.net/);
});

test('policy, ignore rules, severity overrides and baseline work with new findings', t => {
  const f = fixture(t, { '.node-version': '24.22.0\n' });
  assert.equal(f.scan({ INPUT_POLICY: 'secrets-only' }).report.findings.length, 0);
  f.write('.devshield.json', JSON.stringify({ ignoreRules: ['node-october-2026-runtime'] }));
  assert.equal(f.scan().report.findings.length, 0);
  f.write('.devshield.json', JSON.stringify({ severityOverrides: { 'node-october-2026-runtime': 'low' } }));
  assert.equal(f.scan().status, 0);
  f.write('.devshield.json', '{}');
  const initial = f.scan();
  assert.equal(initial.status, 1);
  fs.copyFileSync(path.join(f.cwd, '.devshield/devshield-baseline.json'), path.join(f.cwd, '.devshield-baseline.json'));
  f.write('.node-version', '# moved\n24.22.0\n');
  assert.equal(f.scan().status, 0);
  assert.equal(f.scan({ INPUT_BASELINE_MODE: 'off' }).status, 1);
});

test('critical cannot be suppressed inline; high can', t => {
  const f = fixture(t, { Dockerfile: '# devshield:ignore php-october-2026-runtime\nFROM php:8.4.26\n', '.nvmrc': '# devshield:ignore node-october-2026-runtime\n24.22.0\n' });
  const findings = f.scan().report.findings;
  assert.ok(findings.some(x => x.rule === 'php-october-2026-runtime'));
  assert.ok(!findings.some(x => x.rule === 'node-october-2026-runtime'));
});

test('staged mode reads the index, not a different working-tree runtime', t => {
  const f = fixture(t, { '.node-version': '24.22.1\n' });
  f.write('.node-version', '24.22.0\n'); f.git('add', '.node-version');
  f.write('.node-version', '24.22.1\n');
  assert.equal(f.scan({ INPUT_SCAN_SCOPE: 'staged' }).status, 1);
  f.git('reset', '--hard', 'HEAD');
  f.write('.node-version', '24.22.2\n'); f.git('add', '.node-version');
  f.write('.node-version', '24.22.0\n');
  assert.equal(f.scan({ INPUT_SCAN_SCOPE: 'staged' }).report.findings.length, 0);
});

test('changed-line scan locates duplicate JSON scalar correctly and ignores untouched findings', t => {
  const original = '{\n"version":"24.22.0",\n"volta":{"node":\n"24.22.1"}\n}\n';
  const f = fixture(t, { 'package.json': original, '.php-version': '8.4.26\n' });
  f.write('package.json', original.replace('24.22.1', '24.22.0'));
  f.git('add', 'package.json'); f.git('commit', '-qm', 'runtime regression');
  const result = f.scan({ INPUT_SCAN_SCOPE: 'changed-lines' });
  assert.equal(result.report.findings.length, 1);
  assert.equal(result.report.findings[0].line, 4);
  assert.equal(result.report.findings[0].rule, 'node-october-2026-runtime');
});

test('excluded paths do not contribute runtime findings', t => {
  const f = fixture(t, { 'legacy/.php-version': '8.4.26\n' });
  assert.equal(f.scan({ INPUT_EXCLUDE_PATHS: 'legacy/**' }).report.findings.length, 0);
});

test('baseline does not hide a changed unresolved version declaration', t => {
  const f = fixture(t, { '.nvmrc': '24.x\n' });
  const initial = f.scan();
  fs.copyFileSync(path.join(f.cwd, '.devshield/devshield-baseline.json'), path.join(f.cwd, '.devshield-baseline.json'));
  assert.equal(f.scan().report.findings[0].status, 'existing');
  f.write('.nvmrc', '26.x\n');
  const updated = f.scan().report.findings[0];
  assert.equal(updated.status, 'new');
  assert.notEqual(updated.fingerprint, initial.report.findings[0].fingerprint);
});

test('version CLI thresholds, evidence labels, dispatch and invalid arguments', () => {
  const run = (...args) => spawnSync(process.execPath, [path.join(root, 'bin/devshield.mjs'), '--runtime-advisories', ...args], { encoding: 'utf8' });
  const vulnerable = run('--node-version', '24.22.0');
  assert.equal(vulnerable.status, 1);
  assert.equal(JSON.parse(vulnerable.stdout).assessments[0].evidenceSource, 'operator-supplied-version');
  assert.equal(run('--node-version', '24.22.0', '--fail-on', 'critical').status, 0);
  assert.equal(run('--php-version', '8.4.26', '--fail-on', 'critical').status, 1);
  assert.equal(run('--node-version', '24.22.1', '--php-version', '8.4.27').status, 0);
  assert.equal(JSON.parse(run('--fail-on', 'none').stdout).assessments[0].evidenceSource, 'local-scanner-process');
  for (const args of [['--node-version'], ['--php-version', '8.4'], ['--node-version', '24.22.1-rc.1'], ['--fail-on', 'banana'], ['--url', 'https://example.invalid']]) assert.equal(run(...args).status, 2);
});
