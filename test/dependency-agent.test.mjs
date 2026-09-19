import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  createDependencyMission,
  dependencyMissionMarkdown,
  loadWorkspaceDependencyEvidence
} from '../src/dependency-agent.mjs';

const sri = `sha512-${Buffer.alloc(64, 7).toString('base64')}`;

function workspace() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'devshield-dependency-agent-'));
}

function writeLock(root, packages) {
  fs.writeFileSync(path.join(root, 'package-lock.json'), JSON.stringify({
    lockfileVersion: 3,
    packages: {
      '': { name: 'app', dependencies: { risky: '1.0.0' } },
      ...packages
    }
  }));
}

test('links dependency-review evidence to direct application references without claiming exploitability', () => {
  const root = workspace();
  writeLock(root, {
    'node_modules/risky': {
      version: '1.0.0',
      resolved: 'https://registry.npmjs.org/risky/-/risky-1.0.0.tgz',
      integrity: sri,
      hasInstallScript: true
    }
  });
  fs.mkdirSync(path.join(root, 'src'));
  fs.writeFileSync(path.join(root, 'src/app.js'), "import risky from 'risky';\n");
  fs.mkdirSync(path.join(root, '.github/workflows'), { recursive: true });
  fs.writeFileSync(path.join(root, '.github/workflows/ci.yml'), 'name: ci\n');

  const evidence = loadWorkspaceDependencyEvidence({ workspace: root });
  const mission = createDependencyMission({
    workspace: root,
    evidence,
    repositoryFiles: ['src/app.js', '.github/workflows/ci.yml'],
    findings: [{
      rule: 'dependency-vulnerability',
      severity: 'high',
      category: 'dependencies',
      file: 'package-lock.json',
      line: 1,
      fingerprint: 'known-1',
      message: 'Known advisory',
      dependency: { name: 'risky', version: '1.0.0', advisoryGhsaId: 'GHSA-test' }
    }]
  });

  assert.equal(mission.summary.prioritizedPackages, 1);
  assert.equal(mission.priorityQueue[0].applicationReferences[0], 'src/app.js');
  assert.deepEqual(mission.priorityQueue[0].declaredByRoot, ['runtime']);
  assert.ok(mission.attackPaths.some(path => path.type === 'known-advisory-to-source-reference'));
  assert.equal(mission.guardrails.exploitabilityInference, false);
  assert.match(dependencyMissionMarkdown(mission), /without treating metadata gaps as vulnerabilities/i);
});

test('correlates insecure source metadata with CI as a heuristic, not a confirmed compromise', () => {
  const root = workspace();
  writeLock(root, {
    'node_modules/risky': {
      version: '1.0.0',
      resolved: 'http://registry.example/risky.tgz'
    }
  });
  fs.mkdirSync(path.join(root, '.github/workflows'), { recursive: true });
  fs.writeFileSync(path.join(root, '.github/workflows/ci.yml'), 'name: ci\n');

  const evidence = loadWorkspaceDependencyEvidence({ workspace: root });
  const mission = createDependencyMission({
    workspace: root,
    evidence,
    repositoryFiles: ['.github/workflows/ci.yml']
  });

  const pathItem = mission.attackPaths.find(path => path.type === 'insecure-source-to-ci-build');
  assert.equal(pathItem.confidence, 'heuristic');
  assert.match(pathItem.explanation, /not proved/i);
});

test('elevates lifecycle-script review when sensitive CI context exists', () => {
  const root = workspace();
  writeLock(root, {
    'node_modules/risky': {
      version: '1.0.0',
      resolved: 'https://registry.npmjs.org/risky/-/risky-1.0.0.tgz',
      integrity: sri,
      hasInstallScript: true
    }
  });
  fs.mkdirSync(path.join(root, '.github/workflows'), { recursive: true });
  fs.writeFileSync(path.join(root, '.github/workflows/ci.yml'), 'name: ci\n');

  const evidence = loadWorkspaceDependencyEvidence({ workspace: root });
  const mission = createDependencyMission({
    workspace: root,
    evidence,
    repositoryFiles: ['.github/workflows/ci.yml'],
    findings: [{
      rule: 'workflow-write-permissions',
      severity: 'high',
      category: 'ci-security',
      file: '.github/workflows/ci.yml',
      line: 1,
      fingerprint: 'ci-1',
      message: 'Sensitive CI permission'
    }]
  });

  const pathItem = mission.attackPaths.find(path => path.type === 'lifecycle-script-ci-execution-surface');
  assert.equal(pathItem.confidence, 'heuristic-elevated');
  assert.equal(mission.priorityQueue[0].installScript, 'declared');
});

test('missing and malformed lockfiles are explicit non-success states', () => {
  const root = workspace();
  let evidence = loadWorkspaceDependencyEvidence({ workspace: root });
  assert.equal(evidence.status, 'missing');
  let mission = createDependencyMission({ workspace: root, evidence });
  assert.equal(mission.state, 'no-lockfile');

  fs.writeFileSync(path.join(root, 'package-lock.json'), '{');
  evidence = loadWorkspaceDependencyEvidence({ workspace: root });
  assert.equal(evidence.status, 'invalid');
  mission = createDependencyMission({ workspace: root, evidence });
  assert.equal(mission.state, 'invalid-lockfile');
});

test('mission identity is stable for equivalent evidence and dependency findings', () => {
  const root = workspace();
  writeLock(root, {
    'node_modules/risky': {
      version: '1.0.0',
      resolved: 'http://registry.example/risky.tgz'
    }
  });
  const evidence = loadWorkspaceDependencyEvidence({ workspace: root });
  const finding = {
    rule: 'dependency-vulnerability',
    severity: 'medium',
    category: 'dependencies',
    file: 'package-lock.json',
    line: 1,
    fingerprint: 'stable-fingerprint',
    dependency: { name: 'risky', version: '1.0.0' }
  };
  const a = createDependencyMission({ workspace: root, evidence, findings: [finding] });
  const b = createDependencyMission({ workspace: root, evidence, findings: [finding] });
  assert.equal(a.missionId, b.missionId);
});

test('off mode emits no dependency mission work', () => {
  const root = workspace();
  const mission = createDependencyMission({ workspace: root, evidence: { status: 'missing' }, mode: 'off' });
  assert.equal(mission.state, 'disabled');
  assert.equal(mission.tasks.length, 0);
  assert.equal(mission.attackPaths.length, 0);
});
