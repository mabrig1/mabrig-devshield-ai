import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  createRepositorySecurityGraph,
  repositorySecurityGraphDot,
  repositorySecurityGraphMarkdown
} from '../src/security-graph.mjs';

function workspace() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'devshield-security-graph-'));
}

test('builds package -> module -> API route path from traceable imports', () => {
  const root = workspace();
  fs.mkdirSync(path.join(root, 'src/lib'), { recursive: true });
  fs.mkdirSync(path.join(root, 'src/api'), { recursive: true });
  fs.writeFileSync(path.join(root, 'src/lib/client.ts'), "import risky from 'risky';\nexport default risky;\n");
  fs.writeFileSync(path.join(root, 'src/api/users.ts'), "import client from '../lib/client';\nexport default client;\n");

  const dependencyMission = {
    priorityQueue: [{
      identity: 'pkg:npm/risky@1.0.0',
      name: 'risky',
      installName: 'risky',
      version: '1.0.0',
      declaredByRoot: ['runtime'],
      installScript: 'not-declared',
      applicationReferences: ['src/lib/client.ts'],
      metadataFindings: [],
      knownDependencyFindings: []
    }]
  };

  const graph = createRepositorySecurityGraph({
    workspace: root,
    repositoryFiles: ['src/lib/client.ts', 'src/api/users.ts'],
    dependencyMission
  });

  const api = graph.nodes.find(node => node.type === 'file' && node.attributes.path === 'src/api/users.ts');
  assert.equal(api.attributes.role, 'api-route');
  const pathItem = graph.paths.find(item => item.targetNode === api.id);
  assert.ok(pathItem);
  assert.equal(pathItem.confidence, 'evidence-linked');
  assert.equal(pathItem.edgeIds.length, 2);
});

test('connects a package to a finding on a consuming file without storing source snippets', () => {
  const root = workspace();
  fs.mkdirSync(path.join(root, 'src'));
  fs.writeFileSync(path.join(root, 'src/app.js'), "import risky from 'risky';\n");

  const dependencyMission = {
    priorityQueue: [{
      identity: 'pkg:npm/risky@1.0.0',
      name: 'risky',
      installName: 'risky',
      version: '1.0.0',
      applicationReferences: ['src/app.js'],
      metadataFindings: [],
      knownDependencyFindings: []
    }]
  };
  const findings = [{
    rule: 'hardcoded-secret',
    severity: 'critical',
    category: 'secrets',
    file: 'src/app.js',
    line: 7,
    fingerprint: 'secret-fingerprint'
  }];

  const graph = createRepositorySecurityGraph({
    workspace: root,
    repositoryFiles: ['src/app.js'],
    dependencyMission,
    findings
  });

  const finding = graph.nodes.find(node => node.type === 'finding');
  const pathItem = graph.paths.find(item => item.targetNode === finding.id);
  assert.ok(pathItem);
  assert.equal(pathItem.confidence, 'evidence-linked');
  assert.equal(JSON.stringify(graph).includes("import risky"), false);
  assert.equal(graph.guardrails.secretValuesStored, false);
});

test('workflow package-install edges are contextual and weaken path confidence', () => {
  const root = workspace();
  fs.mkdirSync(path.join(root, '.github/workflows'), { recursive: true });
  fs.writeFileSync(path.join(root, '.github/workflows/deploy.yml'), 'name: deploy\nsteps:\n  - run: npm ci\n  - run: vercel deploy\n');

  const dependencyMission = {
    priorityQueue: [{
      identity: 'pkg:npm/risky@1.0.0',
      name: 'risky',
      installName: 'risky',
      version: '1.0.0',
      applicationReferences: [],
      metadataFindings: [{ ruleId: 'dependency-integrity-metadata', severity: 'medium' }],
      knownDependencyFindings: []
    }]
  };
  const findings = [{
    rule: 'workflow-write-permissions',
    severity: 'high',
    category: 'ci-security',
    file: '.github/workflows/deploy.yml',
    line: 1,
    fingerprint: 'workflow-finding'
  }];

  const graph = createRepositorySecurityGraph({
    workspace: root,
    repositoryFiles: ['.github/workflows/deploy.yml'],
    dependencyMission,
    findings
  });

  const contextual = graph.edges.find(edge => edge.type === 'installation-context');
  assert.equal(contextual.confidence, 'contextual');
  const finding = graph.nodes.find(node => node.type === 'finding');
  const pathItem = graph.paths.find(item => item.targetNode === finding.id);
  assert.ok(pathItem);
  assert.equal(pathItem.confidence, 'contextual');
});

test('advisory nodes retain identifiers without inventing advisory content', () => {
  const root = workspace();
  const dependencyMission = {
    priorityQueue: [{
      identity: 'pkg:npm/risky@1.0.0',
      name: 'risky',
      installName: 'risky',
      version: '1.0.0',
      applicationReferences: [],
      metadataFindings: [],
      knownDependencyFindings: [{
        rule: 'dependency-vulnerability',
        severity: 'high',
        fingerprint: 'dep-1',
        dependency: { advisoryGhsaId: 'GHSA-xxxx-yyyy-zzzz', advisoryUrl: 'https://github.com/advisories/GHSA-xxxx-yyyy-zzzz' }
      }]
    }]
  };

  const graph = createRepositorySecurityGraph({ workspace: root, dependencyMission });
  const advisory = graph.nodes.find(node => node.type === 'advisory');
  assert.equal(advisory.attributes.ghsaId, 'GHSA-xxxx-yyyy-zzzz');
  assert.ok(graph.edges.some(edge => edge.type === 'has-advisory'));
});

test('graph identity is stable for equivalent evidence', () => {
  const root = workspace();
  fs.mkdirSync(path.join(root, 'src'));
  fs.writeFileSync(path.join(root, 'src/app.js'), "import risky from 'risky';\n");
  const dependencyMission = {
    priorityQueue: [{
      identity: 'pkg:npm/risky@1.0.0',
      name: 'risky',
      installName: 'risky',
      version: '1.0.0',
      applicationReferences: ['src/app.js'],
      metadataFindings: [],
      knownDependencyFindings: []
    }]
  };
  const args = { workspace: root, repositoryFiles: ['src/app.js'], dependencyMission };
  const a = createRepositorySecurityGraph(args);
  const b = createRepositorySecurityGraph(args);
  assert.equal(a.graphId, b.graphId);
});

test('off mode returns an empty graph', () => {
  const root = workspace();
  const graph = createRepositorySecurityGraph({ workspace: root, mode: 'off' });
  assert.equal(graph.state, 'disabled');
  assert.equal(graph.nodes.length, 0);
  assert.equal(graph.edges.length, 0);
});

test('markdown and DOT outputs omit source content and expose graph structure', () => {
  const root = workspace();
  const graph = createRepositorySecurityGraph({ workspace: root });
  assert.match(repositorySecurityGraphMarkdown(graph), /Repository security graph/);
  const dot = repositorySecurityGraphDot(graph);
  assert.match(dot, /^digraph DevShieldSecurityGraph/);
});
