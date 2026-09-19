import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { calculateBlastRadius, createSecurityControlPlane, diffSecurityGraphs, loadCodeowners, ownerHintForFile, propagateReviewPriority, verifyRemediationObservations } from '../src/control-plane.mjs';

function graph({ nodes = [], edges = [], paths = [], graphId = 'g' } = {}) {
  return { schemaVersion: 1, graphId, state: 'ready', nodes, edges, paths };
}
function file(id, rel, role = 'source') {
  return { id, type: 'file', label: rel, attributes: { path: rel, role } };
}
function finding(id, rel, severity = 'high', rule = 'test-rule') {
  return { id, type: 'finding', label: severity + ' ' + rule, attributes: { file: rel, severity, rule, fingerprint: id } };
}
function edge(id, from, to, confidence = 'direct') {
  return { id, from, to, type: 'test-edge', confidence, evidence: [{ kind: 'test' }] };
}

test('diffs stable graph identities and counts new/resolved findings', () => {
  const before = graph({ graphId: 'before', nodes: [file('f1', 'src/a.js'), finding('old-find', 'src/a.js')], edges: [edge('e1', 'f1', 'old-find')], paths: [{ id: 'p1' }] });
  const after = graph({ graphId: 'after', nodes: [file('f1', 'src/a.js'), finding('new-find', 'src/a.js', 'critical')], edges: [edge('e2', 'f1', 'new-find')], paths: [{ id: 'p2' }] });
  const diff = diffSecurityGraphs(after, before);
  assert.equal(diff.status, 'compared');
  assert.equal(diff.summary.resolvedFindings, 1);
  assert.equal(diff.summary.newFindings, 1);
});

test('blast radius preserves contextual confidence', () => {
  const g = graph({ nodes: [file('a', 'src/a.js'), file('b', 'src/b.js'), finding('x', 'src/b.js')], edges: [edge('ab', 'a', 'b'), edge('bx', 'b', 'x', 'contextual')] });
  const blast = calculateBlastRadius(g, ['src/a.js']);
  const target = blast.impacted.find(item => item.nodeId === 'x');
  assert.equal(target.depth, 2);
  assert.equal(target.confidence, 'contextual');
});

test('review priority propagates severity with decay without claiming exploit probability', () => {
  const g = graph({ nodes: [file('a', 'src/a.js'), finding('x', 'src/a.js', 'critical')], edges: [edge('ax', 'a', 'x')] });
  const priority = propagateReviewPriority(g);
  assert.equal(priority.ranked[0].score, 100);
  assert.equal(priority.ranked.find(item => item.nodeId === 'a').score, 72);
  assert.match(priority.methodology, /not exploit probability/i);
});

test('CODEOWNERS last match wins as a best-effort hint', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'devshield-codeowners-'));
  fs.mkdirSync(path.join(root, '.github'), { recursive: true });
  fs.writeFileSync(path.join(root, '.github/CODEOWNERS'), '* @default\nsrc/** @platform\nsrc/api/** @api\n');
  const ownership = loadCodeowners({ workspace: root });
  assert.deepEqual(ownerHintForFile('src/api/users.ts', ownership).owners, ['@api']);
  assert.deepEqual(ownerHintForFile('src/lib/x.ts', ownership).owners, ['@platform']);
});

test('remediation verification reports observed state without claiming proof', () => {
  const g = graph({ nodes: [file('a', 'src/a.js'), finding('x', 'src/a.js', 'high', 'debug-mode')], edges: [edge('ax', 'a', 'x')] });
  const plan = { candidates: [{ id: 'fix-01', rule: 'debug-mode', file: 'src/a.js', line: 1 }, { id: 'fix-02', rule: 'disabled-tls', file: 'src/tls.js', line: 2 }] };
  const verification = verifyRemediationObservations(g, plan);
  assert.equal(verification.summary.stillObserved, 1);
  assert.equal(verification.summary.notObserved, 1);
  assert.match(verification.candidates[1].note, /not proof/i);
});

test('control plane combines graph diff, blast radius, ownership and priority', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'devshield-control-plane-'));
  fs.writeFileSync(path.join(root, 'CODEOWNERS'), 'src/** @security\n');
  const current = graph({ graphId: 'current', nodes: [file('a', 'src/a.js'), finding('x', 'src/a.js', 'critical')], edges: [edge('ax', 'a', 'x')] });
  const control = createSecurityControlPlane({ graph: current, baseline: { status: 'missing', graph: null }, changedFiles: ['src/a.js'], ownership: loadCodeowners({ workspace: root }) });
  assert.equal(control.state, 'ready');
  assert.equal(control.blastRadius.summary.findings, 1);
  assert.deepEqual(control.ownership.hints[0].owners, ['@security']);
  assert.equal(control.reviewPriority.ranked[0].score, 100);
});

test('off mode emits no active control-plane analysis', () => {
  const control = createSecurityControlPlane({ graph: graph(), mode: 'off' });
  assert.equal(control.state, 'disabled');
  assert.equal(control.summary.blastRadiusNodes, 0);
});
