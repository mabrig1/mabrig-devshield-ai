import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  appendSecurityHistory,
  classifySecurityRegression,
  createRiskExposureSnapshot,
  graphDigest,
  loadSecurityHistory,
  validateSecurityHistory
} from '../src/security-history.mjs';

function file(id, rel) {
  return { id, type: 'file', label: rel, attributes: { path: rel, role: 'source' } };
}
function finding(id, rel, severity = 'high') {
  return { id, type: 'finding', label: severity + ' issue', attributes: { file: rel, severity, rule: 'test-rule', fingerprint: id } };
}
function edge(id, from, to, confidence = 'direct') {
  return { id, from, to, type: 'test-edge', confidence, evidence: [{ kind: 'test' }] };
}
function graph(nodes, edges, id = 'g') {
  return { schemaVersion: 1, graphId: id, state: 'ready', nodes, edges, paths: [] };
}

test('graph digest is stable across generatedAt changes', () => {
  const a = { ...graph([file('f', 'src/a.js')], [], 'same'), generatedAt: '2026-01-01T00:00:00Z' };
  const b = { ...graph([file('f', 'src/a.js')], [], 'same'), generatedAt: '2027-01-01T00:00:00Z' };
  assert.equal(graphDigest(a), graphDigest(b));
});

test('classifies new risk, expanded exposure, reduced exposure, and inherited debt', () => {
  const previous = {
    maxDepth: 4,
    items: [
      { nodeId: 'same-expand', type: 'finding', severity: 'high', exposure: { reachableNodes: 1 } },
      { nodeId: 'same-reduce', type: 'finding', severity: 'medium', exposure: { reachableNodes: 3 } },
      { nodeId: 'same-stable', type: 'finding', severity: 'low', exposure: { reachableNodes: 2 } },
      { nodeId: 'gone', type: 'finding', severity: 'high', exposure: { reachableNodes: 1 } }
    ]
  };
  const current = {
    maxDepth: 4,
    items: [
      { nodeId: 'same-expand', type: 'finding', severity: 'high', exposure: { reachableNodes: 4 } },
      { nodeId: 'same-reduce', type: 'finding', severity: 'medium', exposure: { reachableNodes: 1 } },
      { nodeId: 'same-stable', type: 'finding', severity: 'low', exposure: { reachableNodes: 2 } },
      { nodeId: 'new', type: 'advisory', severity: 'critical', exposure: { reachableNodes: 2 } }
    ]
  };
  const result = classifySecurityRegression(current, previous);
  assert.equal(result.state, 'regression');
  assert.equal(result.summary.newRisk, 1);
  assert.equal(result.summary.expandedExposure, 1);
  assert.equal(result.summary.reducedExposure, 1);
  assert.equal(result.summary.resolvedRisk, 1);
  assert.equal(result.summary.unchangedInheritedDebt, 1);
});

test('creates a valid hash chain without claiming a signature', () => {
  const g = graph([file('f', 'src/a.js'), finding('x', 'src/a.js')], [edge('e', 'f', 'x')]);
  const first = appendSecurityHistory({ graph: g, controlPlane: { controlPlaneId: 'c1', summary: {}, blastRadius: { summary: {} } }, recordedAt: '2026-09-19T00:00:00Z' });
  assert.equal(first.history.seal.signed, false);
  assert.equal(first.entry.signature, null);
  assert.equal(validateSecurityHistory(first.history).valid, true);

  const second = appendSecurityHistory({
    graph: g,
    controlPlane: { controlPlaneId: 'c2', summary: {}, blastRadius: { summary: {} } },
    loadedHistory: { status: 'loaded', history: first.history },
    recordedAt: '2026-09-19T01:00:00Z'
  });
  assert.equal(second.entry.previousEntryHash, first.entry.entryHash);
  assert.equal(validateSecurityHistory(second.history).valid, true);
});

test('HMAC signatures verify and fail with a wrong key', () => {
  const g = graph([finding('x', 'src/a.js')], []);
  const result = appendSecurityHistory({ graph: g, controlPlane: { controlPlaneId: 'c', summary: {}, blastRadius: { summary: {} } }, signingKey: 'secret-key', recordedAt: '2026-09-19T00:00:00Z' });
  assert.equal(result.history.seal.signed, true);
  assert.equal(validateSecurityHistory(result.history, { signingKey: 'secret-key' }).signatures, 'verified');
  assert.equal(validateSecurityHistory(result.history, { signingKey: 'wrong-key' }).valid, false);
});

test('tampering with an entry breaks hash-chain validation', () => {
  const g = graph([finding('x', 'src/a.js')], []);
  const result = appendSecurityHistory({ graph: g, controlPlane: { controlPlaneId: 'c', summary: {}, blastRadius: { summary: {} } }, recordedAt: '2026-09-19T00:00:00Z' });
  result.history.entries[0].graphId = 'tampered';
  const validation = validateSecurityHistory(result.history);
  assert.equal(validation.valid, false);
  assert.equal(validation.integrity, 'hash-mismatch');
});

test('loads committed history only when integrity validates', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'devshield-history-'));
  const g = graph([finding('x', 'src/a.js')], []);
  const result = appendSecurityHistory({ graph: g, controlPlane: { controlPlaneId: 'c', summary: {}, blastRadius: { summary: {} } }, recordedAt: '2026-09-19T00:00:00Z' });
  fs.writeFileSync(path.join(root, '.devshield-security-history.json'), JSON.stringify(result.history));
  const loaded = loadSecurityHistory({ workspace: root });
  assert.equal(loaded.status, 'loaded');
  assert.equal(loaded.validation.integrity, 'valid');
});

test('risk exposure snapshot counts graph neighborhood around findings and advisories', () => {
  const g = graph([finding('x', 'src/a.js'), file('f', 'src/a.js'), file('g', 'src/b.js')], [edge('e1', 'x', 'f'), edge('e2', 'f', 'g')]);
  const snapshot = createRiskExposureSnapshot(g);
  assert.equal(snapshot.riskNodes, 1);
  assert.equal(snapshot.items[0].exposure.reachableNodes, 2);
});
