import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  applyRiskExceptions,
  classifyRiskExceptionLifecycle,
  createRiskExceptionSnapshot,
  loadRiskExceptions
} from '../src/risk-exceptions.mjs';

function workspace() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'devshield-exceptions-'));
}
function write(root, value) {
  fs.writeFileSync(path.join(root, '.devshield-exceptions.json'), JSON.stringify(value, null, 2));
}
function history(regression) {
  return { regression };
}
function graph(paths = [], nodes = []) {
  return { nodes, paths };
}

test('loads active exceptions and automatically expires past entries', () => {
  const root = workspace();
  write(root, {
    schemaVersion: 1,
    exceptions: [
      {
        id: 'risk-001',
        owner: '@alice',
        rationale: 'Temporary mitigation while dependency upgrade is validated.',
        reviewedAt: '2026-09-01T00:00:00Z',
        expiresAt: '2026-10-01T00:00:00Z',
        scope: { findingFingerprints: ['aaaaaaaaaaaaaaaa'], graphPathIds: [] }
      },
      {
        id: 'risk-002',
        owner: '@bob',
        rationale: 'Legacy endpoint scheduled for removal after migration.',
        reviewedAt: '2026-08-01T00:00:00Z',
        expiresAt: '2026-09-10T00:00:00Z',
        scope: { findingFingerprints: ['bbbbbbbbbbbbbbbb'], graphPathIds: [] }
      }
    ]
  });
  const result = loadRiskExceptions({ workspace: root, now: '2026-09-19T00:00:00Z', maxDays: 90 });
  assert.equal(result.active.length, 1);
  assert.equal(result.expired.length, 1);
  assert.equal(result.active[0].id, 'risk-001');
});

test('rejects malformed, unscoped and overlong risk acceptance', () => {
  const root = workspace();
  write(root, {
    schemaVersion: 1,
    exceptions: [{
      id: 'x',
      owner: '',
      rationale: 'short',
      reviewedAt: '2026-09-01T00:00:00Z',
      expiresAt: '2027-09-01T00:00:00Z',
      scope: { findingFingerprints: [], graphPathIds: [] }
    }]
  });
  const result = loadRiskExceptions({ workspace: root, now: '2026-09-19T00:00:00Z', maxDays: 90 });
  assert.equal(result.invalid.length, 1);
  assert.ok(result.invalid[0].errors.includes('max-duration'));
  assert.ok(result.invalid[0].errors.includes('scope'));
});

test('applies a fingerprint exception to non-critical regression only', () => {
  const exceptionsResult = {
    active: [{
      id: 'risk-001',
      expiresAt: '2026-10-01T00:00:00Z',
      scope: { findingFingerprints: ['aaaaaaaaaaaaaaaa'], graphPathIds: [] }
    }],
    expired: [],
    invalid: [],
    all: []
  };
  const regression = {
    status: 'compared',
    state: 'regression',
    summary: { newRisk: 2, resolvedRisk: 0, expandedExposure: 0, reducedExposure: 0, unchangedInheritedDebt: 0 },
    newRisk: [
      { nodeId: 'n1', fingerprint: 'aaaaaaaaaaaaaaaa', severity: 'high' },
      { nodeId: 'n2', fingerprint: 'bbbbbbbbbbbbbbbb', severity: 'critical' }
    ],
    resolvedRisk: [],
    expandedExposure: [],
    reducedExposure: [],
    unchangedInheritedDebt: []
  };
  const result = applyRiskExceptions({
    exceptionsResult,
    securityHistoryResult: history(regression),
    securityGraph: graph()
  });
  assert.equal(result.effectiveRegression.summary.newRisk, 1);
  assert.equal(result.applications.length, 1);
  assert.equal(result.effectiveRegression.newRisk[0].nodeId, 'n2');
});

test('critical matching risk is not accepted unless explicitly enabled', () => {
  const exceptionsResult = {
    active: [{
      id: 'risk-critical',
      expiresAt: '2026-10-01T00:00:00Z',
      scope: { findingFingerprints: ['cccccccccccccccc'], graphPathIds: [] }
    }],
    expired: [],
    invalid: [],
    all: []
  };
  const regression = {
    status: 'compared',
    state: 'regression',
    summary: { newRisk: 1, resolvedRisk: 0, expandedExposure: 0, reducedExposure: 0, unchangedInheritedDebt: 0 },
    newRisk: [{ nodeId: 'n1', fingerprint: 'cccccccccccccccc', severity: 'critical' }],
    resolvedRisk: [], expandedExposure: [], reducedExposure: [], unchangedInheritedDebt: []
  };
  const denied = applyRiskExceptions({ exceptionsResult, securityHistoryResult: history(regression), securityGraph: graph(), allowCritical: false });
  assert.equal(denied.effectiveRegression.summary.newRisk, 1);
  assert.equal(denied.summary.criticalSkipped, 1);

  const allowed = applyRiskExceptions({ exceptionsResult, securityHistoryResult: history(regression), securityGraph: graph(), allowCritical: true });
  assert.equal(allowed.effectiveRegression.summary.newRisk, 0);
  assert.equal(allowed.applications.length, 1);
});

test('graph path scope accepts a risk node contained in that path', () => {
  const exceptionsResult = {
    active: [{
      id: 'risk-path',
      expiresAt: '2026-10-01T00:00:00Z',
      scope: { findingFingerprints: [], graphPathIds: ['path-12345678abcdef00'] }
    }],
    expired: [], invalid: [], all: []
  };
  const regression = {
    status: 'compared',
    state: 'regression',
    summary: { newRisk: 1, resolvedRisk: 0, expandedExposure: 0, reducedExposure: 0, unchangedInheritedDebt: 0 },
    newRisk: [{ nodeId: 'finding-1', fingerprint: 'dddddddddddddddd', severity: 'medium' }],
    resolvedRisk: [], expandedExposure: [], reducedExposure: [], unchangedInheritedDebt: []
  };
  const securityGraph = graph(
    [{ id: 'path-12345678abcdef00', nodeIds: ['package-1', 'finding-1'] }],
    [{ id: 'package-1', type: 'package' }, { id: 'finding-1', type: 'finding' }]
  );
  const result = applyRiskExceptions({ exceptionsResult, securityHistoryResult: history(regression), securityGraph });
  assert.equal(result.effectiveRegression.summary.newRisk, 0);
  assert.equal(result.applications[0].matchedBy, 'graph-path');
});

test('exception lifecycle records introduced renewed lapsed and scope changes', () => {
  const previous = {
    items: [
      { id: 'renew', status: 'active', expiresAt: '2026-09-25T00:00:00Z', scopeHash: 'a' },
      { id: 'lapse', status: 'active', expiresAt: '2026-09-25T00:00:00Z', scopeHash: 'b' },
      { id: 'scope', status: 'active', expiresAt: '2026-10-01T00:00:00Z', scopeHash: 'old' }
    ]
  };
  const current = {
    items: [
      { id: 'renew', status: 'active', expiresAt: '2026-10-10T00:00:00Z', scopeHash: 'a' },
      { id: 'scope', status: 'active', expiresAt: '2026-10-01T00:00:00Z', scopeHash: 'new' },
      { id: 'new', status: 'active', expiresAt: '2026-10-01T00:00:00Z', scopeHash: 'c' }
    ]
  };
  const lifecycle = classifyRiskExceptionLifecycle(current, previous);
  assert.deepEqual(lifecycle.introducedIds, ['new']);
  assert.deepEqual(lifecycle.renewedIds, ['renew']);
  assert.deepEqual(lifecycle.lapsedIds, ['lapse']);
  assert.deepEqual(lifecycle.changedScopeIds, ['scope']);
});

test('snapshot omits owner and rationale but preserves lifecycle identity', () => {
  const snapshot = createRiskExceptionSnapshot({
    all: [{
      id: 'risk-001',
      owner: '@alice',
      rationale: 'Sensitive internal rationale that should not enter history.',
      reviewedAt: '2026-09-19T00:00:00Z',
      expiresAt: '2026-10-01T00:00:00Z',
      status: 'active',
      scope: { findingFingerprints: ['aaaaaaaaaaaaaaaa'], graphPathIds: [] }
    }]
  });
  const serialized = JSON.stringify(snapshot);
  assert.equal(serialized.includes('@alice'), false);
  assert.equal(serialized.includes('Sensitive internal rationale'), false);
  assert.equal(snapshot.items[0].id, 'risk-001');
});
