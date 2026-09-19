import test from 'node:test';
import assert from 'node:assert/strict';
import {
  evaluateOwnerApprovals,
  evaluateRegressionPolicy,
  normalizeRegressionPolicy
} from '../src/regression-policy.mjs';

function history(regression) {
  return { regression };
}
function compared(overrides = {}) {
  return {
    status: 'compared',
    state: 'unchanged',
    summary: {
      newRisk: 0,
      resolvedRisk: 0,
      expandedExposure: 0,
      reducedExposure: 0,
      unchangedInheritedDebt: 0,
      ...overrides.summary
    },
    newRisk: overrides.newRisk || [],
    resolvedRisk: overrides.resolvedRisk || [],
    expandedExposure: overrides.expandedExposure || [],
    reducedExposure: overrides.reducedExposure || [],
    unchangedInheritedDebt: overrides.unchangedInheritedDebt || []
  };
}
function control(blastRadiusNodes, owners = []) {
  return {
    summary: { blastRadiusNodes },
    ownership: { owners: owners.map(owner => ({ owner, files: 1 })) }
  };
}

test('default policy is report-only and does not fail builds', () => {
  const policy = normalizeRegressionPolicy({});
  assert.equal(policy.mode, 'report');
  const result = evaluateRegressionPolicy({
    securityHistoryResult: history(compared({
      summary: { newRisk: 1 },
      newRisk: [{ nodeId: 'n1', severity: 'critical' }]
    })),
    controlPlane: control(0)
  });
  assert.equal(result.decision, 'block');
  assert.equal(result.shouldFail, false);
  assert.equal(result.state, 'block');
});

test('enforce mode blocks new risk at or above configured severity', () => {
  const result = evaluateRegressionPolicy({
    securityHistoryResult: history(compared({
      summary: { newRisk: 2 },
      newRisk: [{ nodeId: 'h', severity: 'high' }, { nodeId: 'm', severity: 'medium' }]
    })),
    controlPlane: control(0),
    policy: { mode: 'enforce', newRiskSeverity: 'high', expandedExposure: 'ignore' }
  });
  assert.equal(result.shouldFail, true);
  const rule = result.rules.find(item => item.id === 'new-risk-severity');
  assert.equal(rule.evidence.matching, 1);
});

test('expanded exposure can warn or block independently from inherited debt', () => {
  const regression = compared({
    summary: { expandedExposure: 2, unchangedInheritedDebt: 4 }
  });
  const warn = evaluateRegressionPolicy({
    securityHistoryResult: history(regression),
    controlPlane: control(0),
    policy: { mode: 'enforce', newRiskSeverity: 'none', expandedExposure: 'warn', inheritedDebt: 'warn' }
  });
  assert.equal(warn.shouldFail, false);
  assert.equal(warn.decision, 'warn');

  const block = evaluateRegressionPolicy({
    securityHistoryResult: history(regression),
    controlPlane: control(0),
    policy: { mode: 'enforce', newRiskSeverity: 'none', expandedExposure: 'block' }
  });
  assert.equal(block.shouldFail, true);
});

test('latest individual CODEOWNERS approval satisfies owner-approval evidence', () => {
  const ownership = { owners: [{ owner: '@alice', files: 2 }, { owner: '@org/security', files: 1 }] };
  const reviews = [
    { id: 1, state: 'APPROVED', submitted_at: '2026-09-19T01:00:00Z', user: { login: 'alice' } },
    { id: 2, state: 'CHANGES_REQUESTED', submitted_at: '2026-09-19T02:00:00Z', user: { login: 'alice' } },
    { id: 3, state: 'APPROVED', submitted_at: '2026-09-19T03:00:00Z', user: { login: 'alice' } }
  ];
  const evidence = evaluateOwnerApprovals({ ownership, reviews, reviewStatus: 'success' });
  assert.equal(evidence.satisfied, true);
  assert.deepEqual(evidence.approvedIndividuals, ['@alice']);
  assert.deepEqual(evidence.teamOwners, ['@org/security']);
});

test('team CODEOWNERS are never inferred as approved from a reviewer login', () => {
  const ownership = { owners: [{ owner: '@org/security', files: 2 }] };
  const reviews = [
    { id: 1, state: 'APPROVED', submitted_at: '2026-09-19T01:00:00Z', user: { login: 'security' } }
  ];
  const evidence = evaluateOwnerApprovals({ ownership, reviews, reviewStatus: 'success' });
  assert.equal(evidence.satisfied, false);
  assert.equal(evidence.eligibleIndividuals.length, 0);
  assert.match(evidence.reason, /team/i);
});

test('blast radius can require owner approval and enforce only when configured', () => {
  const ownerApproval = evaluateOwnerApprovals({
    ownership: { owners: [{ owner: '@alice', files: 1 }] },
    reviews: [],
    reviewStatus: 'success'
  });
  const report = evaluateRegressionPolicy({
    securityHistoryResult: history(compared()),
    controlPlane: control(12, ['@alice']),
    ownerApproval,
    policy: { mode: 'report', newRiskSeverity: 'none', blastRadiusThreshold: 10, blastRadiusAction: 'require-owner-approval' }
  });
  assert.equal(report.decision, 'approval-required');
  assert.equal(report.shouldFail, false);

  const enforce = evaluateRegressionPolicy({
    securityHistoryResult: history(compared()),
    controlPlane: control(12, ['@alice']),
    ownerApproval,
    policy: { mode: 'enforce', newRiskSeverity: 'none', blastRadiusThreshold: 10, blastRadiusAction: 'require-owner-approval' }
  });
  assert.equal(enforce.shouldFail, true);
});

test('first unclassified history never triggers a regression block', () => {
  const result = evaluateRegressionPolicy({
    securityHistoryResult: history({ status: 'no-history', state: 'unclassified', summary: {} }),
    controlPlane: control(0),
    policy: { mode: 'enforce', newRiskSeverity: 'low', expandedExposure: 'block' }
  });
  assert.equal(result.shouldFail, false);
  assert.equal(result.rules[0].id, 'history-required');
});
