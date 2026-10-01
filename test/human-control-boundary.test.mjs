import test from 'node:test';
import assert from 'node:assert/strict';
import {
  compareHumanControlOutcome,
  normalizeControlEvidence,
  recommendHumanControl
} from '../src/human-control-boundary.mjs';

test('normalizes evidence conservatively', () => {
  const evidence = normalizeControlEvidence({
    privilege: 'HIGH',
    reversibility: 'low',
    blastRadiusNodes: 12.7,
    uncertainty: 2,
    evidenceQuality: -1
  });
  assert.equal(evidence.privilege, 'high');
  assert.equal(evidence.reversibility, 'low');
  assert.equal(evidence.blastRadiusNodes, 13);
  assert.equal(evidence.uncertainty, 1);
  assert.equal(evidence.evidenceQuality, 0);
});

test('delegates a low-risk reversible action with strong evidence', () => {
  const result = recommendHumanControl({
    privilege: 'low',
    reversibility: 'high',
    evidenceQuality: 0.95,
    uncertainty: 0.05,
    highestFindingSeverity: 'none',
    regressionDecision: 'pass'
  });
  assert.equal(result.boundary, 'delegate');
  assert.equal(result.oversightTheatre.risk, 'low');
});

test('high-privilege credential access cannot be silently delegated', () => {
  const result = recommendHumanControl({
    privilege: 'high',
    reversibility: 'high',
    credentialAccess: true,
    evidenceQuality: 0.95,
    uncertainty: 0
  });
  assert.equal(result.boundary, 'require-approval');
  assert.match(result.hardConstraints.join(' '), /credential/i);
});

test('explicit regression block remains a block without pretending exploitability', () => {
  const result = recommendHumanControl({
    privilege: 'low',
    reversibility: 'high',
    regressionDecision: 'block',
    evidenceQuality: 0.9
  });
  assert.equal(result.boundary, 'block');
  assert.equal(result.guardrails.exploitProbability, false);
  assert.match(result.methodology, /not exploit probability/i);
});

test('weak evidence exposes oversight-theatre risk', () => {
  const result = recommendHumanControl({
    privilege: 'critical',
    reversibility: 'irreversible',
    externalSideEffects: true,
    blastRadiusNodes: 80,
    uncertainty: 0.9,
    evidenceQuality: 0.1,
    highestFindingSeverity: 'high'
  });
  assert.equal(result.boundary, 'block');
  assert.equal(result.oversightTheatre.risk, 'high');
  assert.match(result.oversightTheatre.reasons.join(' '), /rubber-stamp/i);
});

test('paired outcome comparison records when human control improves safety', () => {
  const result = compareHumanControlOutcome({
    autonomous: { unsafe: true, taskSuccess: true },
    humanControlled: { unsafe: false, taskSuccess: true },
    reviewLatencyMs: 18000
  });
  assert.equal(result.state, 'compared');
  assert.equal(result.controlValue, 'improved');
  assert.equal(result.safetyDelta, 1);
  assert.equal(result.taskSuccessDelta, 0);
  assert.equal(result.reviewLatencyMs, 18000);
});

test('paired outcome comparison is explicit when evidence is incomplete', () => {
  const result = compareHumanControlOutcome({
    autonomous: { unsafe: false, taskSuccess: true }
  });
  assert.equal(result.state, 'inconclusive');
  assert.equal(result.controlValue, 'inconclusive');
});
