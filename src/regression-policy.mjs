const severityRank = { low: 1, medium: 2, high: 3, critical: 4 };

function normalizeSeverity(value, fallback = 'critical') {
  const v = String(value || '').toLowerCase();
  if (v === 'none') return 'none';
  return severityRank[v] ? v : fallback;
}

function normalizeChoice(value, choices, fallback) {
  const v = String(value || '').toLowerCase();
  return choices.includes(v) ? v : fallback;
}

function clampInt(value, min, max, fallback) {
  const parsed = Number.parseInt(value, 10);
  return Number.isFinite(parsed) ? Math.max(min, Math.min(max, parsed)) : fallback;
}

export function normalizeRegressionPolicy(raw = {}) {
  return {
    mode: normalizeChoice(raw.mode, ['off', 'report', 'enforce'], 'report'),
    newRiskSeverity: normalizeSeverity(raw.newRiskSeverity, 'critical'),
    expandedExposure: normalizeChoice(raw.expandedExposure, ['ignore', 'warn', 'block'], 'warn'),
    inheritedDebt: normalizeChoice(raw.inheritedDebt, ['ignore', 'warn'], 'ignore'),
    blastRadiusThreshold: clampInt(raw.blastRadiusThreshold, 0, 10000, 0),
    blastRadiusAction: normalizeChoice(raw.blastRadiusAction, ['ignore', 'warn', 'block', 'require-owner-approval'], 'warn')
  };
}

function ownerKind(owner) {
  const value = String(owner || '').trim();
  if (!value.startsWith('@')) return 'invalid';
  return value.slice(1).includes('/') ? 'team' : 'individual';
}

function reviewTime(review) {
  const parsed = Date.parse(review && review.submitted_at || '');
  if (Number.isFinite(parsed)) return parsed;
  return Number(review && review.id) || 0;
}

export function evaluateOwnerApprovals({ ownership = null, reviews = [], reviewStatus = 'unavailable' } = {}) {
  const ownerEntries = Array.isArray(ownership && ownership.owners) ? ownership.owners : [];
  const owners = [...new Set(ownerEntries.map(item => item && item.owner).filter(Boolean))].sort();
  const individuals = owners.filter(owner => ownerKind(owner) === 'individual').map(owner => owner.slice(1).toLowerCase());
  const teams = owners.filter(owner => ownerKind(owner) === 'team');

  const latest = new Map();
  for (const review of Array.isArray(reviews) ? reviews : []) {
    const login = String(review && review.user && review.user.login || '').toLowerCase();
    if (!login || !individuals.includes(login)) continue;
    const previous = latest.get(login);
    if (!previous || reviewTime(review) >= reviewTime(previous)) latest.set(login, review);
  }

  const approvedIndividuals = [...latest.entries()]
    .filter(([, review]) => String(review && review.state || '').toUpperCase() === 'APPROVED')
    .map(([login]) => '@' + login)
    .sort();

  const eligibleIndividuals = individuals.map(login => '@' + login).sort();
  const satisfied = approvedIndividuals.length > 0;

  let reason = 'No verifiable individual CODEOWNERS approval is available.';
  if (satisfied) reason = 'At least one verifiable individual CODEOWNERS owner has an active GitHub APPROVED review.';
  else if (!owners.length) reason = 'No CODEOWNERS ownership hints were resolved for the changed/impacted graph files.';
  else if (!eligibleIndividuals.length && teams.length) reason = 'Only team CODEOWNERS hints were resolved; team membership/approval is not inferred automatically.';
  else if (reviewStatus !== 'success') reason = 'GitHub pull-request review evidence was unavailable, so owner approval could not be verified.';

  return {
    reviewStatus,
    owners,
    eligibleIndividuals,
    teamOwners: teams,
    approvedIndividuals,
    satisfied,
    reason,
    semantics: 'Any one verifiable individual CODEOWNERS owner approval satisfies the v2.2 owner-approval condition. Team ownership is never inferred from reviewer identity.'
  };
}

function findingAtOrAbove(item, threshold) {
  if (threshold === 'none') return false;
  return (severityRank[String(item && item.severity || '').toLowerCase()] || 0) >= (severityRank[threshold] || severityRank.critical);
}

function outcomeRule(id, configuredAction, outcome, message, evidence = {}) {
  return { id, configuredAction, outcome, message, evidence };
}

function decisionRank(value) {
  return ({ pass: 0, warn: 1, 'approval-required': 2, block: 3 })[value] || 0;
}

export function evaluateRegressionPolicy({
  securityHistoryResult = null,
  controlPlane = null,
  policy: rawPolicy = {},
  ownerApproval = null
} = {}) {
  const policy = normalizeRegressionPolicy(rawPolicy);
  const regression = securityHistoryResult && securityHistoryResult.regression || null;
  const blastRadiusNodes = Number(controlPlane && controlPlane.summary && controlPlane.summary.blastRadiusNodes) || 0;
  const rules = [];

  if (policy.mode === 'off') {
    return {
      schemaVersion: 1,
      mode: policy.mode,
      state: 'disabled',
      shouldFail: false,
      decision: 'pass',
      policy,
      ownerApproval: ownerApproval || evaluateOwnerApprovals(),
      summary: { block: 0, warn: 0, approvalRequired: 0, pass: 0 },
      rules: []
    };
  }

  if (!regression || regression.status !== 'compared') {
    rules.push(outcomeRule(
      'history-required',
      'report',
      'pass',
      'No trusted previous history entry is available; regression-specific blocking is not applied on the first/unclassified snapshot.',
      { regressionStatus: regression && regression.status || 'unavailable' }
    ));
  } else {
    const thresholdMatches = (regression.newRisk || []).filter(item => findingAtOrAbove(item, policy.newRiskSeverity));
    if (policy.newRiskSeverity === 'none' || !thresholdMatches.length) {
      rules.push(outcomeRule(
        'new-risk-severity',
        policy.newRiskSeverity,
        'pass',
        policy.newRiskSeverity === 'none'
          ? 'New-risk severity gating is disabled.'
          : 'No new risk meets the configured severity threshold.',
        { threshold: policy.newRiskSeverity, matching: 0, totalNewRisk: regression.summary && regression.summary.newRisk || 0 }
      ));
    } else {
      rules.push(outcomeRule(
        'new-risk-severity',
        policy.newRiskSeverity,
        'block',
        thresholdMatches.length + ' new risk node(s) meet or exceed the configured severity threshold.',
        {
          threshold: policy.newRiskSeverity,
          matching: thresholdMatches.length,
          nodeIds: thresholdMatches.slice(0, 20).map(item => item.nodeId),
          severities: thresholdMatches.slice(0, 20).map(item => item.severity)
        }
      ));
    }

    const expandedCount = Number(regression.summary && regression.summary.expandedExposure) || 0;
    if (!expandedCount || policy.expandedExposure === 'ignore') {
      rules.push(outcomeRule(
        'expanded-exposure',
        policy.expandedExposure,
        'pass',
        expandedCount ? 'Expanded exposure is configured to be ignored by the regression gate.' : 'No expanded exposure is present.',
        { count: expandedCount }
      ));
    } else {
      rules.push(outcomeRule(
        'expanded-exposure',
        policy.expandedExposure,
        policy.expandedExposure,
        expandedCount + ' existing risk node(s) have increased bounded graph exposure.',
        { count: expandedCount }
      ));
    }

    const inheritedCount = Number(regression.summary && regression.summary.unchangedInheritedDebt) || 0;
    if (!inheritedCount || policy.inheritedDebt === 'ignore') {
      rules.push(outcomeRule(
        'inherited-debt',
        policy.inheritedDebt,
        'pass',
        inheritedCount ? 'Unchanged inherited debt is allowed by policy.' : 'No unchanged inherited debt is present.',
        { count: inheritedCount }
      ));
    } else {
      rules.push(outcomeRule(
        'inherited-debt',
        policy.inheritedDebt,
        'warn',
        inheritedCount + ' unchanged inherited risk node(s) remain visible.',
        { count: inheritedCount }
      ));
    }
  }

  const approval = ownerApproval || evaluateOwnerApprovals();
  if (!policy.blastRadiusThreshold || blastRadiusNodes <= policy.blastRadiusThreshold || policy.blastRadiusAction === 'ignore') {
    rules.push(outcomeRule(
      'blast-radius',
      policy.blastRadiusAction,
      'pass',
      !policy.blastRadiusThreshold
        ? 'Blast-radius threshold gating is disabled.'
        : blastRadiusNodes <= policy.blastRadiusThreshold
          ? 'Blast radius is within the configured threshold.'
          : 'Blast-radius policy action is configured to ignore.',
      { impactedNodes: blastRadiusNodes, threshold: policy.blastRadiusThreshold }
    ));
  } else if (policy.blastRadiusAction === 'require-owner-approval') {
    rules.push(outcomeRule(
      'blast-radius',
      policy.blastRadiusAction,
      approval.satisfied ? 'pass' : 'approval-required',
      approval.satisfied
        ? 'Blast radius exceeds the threshold, but a verifiable individual CODEOWNERS approval is present.'
        : 'Blast radius exceeds the threshold and requires a verifiable individual CODEOWNERS approval.',
      {
        impactedNodes: blastRadiusNodes,
        threshold: policy.blastRadiusThreshold,
        approval: {
          reviewStatus: approval.reviewStatus,
          eligibleIndividuals: approval.eligibleIndividuals,
          approvedIndividuals: approval.approvedIndividuals,
          teamOwners: approval.teamOwners,
          satisfied: approval.satisfied,
          reason: approval.reason
        }
      }
    ));
  } else {
    rules.push(outcomeRule(
      'blast-radius',
      policy.blastRadiusAction,
      policy.blastRadiusAction,
      'Blast radius exceeds the configured threshold.',
      { impactedNodes: blastRadiusNodes, threshold: policy.blastRadiusThreshold }
    ));
  }

  let decision = 'pass';
  for (const rule of rules) if (decisionRank(rule.outcome) > decisionRank(decision)) decision = rule.outcome;
  const shouldFail = policy.mode === 'enforce' && (decision === 'block' || decision === 'approval-required');
  const summary = {
    block: rules.filter(rule => rule.outcome === 'block').length,
    warn: rules.filter(rule => rule.outcome === 'warn').length,
    approvalRequired: rules.filter(rule => rule.outcome === 'approval-required').length,
    pass: rules.filter(rule => rule.outcome === 'pass').length
  };

  return {
    schemaVersion: 1,
    mode: policy.mode,
    state: shouldFail ? 'failed' : decision === 'pass' ? 'passed' : decision,
    decision,
    shouldFail,
    policy,
    ownerApproval: approval,
    summary,
    rules,
    guardrails: {
      deterministicGateUnchanged: true,
      reportModeNeverFailsBuild: true,
      teamApprovalNotInferred: true,
      regressionClassificationIsNotExploitProbability: true
    }
  };
}

export function regressionPolicyMarkdown(result) {
  if (!result || result.state === 'disabled') return '### Policy-aware regression gate\n\nRegression gate: disabled.';
  const lines = [
    '### Policy-aware regression gate',
    '',
    'Mode **' + result.mode + '** · decision **' + result.decision + '** · enforced failure **' + (result.shouldFail ? 'yes' : 'no') + '**',
    '',
    'This gate is additive. It does not weaken or replace DevShield\'s deterministic finding gate.'
  ];
  for (const rule of result.rules) {
    lines.push('- **' + rule.id + '** — ' + rule.outcome + ': ' + rule.message);
  }
  if (result.ownerApproval && result.ownerApproval.owners.length) {
    lines.push('', '**Owner-approval evidence:** ' + result.ownerApproval.reason);
  }
  return lines.join('\n');
}
