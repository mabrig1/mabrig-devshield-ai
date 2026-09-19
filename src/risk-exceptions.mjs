import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

const severityRank = { low: 1, medium: 2, high: 3, critical: 4 };

function sha256(value) {
  return crypto.createHash('sha256').update(String(value)).digest('hex');
}

function safeRelative(value) {
  const rel = String(value || '').trim();
  if (!rel || path.isAbsolute(rel) || rel.includes('\\') || /[\x00-\x1f\x7f]/.test(rel)) return false;
  return !rel.split('/').some(part => !part || part === '.' || part === '..');
}

function canonical(value) {
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  if (value && typeof value === 'object') {
    const keys = Object.keys(value).sort();
    return '{' + keys.map(key => JSON.stringify(key) + ':' + canonical(value[key])).join(',') + '}';
  }
  return JSON.stringify(value);
}

function parseTime(value) {
  const millis = Date.parse(String(value || ''));
  return Number.isFinite(millis) ? millis : null;
}

function uniqueStrings(values, max = 50) {
  return [...new Set((Array.isArray(values) ? values : []).map(value => String(value || '').trim()).filter(Boolean))].slice(0, max);
}

function validFingerprint(value) {
  return /^[a-f0-9]{16,128}$/i.test(String(value || ''));
}

function validPathId(value) {
  return /^path-[a-f0-9]{8,64}$/i.test(String(value || ''));
}

function validateException(raw, { nowMs, maxDays }) {
  const errors = [];
  const id = String(raw && raw.id || '').trim();
  const owner = String(raw && raw.owner || '').trim();
  const rationale = String(raw && raw.rationale || '').trim();
  const reviewedAt = String(raw && raw.reviewedAt || '').trim();
  const expiresAt = String(raw && raw.expiresAt || '').trim();
  const reviewedMs = parseTime(reviewedAt);
  const expiresMs = parseTime(expiresAt);
  const fingerprints = uniqueStrings(raw && raw.scope && raw.scope.findingFingerprints).filter(validFingerprint);
  const graphPathIds = uniqueStrings(raw && raw.scope && raw.scope.graphPathIds).filter(validPathId);

  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{2,79}$/.test(id)) errors.push('id');
  if (!owner || owner.length > 160) errors.push('owner');
  if (rationale.length < 12 || rationale.length > 1000) errors.push('rationale');
  if (reviewedMs == null) errors.push('reviewedAt');
  if (reviewedMs != null && reviewedMs > nowMs + 5 * 60 * 1000) errors.push('reviewedAt-future');
  if (expiresMs == null) errors.push('expiresAt');
  if (reviewedMs != null && expiresMs != null && expiresMs <= reviewedMs) errors.push('expiry-order');
  if (reviewedMs != null && expiresMs != null && expiresMs - reviewedMs > maxDays * 86400000) errors.push('max-duration');
  if (!fingerprints.length && !graphPathIds.length) errors.push('scope');
  if ((raw && raw.scope && Array.isArray(raw.scope.findingFingerprints) ? raw.scope.findingFingerprints.length : 0) !== fingerprints.length) errors.push('findingFingerprints');
  if ((raw && raw.scope && Array.isArray(raw.scope.graphPathIds) ? raw.scope.graphPathIds.length : 0) !== graphPathIds.length) errors.push('graphPathIds');

  let status = errors.length ? 'invalid' : expiresMs <= nowMs ? 'expired' : 'active';
  return {
    id: id || null,
    owner: owner || null,
    rationale: rationale || null,
    reviewedAt: reviewedAt || null,
    expiresAt: expiresAt || null,
    scope: { findingFingerprints: fingerprints, graphPathIds },
    status,
    errors
  };
}

export function loadRiskExceptions({
  workspace,
  exceptionsFile = '.devshield-exceptions.json',
  now = new Date().toISOString(),
  maxDays = 90,
  maxBytes = 1024 * 1024
} = {}) {
  if (!workspace) throw new Error('workspace is required');
  const rel = String(exceptionsFile || '').trim();
  if (!safeRelative(rel)) {
    return { status: 'invalid-path', file: rel || null, active: [], expired: [], invalid: [], all: [] };
  }

  let raw;
  try {
    const abs = path.join(workspace, rel);
    const stat = fs.lstatSync(abs);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.size > maxBytes) {
      return { status: 'invalid', file: rel, active: [], expired: [], invalid: [{ id: null, errors: ['file'] }], all: [] };
    }
    raw = JSON.parse(fs.readFileSync(abs, 'utf8'));
  } catch (error) {
    if (error && error.code === 'ENOENT') return { status: 'missing', file: rel, active: [], expired: [], invalid: [], all: [] };
    return { status: 'invalid', file: rel, active: [], expired: [], invalid: [{ id: null, errors: ['parse'] }], all: [] };
  }

  if (!raw || typeof raw !== 'object' || raw.schemaVersion !== 1 || !Array.isArray(raw.exceptions)) {
    return { status: 'invalid', file: rel, active: [], expired: [], invalid: [{ id: null, errors: ['schema'] }], all: [] };
  }

  const nowMs = parseTime(now);
  if (nowMs == null) throw new Error('now must be a valid date');
  const cappedDays = Math.max(1, Math.min(365, Number(maxDays) || 90));
  const all = raw.exceptions.slice(0, 500).map(item => validateException(item, { nowMs, maxDays: cappedDays }));
  const idCounts = new Map();
  for (const item of all) if (item.id) idCounts.set(item.id, (idCounts.get(item.id) || 0) + 1);
  for (const item of all) {
    if (item.id && (idCounts.get(item.id) || 0) > 1) {
      item.status = 'invalid';
      if (!item.errors.includes('duplicate-id')) item.errors.push('duplicate-id');
    }
  }
  const active = all.filter(item => item.status === 'active');
  const expired = all.filter(item => item.status === 'expired');
  const invalid = all.filter(item => item.status === 'invalid');
  return {
    status: invalid.length ? 'loaded-with-invalid' : 'loaded',
    file: rel,
    maxDays: cappedDays,
    evaluatedAt: now,
    active,
    expired,
    invalid,
    all
  };
}

function pathRiskNodes(graph) {
  const nodes = new Map((graph && Array.isArray(graph.nodes) ? graph.nodes : []).map(node => [node.id, node]));
  const map = new Map();
  for (const item of graph && Array.isArray(graph.paths) ? graph.paths : []) {
    const riskIds = (item.nodeIds || []).filter(id => ['finding', 'advisory'].includes(nodes.get(id)?.type));
    map.set(item.id, new Set(riskIds));
  }
  return map;
}

function exceptionMatchesItem(exceptionItem, riskItem, graphPathRiskNodes) {
  const fingerprints = new Set(exceptionItem.scope.findingFingerprints);
  if (riskItem.fingerprint && fingerprints.has(riskItem.fingerprint)) return { matchedBy: 'finding-fingerprint', value: riskItem.fingerprint };
  for (const pathId of exceptionItem.scope.graphPathIds) {
    if (graphPathRiskNodes.get(pathId)?.has(riskItem.nodeId)) return { matchedBy: 'graph-path', value: pathId };
  }
  return null;
}

function isCritical(item) {
  return (severityRank[String(item && item.severity || '').toLowerCase()] || 0) >= severityRank.critical;
}

function filterRegressionItems(items, exceptions, graphPathRiskNodes, allowCritical, category, applications, criticalSkipped) {
  const kept = [];
  for (const item of Array.isArray(items) ? items : []) {
    let accepted = null;
    for (const exceptionItem of exceptions) {
      const match = exceptionMatchesItem(exceptionItem, item, graphPathRiskNodes);
      if (!match) continue;
      if (isCritical(item) && !allowCritical) {
        criticalSkipped.push({
          exceptionId: exceptionItem.id,
          nodeId: item.nodeId,
          category,
          severity: item.severity,
          reason: 'critical-risk-exceptions-disabled'
        });
        continue;
      }
      accepted = { exceptionItem, match };
      break;
    }
    if (!accepted) {
      kept.push(item);
      continue;
    }
    applications.push({
      exceptionId: accepted.exceptionItem.id,
      nodeId: item.nodeId,
      category,
      severity: item.severity,
      matchedBy: accepted.match.matchedBy,
      scopeValue: accepted.match.value,
      expiresAt: accepted.exceptionItem.expiresAt
    });
  }
  return kept;
}

export function applyRiskExceptions({
  exceptionsResult,
  securityHistoryResult,
  securityGraph,
  allowCritical = false
} = {}) {
  const rawRegression = securityHistoryResult && securityHistoryResult.regression;
  if (!rawRegression || rawRegression.status !== 'compared') {
    return {
      effectiveRegression: rawRegression || null,
      summary: {
        activeExceptions: exceptionsResult?.active?.length || 0,
        expiredExceptions: exceptionsResult?.expired?.length || 0,
        invalidExceptions: exceptionsResult?.invalid?.length || 0,
        appliedItems: 0,
        criticalSkipped: 0
      },
      applications: [],
      criticalSkipped: [],
      unusedActiveExceptionIds: (exceptionsResult?.active || []).map(item => item.id)
    };
  }

  const active = Array.isArray(exceptionsResult?.active) ? exceptionsResult.active : [];
  const graphPathRiskNodes = pathRiskNodes(securityGraph);
  const applications = [];
  const criticalSkipped = [];

  const newRisk = filterRegressionItems(rawRegression.newRisk, active, graphPathRiskNodes, allowCritical, 'new-risk', applications, criticalSkipped);
  const expandedExposure = filterRegressionItems(rawRegression.expandedExposure, active, graphPathRiskNodes, allowCritical, 'expanded-exposure', applications, criticalSkipped);
  const unchangedInheritedDebt = filterRegressionItems(rawRegression.unchangedInheritedDebt, active, graphPathRiskNodes, allowCritical, 'inherited-debt', applications, criticalSkipped);
  const reducedExposure = Array.isArray(rawRegression.reducedExposure) ? [...rawRegression.reducedExposure] : [];
  const resolvedRisk = Array.isArray(rawRegression.resolvedRisk) ? [...rawRegression.resolvedRisk] : [];

  const state = newRisk.length || expandedExposure.length
    ? 'regression'
    : resolvedRisk.length || reducedExposure.length
      ? 'improvement'
      : 'unchanged';

  const effectiveRegression = {
    ...rawRegression,
    state,
    summary: {
      newRisk: newRisk.length,
      resolvedRisk: resolvedRisk.length,
      expandedExposure: expandedExposure.length,
      reducedExposure: reducedExposure.length,
      unchangedInheritedDebt: unchangedInheritedDebt.length
    },
    newRisk,
    resolvedRisk,
    expandedExposure,
    reducedExposure,
    unchangedInheritedDebt
  };

  const used = new Set(applications.map(item => item.exceptionId));
  return {
    effectiveRegression,
    rawRegressionSummary: rawRegression.summary,
    summary: {
      activeExceptions: active.length,
      expiredExceptions: exceptionsResult?.expired?.length || 0,
      invalidExceptions: exceptionsResult?.invalid?.length || 0,
      appliedItems: applications.length,
      criticalSkipped: criticalSkipped.length
    },
    applications,
    criticalSkipped,
    unusedActiveExceptionIds: active.map(item => item.id).filter(id => !used.has(id))
  };
}

function scopeHash(item) {
  return sha256(canonical(item.scope || {}));
}

export function createRiskExceptionSnapshot(exceptionsResult) {
  const items = (exceptionsResult?.all || [])
    .filter(item => item.id)
    .map(item => ({
      id: item.id,
      status: item.status,
      reviewedAt: item.reviewedAt,
      expiresAt: item.expiresAt,
      scopeHash: scopeHash(item)
    }))
    .sort((a, b) => a.id.localeCompare(b.id));
  return { items };
}

export function classifyRiskExceptionLifecycle(currentSnapshot, previousSnapshot) {
  const current = new Map((currentSnapshot?.items || []).map(item => [item.id, item]));
  const previous = new Map((previousSnapshot?.items || []).map(item => [item.id, item]));
  const introducedIds = [];
  const renewedIds = [];
  const lapsedIds = [];
  const changedScopeIds = [];

  for (const [id, item] of current) {
    const old = previous.get(id);
    if (!old) {
      introducedIds.push(id);
      continue;
    }
    if (item.scopeHash !== old.scopeHash) changedScopeIds.push(id);
    const oldExpiry = parseTime(old.expiresAt);
    const newExpiry = parseTime(item.expiresAt);
    if (oldExpiry != null && newExpiry != null && newExpiry > oldExpiry) renewedIds.push(id);
    if (old.status === 'active' && item.status === 'expired') lapsedIds.push(id);
  }
  for (const [id, item] of previous) {
    if (item.status === 'active' && !current.has(id)) lapsedIds.push(id);
  }

  const uniqueSorted = values => [...new Set(values)].sort();
  return {
    introducedIds: uniqueSorted(introducedIds),
    renewedIds: uniqueSorted(renewedIds),
    lapsedIds: uniqueSorted(lapsedIds),
    changedScopeIds: uniqueSorted(changedScopeIds),
    summary: {
      introduced: new Set(introducedIds).size,
      renewed: new Set(renewedIds).size,
      lapsed: new Set(lapsedIds).size,
      changedScope: new Set(changedScopeIds).size
    }
  };
}

export function riskExceptionsMarkdown(exceptionsResult, applicationResult, lifecycle = null) {
  const lines = [
    '### Time-bound risk exceptions',
    '',
    'Source **' + (exceptionsResult?.status || 'missing') + '** · active **' + (applicationResult?.summary?.activeExceptions || 0) + '** · expired **' + (applicationResult?.summary?.expiredExceptions || 0) + '** · invalid **' + (applicationResult?.summary?.invalidExceptions || 0) + '** · applied regression items **' + (applicationResult?.summary?.appliedItems || 0) + '**',
    '',
    'Exceptions affect only the v2.2 regression-policy layer. Findings, SARIF, graph/history evidence, and the deterministic fail-on gate remain unchanged.'
  ];
  if (applicationResult?.summary?.criticalSkipped) {
    lines.push('', '**Critical risk:** ' + applicationResult.summary.criticalSkipped + ' matching item(s) were not accepted because critical exceptions are disabled.');
  }
  if (lifecycle) {
    lines.push('', '**Lifecycle:** introduced ' + lifecycle.summary.introduced + ' · renewed ' + lifecycle.summary.renewed + ' · lapsed ' + lifecycle.summary.lapsed + ' · scope changed ' + lifecycle.summary.changedScope);
  }
  return lines.join('\n');
}

export function writeRiskExceptions({ workspace, reportDir = '.devshield', exceptionsResult, applicationResult, lifecycle } = {}) {
  if (!workspace) throw new Error('workspace is required');
  const dir = path.join(workspace, reportDir);
  fs.mkdirSync(dir, { recursive: true });
  const jsonFile = path.join(dir, 'devshield-risk-exceptions.json');
  const markdownFile = path.join(dir, 'devshield-risk-exceptions.md');
  const report = {
    source: {
      status: exceptionsResult?.status || 'missing',
      file: exceptionsResult?.file || null,
      maxDays: exceptionsResult?.maxDays || null
    },
    summary: applicationResult?.summary || null,
    applications: applicationResult?.applications || [],
    criticalSkipped: applicationResult?.criticalSkipped || [],
    unusedActiveExceptionIds: applicationResult?.unusedActiveExceptionIds || [],
    expired: (exceptionsResult?.expired || []).map(item => ({ id: item.id, expiresAt: item.expiresAt })),
    invalid: (exceptionsResult?.invalid || []).map(item => ({ id: item.id, errors: item.errors })),
    lifecycle: lifecycle || null
  };
  fs.writeFileSync(jsonFile, JSON.stringify(report, null, 2) + '\n');
  fs.writeFileSync(markdownFile, riskExceptionsMarkdown(exceptionsResult, applicationResult, lifecycle) + '\n');
  return {
    jsonFile: path.relative(workspace, jsonFile).replace(/\\/g, '/'),
    markdownFile: path.relative(workspace, markdownFile).replace(/\\/g, '/')
  };
}
