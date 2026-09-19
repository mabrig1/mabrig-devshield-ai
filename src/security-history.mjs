import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

const riskTypes = new Set(['finding', 'advisory']);

function sha256(value) {
  return crypto.createHash('sha256').update(String(value)).digest('hex');
}

function hmac(value, key) {
  return crypto.createHmac('sha256', key).update(String(value)).digest('hex');
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

function graphValid(graph) {
  return graph && typeof graph === 'object' && Array.isArray(graph.nodes) && Array.isArray(graph.edges) && Array.isArray(graph.paths);
}

function severityRank(value) {
  return ({ low: 1, medium: 2, high: 3, critical: 4 })[String(value || '').toLowerCase()] || 0;
}

function adjacency(graph) {
  const map = new Map();
  for (const edge of graph.edges || []) {
    const forward = map.get(edge.from) || [];
    forward.push({ nodeId: edge.to, edge });
    map.set(edge.from, forward);
    const backward = map.get(edge.to) || [];
    backward.push({ nodeId: edge.from, edge });
    map.set(edge.to, backward);
  }
  return map;
}

function exposureForSeed(seedId, graph, maxDepth = 4) {
  const links = adjacency(graph);
  const queue = [{ nodeId: seedId, depth: 0, contextual: false }];
  const seen = new Map([[seedId, { depth: 0, contextual: false }]]);
  while (queue.length) {
    const current = queue.shift();
    if (current.depth >= maxDepth) continue;
    for (const next of links.get(current.nodeId) || []) {
      const depth = current.depth + 1;
      const contextual = current.contextual || next.edge.confidence !== 'direct';
      const existing = seen.get(next.nodeId);
      if (existing && existing.depth <= depth && (!existing.contextual || contextual)) continue;
      seen.set(next.nodeId, { depth, contextual });
      queue.push({ nodeId: next.nodeId, depth, contextual });
    }
  }
  seen.delete(seedId);
  const values = [...seen.values()];
  return {
    reachableNodes: seen.size,
    evidenceLinked: values.filter(item => !item.contextual).length,
    contextual: values.filter(item => item.contextual).length,
    maxDepth
  };
}

export function graphDigest(graph) {
  if (!graphValid(graph)) throw new Error('security graph is required');
  const material = {
    schemaVersion: graph.schemaVersion || 1,
    graphId: graph.graphId || null,
    state: graph.state || null,
    nodes: [...graph.nodes].sort((a, b) => String(a.id).localeCompare(String(b.id))),
    edges: [...graph.edges].sort((a, b) => String(a.id).localeCompare(String(b.id))),
    paths: [...graph.paths].sort((a, b) => String(a.id).localeCompare(String(b.id)))
  };
  return sha256(canonical(material));
}

export function createRiskExposureSnapshot(graph, { maxDepth = 4 } = {}) {
  if (!graphValid(graph)) throw new Error('security graph is required');
  const seeds = graph.nodes.filter(node => riskTypes.has(node.type)).sort((a, b) => String(a.id).localeCompare(String(b.id)));
  const items = seeds.map(node => ({
    nodeId: node.id,
    type: node.type,
    severity: node.attributes && node.attributes.severity || null,
    rule: node.attributes && node.attributes.rule || null,
    file: node.attributes && node.attributes.file || null,
    fingerprint: node.attributes && node.attributes.fingerprint || null,
    exposure: exposureForSeed(node.id, graph, maxDepth)
  }));
  return {
    maxDepth,
    riskNodes: items.length,
    items
  };
}

function snapshotById(snapshot) {
  return new Map((snapshot && Array.isArray(snapshot.items) ? snapshot.items : []).map(item => [item.nodeId, item]));
}

export function classifySecurityRegression(currentSnapshot, previousSnapshot) {
  if (!previousSnapshot || !Array.isArray(previousSnapshot.items)) {
    return {
      status: 'no-history',
      state: 'unclassified',
      summary: { newRisk: 0, resolvedRisk: 0, expandedExposure: 0, reducedExposure: 0, unchangedInheritedDebt: 0 },
      newRisk: [],
      resolvedRisk: [],
      expandedExposure: [],
      reducedExposure: [],
      unchangedInheritedDebt: []
    };
  }

  const current = snapshotById(currentSnapshot);
  const previous = snapshotById(previousSnapshot);
  const newRisk = [];
  const resolvedRisk = [];
  const expandedExposure = [];
  const reducedExposure = [];
  const unchangedInheritedDebt = [];

  for (const [id, item] of current.entries()) {
    const old = previous.get(id);
    if (!old) {
      newRisk.push(item);
      continue;
    }
    const before = old.exposure && old.exposure.reachableNodes || 0;
    const after = item.exposure && item.exposure.reachableNodes || 0;
    const detail = {
      nodeId: id,
      type: item.type,
      severity: item.severity,
      rule: item.rule,
      file: item.file,
      fingerprint: item.fingerprint || null,
      beforeReachableNodes: before,
      afterReachableNodes: after,
      delta: after - before
    };
    if (after > before) expandedExposure.push(detail);
    else if (after < before) reducedExposure.push(detail);
    else unchangedInheritedDebt.push(detail);
  }

  for (const [id, item] of previous.entries()) {
    if (!current.has(id)) resolvedRisk.push(item);
  }

  const state = newRisk.length || expandedExposure.length
    ? 'regression'
    : resolvedRisk.length || reducedExposure.length
      ? 'improvement'
      : 'unchanged';

  const sortSeverity = (a, b) => severityRank(b.severity) - severityRank(a.severity) || String(a.nodeId).localeCompare(String(b.nodeId));
  newRisk.sort(sortSeverity);
  resolvedRisk.sort(sortSeverity);
  expandedExposure.sort((a, b) => b.delta - a.delta || sortSeverity(a, b));
  reducedExposure.sort((a, b) => a.delta - b.delta || sortSeverity(a, b));
  unchangedInheritedDebt.sort(sortSeverity);

  return {
    status: 'compared',
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
}

function entryPayload(entry) {
  const payload = {
    schemaVersion: entry.schemaVersion,
    sequence: entry.sequence,
    recordedAt: entry.recordedAt,
    revision: entry.revision,
    graphId: entry.graphId,
    graphDigest: entry.graphDigest,
    controlPlaneId: entry.controlPlaneId,
    controlSummary: entry.controlSummary,
    blastRadiusSummary: entry.blastRadiusSummary,
    riskSnapshot: entry.riskSnapshot,
    regression: entry.regression,
    previousEntryHash: entry.previousEntryHash
  };
  if (Object.prototype.hasOwnProperty.call(entry, 'exceptionSnapshot')) payload.exceptionSnapshot = entry.exceptionSnapshot;
  if (Object.prototype.hasOwnProperty.call(entry, 'exceptionLifecycle')) payload.exceptionLifecycle = entry.exceptionLifecycle;
  return payload;
}

function secureEqualHex(a, b) {
  if (!/^[a-f0-9]{64}$/i.test(String(a || '')) || !/^[a-f0-9]{64}$/i.test(String(b || ''))) return false;
  return crypto.timingSafeEqual(Buffer.from(a, 'hex'), Buffer.from(b, 'hex'));
}

export function validateSecurityHistory(history, { signingKey = '' } = {}) {
  if (!history || typeof history !== 'object' || history.schemaVersion !== 1 || !Array.isArray(history.entries)) {
    return { valid: false, integrity: 'invalid-schema', signatures: 'unknown', entries: 0 };
  }
  let previous = null;
  let signed = 0;
  let verified = 0;
  for (let i = 0; i < history.entries.length; i++) {
    const entry = history.entries[i];
    if (!entry || entry.sequence !== i + 1) return { valid: false, integrity: 'invalid-sequence', signatures: 'unknown', entries: history.entries.length };
    if ((entry.previousEntryHash || null) !== previous) return { valid: false, integrity: 'broken-chain', signatures: 'unknown', entries: history.entries.length };
    const expected = sha256(canonical(entryPayload(entry)));
    if (!secureEqualHex(expected, entry.entryHash)) return { valid: false, integrity: 'hash-mismatch', signatures: 'unknown', entries: history.entries.length };
    if (entry.signature) {
      signed++;
      if (signingKey) {
        const expectedSignature = hmac(entry.entryHash, signingKey);
        if (!secureEqualHex(expectedSignature, entry.signature)) return { valid: false, integrity: 'valid', signatures: 'signature-mismatch', entries: history.entries.length };
        verified++;
      }
    }
    previous = entry.entryHash;
  }
  let signatures = 'unsigned';
  if (signed && signingKey && verified === signed) signatures = signed === history.entries.length ? 'verified' : 'partially-verified';
  else if (signed && !signingKey) signatures = 'present-unverified';
  else if (signed) signatures = 'mixed';
  return { valid: true, integrity: 'valid', signatures, entries: history.entries.length, headHash: previous };
}

export function loadSecurityHistory({ workspace, historyFile = '.devshield-security-history.json', signingKey = '', maxBytes = 12 * 1024 * 1024 } = {}) {
  if (!workspace) throw new Error('workspace is required');
  const rel = String(historyFile || '').trim();
  if (!safeRelative(rel)) return { status: 'invalid-path', file: rel || null, history: null, validation: null };
  try {
    const abs = path.join(workspace, rel);
    const stat = fs.lstatSync(abs);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.size > maxBytes) return { status: 'invalid', file: rel, history: null, validation: null };
    const history = JSON.parse(fs.readFileSync(abs, 'utf8'));
    const validation = validateSecurityHistory(history, { signingKey });
    return validation.valid
      ? { status: 'loaded', file: rel, history, validation }
      : { status: 'invalid', file: rel, history: null, validation };
  } catch (error) {
    if (error && error.code === 'ENOENT') return { status: 'missing', file: rel, history: null, validation: null };
    return { status: 'invalid', file: rel, history: null, validation: null };
  }
}

function normalizeRevision(revision) {
  const item = revision && typeof revision === 'object' ? revision : {};
  return {
    repository: item.repository || null,
    sha: item.sha || null,
    ref: item.ref || null,
    event: item.event || null,
    pullRequest: Number.isInteger(item.pullRequest) ? item.pullRequest : null
  };
}

export function appendSecurityHistory({
  graph,
  controlPlane,
  loadedHistory = { status: 'missing', history: null },
  revision = {},
  signingKey = '',
  recordedAt = new Date().toISOString(),
  maxEntries = 60,
  exceptionSnapshot = null,
  exceptionLifecycle = null
} = {}) {
  if (!graphValid(graph)) throw new Error('security graph is required');
  const sourceEntries = loadedHistory && loadedHistory.status === 'loaded' && loadedHistory.history
    ? loadedHistory.history.entries
    : [];
  const previousEntry = sourceEntries.length ? sourceEntries[sourceEntries.length - 1] : null;
  const riskSnapshot = createRiskExposureSnapshot(graph);
  const regression = classifySecurityRegression(riskSnapshot, previousEntry && previousEntry.riskSnapshot);
  const sequence = sourceEntries.length + 1;
  const payload = {
    schemaVersion: 1,
    sequence,
    recordedAt,
    revision: normalizeRevision(revision),
    graphId: graph.graphId || null,
    graphDigest: graphDigest(graph),
    controlPlaneId: controlPlane && controlPlane.controlPlaneId || null,
    controlSummary: controlPlane && controlPlane.summary || null,
    blastRadiusSummary: controlPlane && controlPlane.blastRadius && controlPlane.blastRadius.summary || null,
    riskSnapshot,
    regression: { state: regression.state, summary: regression.summary },
    ...(exceptionSnapshot ? { exceptionSnapshot } : {}),
    ...(exceptionLifecycle ? { exceptionLifecycle: { summary: exceptionLifecycle.summary } } : {}),
    previousEntryHash: previousEntry && previousEntry.entryHash || null
  };
  const entryHash = sha256(canonical(payload));
  const entry = {
    ...payload,
    entryHash,
    signature: signingKey ? hmac(entryHash, signingKey) : null,
    signatureAlgorithm: signingKey ? 'hmac-sha256' : null
  };
  const retained = [...sourceEntries, entry].slice(-Math.max(1, Math.min(200, Number(maxEntries) || 60)));
  const resequenced = retained.map((item, index) => ({ ...item, sequence: index + 1 }));
  if (retained.length !== sourceEntries.length + 1) {
    let previousHash = null;
    for (let i = 0; i < resequenced.length; i++) {
      const nextPayload = { ...entryPayload(resequenced[i]), sequence: i + 1, previousEntryHash: previousHash };
      const nextHash = sha256(canonical(nextPayload));
      resequenced[i] = {
        ...resequenced[i],
        ...nextPayload,
        entryHash: nextHash,
        signature: signingKey ? hmac(nextHash, signingKey) : null,
        signatureAlgorithm: signingKey ? 'hmac-sha256' : null
      };
      previousHash = nextHash;
    }
  }
  const history = {
    schemaVersion: 1,
    seal: {
      integrityAlgorithm: 'sha256-chain',
      signatureAlgorithm: signingKey ? 'hmac-sha256' : null,
      signed: Boolean(signingKey)
    },
    entries: resequenced
  };
  return {
    history,
    entry: history.entries[history.entries.length - 1],
    regression,
    validation: validateSecurityHistory(history, { signingKey })
  };
}

export function securityHistoryMarkdown(result, loadedHistory) {
  if (!result) return '### Security graph history\n\nHistory: unavailable.';
  const regression = result.regression;
  const signatureText = result.history.seal.signed ? 'HMAC-signed' : 'hash-chained';
  const lines = [
    '### Security graph history',
    '',
    'Snapshot **' + result.entry.sequence + '** · ' + signatureText + ' · regression state **' + regression.state + '** · history source **' + (loadedHistory && loadedHistory.status || 'missing') + '**',
    '',
    'Classification compares stable risk-node exposure across history snapshots. It is not a breach forecast or exploitability score.'
  ];
  if (regression.status === 'compared') {
    lines.push('', '**Regression classification:** new risk ' + regression.summary.newRisk + ' · expanded exposure ' + regression.summary.expandedExposure + ' · reduced exposure ' + regression.summary.reducedExposure + ' · resolved risk ' + regression.summary.resolvedRisk + ' · unchanged inherited debt ' + regression.summary.unchangedInheritedDebt);
  } else {
    lines.push('', '**Regression classification:** unavailable until a reviewed history snapshot is committed.');
  }
  if (result.entry.exceptionLifecycle && result.entry.exceptionLifecycle.summary) {
    const lifecycle = result.entry.exceptionLifecycle.summary;
    lines.push('', '**Risk-exception lifecycle:** introduced ' + lifecycle.introduced + ' · renewed ' + lifecycle.renewed + ' · lapsed ' + lifecycle.lapsed + ' · scope changed ' + lifecycle.changedScope);
  }
  return lines.join('\n');
}

export function writeSecurityHistory({ workspace, reportDir = '.devshield', result, historyFile = '.devshield-security-history.json' } = {}) {
  if (!workspace) throw new Error('workspace is required');
  const dir = path.join(workspace, reportDir);
  fs.mkdirSync(dir, { recursive: true });
  const jsonFile = path.join(dir, 'devshield-security-history.json');
  const markdownFile = path.join(dir, 'devshield-security-history.md');
  const candidateFile = path.join(dir, 'devshield-security-history-candidate.json');
  fs.writeFileSync(jsonFile, JSON.stringify({
    currentEntry: result.entry,
    regression: result.regression,
    validation: result.validation
  }, null, 2) + '\n');
  fs.writeFileSync(markdownFile, securityHistoryMarkdown(result, { status: result.entry.sequence > 1 ? 'loaded' : 'missing' }) + '\n');
  fs.writeFileSync(candidateFile, JSON.stringify(result.history, null, 2) + '\n');
  return {
    jsonFile: path.relative(workspace, jsonFile).replace(/\\/g, '/'),
    markdownFile: path.relative(workspace, markdownFile).replace(/\\/g, '/'),
    candidateFile: path.relative(workspace, candidateFile).replace(/\\/g, '/'),
    committedHistoryFile: historyFile
  };
}
