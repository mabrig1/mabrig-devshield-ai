import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

const severityScore = { low: 25, medium: 50, high: 75, critical: 100 };

function hash(value) {
  return crypto.createHash('sha256').update(String(value)).digest('hex');
}

function safeRelative(value) {
  const rel = String(value || '').trim();
  if (!rel || path.isAbsolute(rel) || rel.includes('\\') || /[\x00-\x1f\x7f]/.test(rel)) return false;
  return !rel.split('/').some(part => !part || part === '.' || part === '..');
}

function graphValid(graph) {
  return graph && typeof graph === 'object' && Array.isArray(graph.nodes) && Array.isArray(graph.edges) && Array.isArray(graph.paths);
}

function byId(items) {
  return new Map((Array.isArray(items) ? items : []).filter(item => item && item.id).map(item => [item.id, item]));
}

function diffItems(current, previous) {
  const a = byId(current);
  const b = byId(previous);
  return {
    added: [...a.keys()].filter(id => !b.has(id)).sort(),
    removed: [...b.keys()].filter(id => !a.has(id)).sort(),
    unchanged: [...a.keys()].filter(id => b.has(id)).sort()
  };
}

export function loadSecurityGraphBaseline({ workspace, baselineFile = '.devshield-security-graph-baseline.json', maxBytes = 8 * 1024 * 1024 } = {}) {
  if (!workspace) throw new Error('workspace is required');
  const rel = String(baselineFile || '').trim();
  if (!safeRelative(rel)) return { status: 'invalid-path', file: rel || null, graph: null };
  try {
    const abs = path.join(workspace, rel);
    const stat = fs.lstatSync(abs);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.size > maxBytes) return { status: 'invalid', file: rel, graph: null };
    const parsed = JSON.parse(fs.readFileSync(abs, 'utf8'));
    if (!graphValid(parsed)) return { status: 'invalid', file: rel, graph: null };
    return { status: 'loaded', file: rel, graph: parsed };
  } catch (error) {
    if (error && error.code === 'ENOENT') return { status: 'missing', file: rel, graph: null };
    return { status: 'invalid', file: rel, graph: null };
  }
}

export function diffSecurityGraphs(currentGraph, baselineGraph) {
  if (!graphValid(currentGraph)) throw new Error('current graph is required');
  if (!graphValid(baselineGraph)) {
    return {
      status: 'no-baseline',
      baselineGraphId: null,
      currentGraphId: currentGraph.graphId || null,
      nodes: { added: [], removed: [], unchanged: [] },
      edges: { added: [], removed: [], unchanged: [] },
      paths: { added: [], removed: [], unchanged: [] },
      summary: { addedNodes: 0, removedNodes: 0, addedEdges: 0, removedEdges: 0, addedPaths: 0, removedPaths: 0, resolvedFindings: 0, newFindings: 0 }
    };
  }
  const nodes = diffItems(currentGraph.nodes, baselineGraph.nodes);
  const edges = diffItems(currentGraph.edges, baselineGraph.edges);
  const paths = diffItems(currentGraph.paths, baselineGraph.paths);
  const currentNodes = byId(currentGraph.nodes);
  const previousNodes = byId(baselineGraph.nodes);
  const resolvedFindingNodeIds = nodes.removed.filter(id => previousNodes.get(id) && previousNodes.get(id).type === 'finding');
  const newFindingNodeIds = nodes.added.filter(id => currentNodes.get(id) && currentNodes.get(id).type === 'finding');
  return {
    status: 'compared',
    baselineGraphId: baselineGraph.graphId || null,
    currentGraphId: currentGraph.graphId || null,
    nodes,
    edges,
    paths,
    resolvedFindingNodeIds,
    newFindingNodeIds,
    summary: {
      addedNodes: nodes.added.length,
      removedNodes: nodes.removed.length,
      addedEdges: edges.added.length,
      removedEdges: edges.removed.length,
      addedPaths: paths.added.length,
      removedPaths: paths.removed.length,
      resolvedFindings: resolvedFindingNodeIds.length,
      newFindings: newFindingNodeIds.length
    }
  };
}

function codeownersRegex(pattern) {
  let source = String(pattern || '').trim();
  if (!source || source.startsWith('!')) return null;
  const anchored = source.startsWith('/');
  if (anchored) source = source.slice(1);
  const directoryOnly = source.endsWith('/');
  if (directoryOnly) source = source.slice(0, -1);
  let out = '';
  for (let i = 0; i < source.length; i++) {
    const ch = source[i];
    if (ch === '*') {
      if (source[i + 1] === '*') {
        out += '.*';
        i++;
      } else out += '[^/]*';
    } else if (ch === '?') out += '[^/]';
    else out += ch.replace(/[\\^$.*+?()[\]{}|]/g, '\\$&');
  }
  if (!anchored && !source.includes('/')) out = '(?:^|.*/)' + out;
  else out = '^' + out;
  if (directoryOnly) out += '(?:/.*)?';
  return new RegExp(out + '$');
}

function parseCodeowners(raw) {
  const rules = [];
  for (const original of String(raw || '').split(/\r?\n/)) {
    const line = original.trim();
    if (!line || line.startsWith('#')) continue;
    const parts = line.split(/\s+/);
    if (parts.length < 2) continue;
    const owners = parts.slice(1).filter(owner => owner.startsWith('@'));
    if (!owners.length) continue;
    const regex = codeownersRegex(parts[0]);
    if (regex) rules.push({ pattern: parts[0], owners, regex });
  }
  return rules;
}

export function loadCodeowners({ workspace, maxBytes = 512 * 1024 } = {}) {
  if (!workspace) throw new Error('workspace is required');
  for (const rel of ['.github/CODEOWNERS', 'CODEOWNERS', 'docs/CODEOWNERS']) {
    try {
      const abs = path.join(workspace, rel);
      const stat = fs.lstatSync(abs);
      if (!stat.isFile() || stat.isSymbolicLink() || stat.size > maxBytes) continue;
      return { status: 'loaded', file: rel, rules: parseCodeowners(fs.readFileSync(abs, 'utf8')) };
    } catch (error) {
      if (error && error.code !== 'ENOENT') return { status: 'invalid', file: rel, rules: [] };
    }
  }
  return { status: 'missing', file: null, rules: [] };
}

export function ownerHintForFile(rel, ownership) {
  if (!safeRelative(rel) || !ownership || ownership.status !== 'loaded') return { owners: [], matchedPattern: null, source: ownership ? ownership.file : null };
  let match = null;
  for (const rule of ownership.rules || []) {
    rule.regex.lastIndex = 0;
    if (rule.regex.test(rel)) match = rule;
  }
  return match ? { owners: [...match.owners], matchedPattern: match.pattern, source: ownership.file } : { owners: [], matchedPattern: null, source: ownership.file };
}

function adjacency(graph) {
  const map = new Map();
  for (const edge of graph.edges || []) {
    const a = map.get(edge.from) || [];
    a.push({ nodeId: edge.to, edge });
    map.set(edge.from, a);
    const b = map.get(edge.to) || [];
    b.push({ nodeId: edge.from, edge });
    map.set(edge.to, b);
  }
  return map;
}

export function calculateBlastRadius(graph, changedFiles = [], { maxDepth = 3, maxImpacted = 250 } = {}) {
  if (!graphValid(graph)) throw new Error('graph is required');
  const nodes = byId(graph.nodes);
  const fileIds = new Map(graph.nodes.filter(node => node.type === 'file' && node.attributes && node.attributes.path).map(node => [node.attributes.path, node.id]));
  const starts = [...new Set((changedFiles || []).filter(safeRelative))].map(file => ({ file, nodeId: fileIds.get(file) })).filter(item => item.nodeId).slice(0, 60);
  const links = adjacency(graph);
  const reached = new Map();
  for (const start of starts) {
    const queue = [{ nodeId: start.nodeId, depth: 0, contextual: false, edgeIds: [] }];
    const seen = new Map([[start.nodeId, 0]]);
    while (queue.length) {
      const current = queue.shift();
      if (current.depth >= maxDepth) continue;
      for (const next of links.get(current.nodeId) || []) {
        const depth = current.depth + 1;
        const contextual = current.contextual || next.edge.confidence !== 'direct';
        if ((seen.get(next.nodeId) ?? Infinity) <= depth) continue;
        seen.set(next.nodeId, depth);
        if (next.nodeId !== start.nodeId) {
          const candidate = {
            nodeId: next.nodeId,
            depth,
            confidence: contextual ? 'contextual' : 'evidence-linked',
            viaChangedFile: start.file,
            edgeIds: [...current.edgeIds, next.edge.id]
          };
          const old = reached.get(next.nodeId);
          if (!old || candidate.depth < old.depth || (candidate.depth === old.depth && candidate.confidence === 'evidence-linked' && old.confidence !== 'evidence-linked')) reached.set(next.nodeId, candidate);
        }
        queue.push({ nodeId: next.nodeId, depth, contextual, edgeIds: [...current.edgeIds, next.edge.id] });
      }
    }
  }
  const impacted = [...reached.values()].map(item => ({ ...item, node: nodes.get(item.nodeId) })).filter(item => item.node)
    .sort((a, b) => a.depth - b.depth || a.node.type.localeCompare(b.node.type) || a.nodeId.localeCompare(b.nodeId)).slice(0, maxImpacted)
    .map(item => ({
      nodeId: item.nodeId,
      depth: item.depth,
      confidence: item.confidence,
      viaChangedFile: item.viaChangedFile,
      edgeIds: item.edgeIds,
      nodeType: item.node.type,
      label: item.node.label,
      attributes: item.node.attributes || {}
    }));
  const count = type => impacted.filter(item => item.nodeType === type).length;
  return {
    changedFilesMatched: starts.length,
    changedFiles: starts.map(item => item.file),
    maxDepth,
    impacted,
    summary: {
      impactedNodes: impacted.length,
      files: count('file'),
      packages: count('package'),
      findings: count('finding'),
      advisories: count('advisory'),
      evidenceLinked: impacted.filter(item => item.confidence === 'evidence-linked').length,
      contextual: impacted.filter(item => item.confidence === 'contextual').length
    }
  };
}

function prioritySeed(node) {
  if (node.type === 'finding') {
    const severity = node.attributes && node.attributes.severity || 'low';
    return { score: severityScore[severity] || 25, reason: 'finding:' + severity };
  }
  if (node.type === 'advisory') {
    const severity = node.attributes && node.attributes.severity || 'medium';
    return { score: severityScore[severity] || 50, reason: 'advisory:' + severity };
  }
  return null;
}

export function propagateReviewPriority(graph, { maxDepth = 4 } = {}) {
  if (!graphValid(graph)) throw new Error('graph is required');
  const nodes = byId(graph.nodes);
  const links = adjacency(graph);
  const best = new Map();
  for (const node of graph.nodes) {
    const seed = prioritySeed(node);
    if (!seed) continue;
    best.set(node.id, { nodeId: node.id, score: seed.score, seedNodeId: node.id, reason: seed.reason, depth: 0, confidence: 'evidence-linked' });
    const queue = [{ nodeId: node.id, score: seed.score, depth: 0, contextual: false }];
    const seen = new Map([[node.id, seed.score]]);
    while (queue.length) {
      const current = queue.shift();
      if (current.depth >= maxDepth) continue;
      for (const next of links.get(current.nodeId) || []) {
        const contextual = current.contextual || next.edge.confidence !== 'direct';
        const score = Math.round(current.score * (next.edge.confidence === 'direct' ? 0.72 : 0.42));
        if (score < 10 || (seen.get(next.nodeId) || 0) >= score) continue;
        seen.set(next.nodeId, score);
        const candidate = { nodeId: next.nodeId, score, seedNodeId: node.id, reason: seed.reason, depth: current.depth + 1, confidence: contextual ? 'contextual' : 'evidence-linked' };
        if (!best.has(next.nodeId) || candidate.score > best.get(next.nodeId).score) best.set(next.nodeId, candidate);
        queue.push({ nodeId: next.nodeId, score, depth: current.depth + 1, contextual });
      }
    }
  }
  const ranked = [...best.values()].map(item => {
    const node = nodes.get(item.nodeId);
    return { ...item, nodeType: node ? node.type : 'unknown', label: node ? node.label : item.nodeId, attributes: node && node.attributes || {} };
  }).sort((a, b) => b.score - a.score || a.depth - b.depth || a.nodeId.localeCompare(b.nodeId));
  return {
    methodology: 'Evidence-weighted review-priority propagation; not exploit probability or CVSS.',
    maxDepth,
    ranked,
    summary: {
      rankedNodes: ranked.length,
      highPriority: ranked.filter(item => item.score >= 75).length,
      mediumPriority: ranked.filter(item => item.score >= 50 && item.score < 75).length,
      contextual: ranked.filter(item => item.confidence === 'contextual').length
    }
  };
}

export function verifyRemediationObservations(graph, remediationPlan) {
  if (!graphValid(graph)) throw new Error('graph is required');
  const findings = graph.nodes.filter(node => node.type === 'finding');
  const results = (remediationPlan && Array.isArray(remediationPlan.candidates) ? remediationPlan.candidates : []).map(candidate => {
    const matches = findings.filter(node => node.attributes && node.attributes.rule === candidate.rule && node.attributes.file === candidate.file);
    return {
      candidateId: candidate.id,
      rule: candidate.rule,
      file: candidate.file,
      plannedLine: candidate.line,
      status: matches.length ? 'still-observed' : 'not-observed-after-scan',
      matchingFindingNodeIds: matches.map(node => node.id),
      note: matches.length ? 'A matching rule/file finding remains in the current graph.' : 'No matching rule/file finding is present in the current graph. This is verification evidence, not proof the underlying issue is impossible.'
    };
  });
  return { candidates: results, summary: { checked: results.length, stillObserved: results.filter(item => item.status === 'still-observed').length, notObserved: results.filter(item => item.status === 'not-observed-after-scan').length } };
}

function ownershipSummary(graph, ownership, blast) {
  const files = new Map(graph.nodes.filter(node => node.type === 'file' && node.attributes && node.attributes.path).map(node => [node.id, node]));
  const relevantPaths = new Set(Array.isArray(blast.changedFiles) ? blast.changedFiles : []);
  for (const item of blast.impacted || []) {
    if (item.nodeType === 'file' && item.attributes && item.attributes.path) relevantPaths.add(item.attributes.path);
  }
  const hints = [...relevantPaths].sort().map(file => ({ file, ...ownerHintForFile(file, ownership) }));
  const counts = new Map();
  for (const hint of hints) for (const owner of hint.owners) counts.set(owner, (counts.get(owner) || 0) + 1);
  return {
    sourceStatus: ownership.status,
    sourceFile: ownership.file,
    resolution: 'Best-effort CODEOWNERS hint; GitHub review requirements remain authoritative.',
    hints,
    owners: [...counts.entries()].map(([owner, filesCount]) => ({ owner, files: filesCount })).sort((a, b) => b.files - a.files || a.owner.localeCompare(b.owner))
  };
}

export function createSecurityControlPlane({ graph, baseline = { status: 'missing', graph: null }, changedFiles = [], ownership = { status: 'missing', file: null, rules: [] }, remediationPlan = null, mode = 'auto' } = {}) {
  const normalizedMode = ['off', 'auto', 'on'].includes(mode) ? mode : 'auto';
  if (!graphValid(graph)) throw new Error('security graph is required');
  if (normalizedMode === 'off') {
    return {
      schemaVersion: 1,
      controlPlaneId: 'disabled',
      mode: normalizedMode,
      state: 'disabled',
      summary: { graphChanges: 0, blastRadiusNodes: 0, rankedNodes: 0, ownershipHints: 0, remediationChecks: 0 },
      guardrails: { exploitProbability: false, automaticOwnershipAssignment: false, repositoryMutation: false },
      graphDiff: diffSecurityGraphs(graph, null),
      blastRadius: { changedFilesMatched: 0, changedFiles: [], impacted: [], summary: { impactedNodes: 0, files: 0, packages: 0, findings: 0, advisories: 0, evidenceLinked: 0, contextual: 0 } },
      reviewPriority: { methodology: 'disabled', ranked: [], summary: { rankedNodes: 0, highPriority: 0, mediumPriority: 0, contextual: 0 } },
      ownership: { sourceStatus: ownership.status, sourceFile: ownership.file, hints: [], owners: [] },
      remediationVerification: { candidates: [], summary: { checked: 0, stillObserved: 0, notObserved: 0 } }
    };
  }
  const graphDiff = diffSecurityGraphs(graph, baseline && baseline.graph);
  const blastRadius = calculateBlastRadius(graph, changedFiles);
  const reviewPriority = propagateReviewPriority(graph);
  const ownershipResult = ownershipSummary(graph, ownership, blastRadius);
  const remediationVerification = verifyRemediationObservations(graph, remediationPlan);
  const signature = JSON.stringify({
    graphId: graph.graphId,
    baselineGraphId: graphDiff.baselineGraphId,
    diff: graphDiff.summary,
    blast: blastRadius.summary,
    priority: reviewPriority.summary,
    owners: ownershipResult.owners,
    remediation: remediationVerification.summary
  });
  return {
    schemaVersion: 1,
    controlPlaneId: hash(signature).slice(0, 16),
    mode: normalizedMode,
    generatedAt: new Date().toISOString(),
    state: 'ready',
    objective: 'Turn graph evidence into review coordination without converting heuristics into exploit probability.',
    summary: {
      graphChanges: graphDiff.summary.addedNodes + graphDiff.summary.removedNodes + graphDiff.summary.addedEdges + graphDiff.summary.removedEdges,
      blastRadiusNodes: blastRadius.summary.impactedNodes,
      rankedNodes: reviewPriority.summary.rankedNodes,
      ownershipHints: ownershipResult.hints.length,
      remediationChecks: remediationVerification.summary.checked
    },
    guardrails: {
      exploitProbability: false,
      cvssReplacement: false,
      automaticOwnershipAssignment: false,
      repositoryMutation: false,
      codeownersHintsAreBestEffort: true,
      remediationAbsenceIsNotProofOfImpossibility: true
    },
    baseline: { status: baseline && baseline.status || 'missing', file: baseline && baseline.file || null },
    graphDiff,
    blastRadius,
    reviewPriority,
    ownership: ownershipResult,
    remediationVerification
  };
}

export function securityControlPlaneMarkdown(control) {
  if (!control || control.state === 'disabled') return '### Security control plane\n\nControl plane: disabled.';
  const lines = [
    '### Security control plane',
    '',
    'Control plane ' + control.controlPlaneId + ' · graph changes **' + control.summary.graphChanges + '** · blast-radius nodes **' + control.summary.blastRadiusNodes + '** · ranked nodes **' + control.summary.rankedNodes + '** · ownership hints **' + control.summary.ownershipHints + '**',
    '',
    'Review-priority propagation is evidence-weighted triage, not exploit probability. CODEOWNERS resolution is a best-effort ownership hint.'
  ];
  if (control.graphDiff.status === 'compared') lines.push('', '**Graph diff:** +' + control.graphDiff.summary.addedNodes + ' / -' + control.graphDiff.summary.removedNodes + ' nodes · +' + control.graphDiff.summary.addedEdges + ' / -' + control.graphDiff.summary.removedEdges + ' edges · new findings ' + control.graphDiff.summary.newFindings + ' · no-longer-observed findings ' + control.graphDiff.summary.resolvedFindings);
  else lines.push('', '**Graph diff:** no committed graph baseline is available yet.');
  if (control.reviewPriority.ranked.length) {
    lines.push('', '**Top review-priority nodes**');
    for (const item of control.reviewPriority.ranked.slice(0, 5)) lines.push('- **' + item.score + '/100** ' + item.label + ' (' + item.confidence + ')');
  }
  if (control.ownership.owners.length) lines.push('', '**Ownership hints:** ' + control.ownership.owners.slice(0, 5).map(item => item.owner + ' (' + item.files + ')').join(' · '));
  if (control.remediationVerification.summary.checked) lines.push('', '**Remediation verification:** checked ' + control.remediationVerification.summary.checked + ' · still observed ' + control.remediationVerification.summary.stillObserved + ' · not observed after scan ' + control.remediationVerification.summary.notObserved);
  return lines.join('\n');
}

export function writeSecurityControlPlane({ workspace, reportDir = '.devshield', control, graph }) {
  const dir = path.join(workspace, reportDir);
  fs.mkdirSync(dir, { recursive: true });
  const jsonFile = path.join(dir, 'devshield-control-plane.json');
  const markdownFile = path.join(dir, 'devshield-control-plane.md');
  const baselineCandidateFile = path.join(dir, 'devshield-security-graph-baseline-candidate.json');
  fs.writeFileSync(jsonFile, JSON.stringify(control, null, 2) + '\n');
  fs.writeFileSync(markdownFile, securityControlPlaneMarkdown(control) + '\n');
  fs.writeFileSync(baselineCandidateFile, JSON.stringify(graph, null, 2) + '\n');
  return {
    jsonFile: path.relative(workspace, jsonFile).replace(/\\/g, '/'),
    markdownFile: path.relative(workspace, markdownFile).replace(/\\/g, '/'),
    baselineCandidateFile: path.relative(workspace, baselineCandidateFile).replace(/\\/g, '/')
  };
}
