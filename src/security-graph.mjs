import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

const severityRank = { low: 1, medium: 2, high: 3, critical: 4 };
const sourceExtensions = ['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.mts', '.cts', '.vue', '.svelte'];

function hash(value) {
  return crypto.createHash('sha256').update(String(value)).digest('hex');
}

function stableId(prefix, value) {
  return `${prefix}-${hash(value).slice(0, 16)}`;
}

function safeRelative(rel) {
  const value = String(rel || '');
  if (!value || path.isAbsolute(value) || value.includes('\\') || /[\x00-\x1f\x7f]/.test(value)) return false;
  const parts = value.split('/');
  return !parts.some(part => !part || part === '.' || part === '..');
}

function readText(workspace, rel, maxFileBytes) {
  if (!safeRelative(rel)) return '';
  const abs = path.join(workspace, rel);
  try {
    const stat = fs.lstatSync(abs);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.size > maxFileBytes) return '';
    const raw = fs.readFileSync(abs);
    if (raw.includes(0)) return '';
    return raw.toString('utf8');
  } catch {
    return '';
  }
}

function fileRole(rel) {
  if (/^\.github\/workflows\/[^/]+\.ya?ml$/i.test(rel)) return 'workflow';
  if (/(^|\/)(pages\/api|app\/api|api|routes?)(\/|$)/i.test(rel) || /\/route\.[cm]?[jt]sx?$/i.test(rel)) return 'api-route';
  if (/(^|\/)(Dockerfile(?:\.[^/]+)?|docker-compose\.ya?ml|compose\.ya?ml)$/i.test(rel)) return 'container';
  if (/\.tf$/i.test(rel) || /(^|\/)(k8s|kubernetes|helm|charts?)(\/|$)/i.test(rel)) return 'infrastructure';
  if (/\.(?:[cm]?[jt]sx?|vue|svelte)$/i.test(rel)) return 'source';
  return 'file';
}

function normalizePackageSpecifier(specifier) {
  const value = String(specifier || '').trim();
  if (!value || value.startsWith('.') || value.startsWith('/') || value.startsWith('#') || value.startsWith('node:')) return null;
  if (value.startsWith('@')) {
    const parts = value.split('/');
    return parts.length >= 2 ? `${parts[0]}/${parts[1]}` : null;
  }
  return value.split('/')[0] || null;
}

function resolveRelativeImport(importer, specifier, fileSet) {
  if (!specifier || !specifier.startsWith('.')) return null;
  const base = path.posix.normalize(path.posix.join(path.posix.dirname(importer), specifier));
  if (!safeRelative(base)) return null;
  const candidates = [base];
  for (const ext of sourceExtensions) candidates.push(`${base}${ext}`);
  for (const ext of sourceExtensions) candidates.push(`${base}/index${ext}`);
  return candidates.find(candidate => fileSet.has(candidate)) || null;
}

function parseImports(content) {
  const imports = [];
  const pattern = /\b(?:from\s*|require\s*\(\s*|import\s*\(\s*|import\s*)['"]([^'"]+)['"]/g;
  let match;
  while ((match = pattern.exec(content))) {
    if (match[1]) imports.push(match[1]);
    if (imports.length >= 500) break;
  }
  return imports;
}

function workflowSignals(content) {
  const dependencyInstall = /\b(?:npm\s+(?:ci|install)|pnpm\s+install|yarn\s+install|bun\s+install)\b/i.test(content);
  const deployment = /\b(?:deploy|vercel|kubectl|helm|docker\s+push|aws\s+(?:ecs|lambda)|gcloud\s+(?:run|functions)|az\s+webapp)\b/i.test(content);
  return { dependencyInstall, deployment };
}

function nodeLabel(node) {
  return String(node.label || node.id).replace(/[\r\n\t]/g, ' ').slice(0, 160);
}

function confidenceWeight(value) {
  return value === 'direct' ? 2 : value === 'contextual' ? 1 : 0;
}

function weakestConfidence(edges) {
  return edges.every(edge => edge.confidence === 'direct') ? 'evidence-linked' : 'contextual';
}

function findingScore(node) {
  if (node.type !== 'finding') return 0;
  return (severityRank[node.attributes?.severity] || 0) * 100;
}

function targetScore(node) {
  if (!node) return 0;
  if (node.type === 'finding') return 500 + findingScore(node);
  if (node.type === 'file' && node.attributes?.role === 'api-route') return 240;
  if (node.type === 'file' && node.attributes?.role === 'workflow') {
    return node.attributes?.deployment ? 220 : node.attributes?.dependencyInstall ? 200 : 150;
  }
  if (node.type === 'advisory') return 400;
  return 0;
}

function edgeKey(from, to, type) {
  return `${from}\0${to}\0${type}`;
}

function addNode(nodes, node) {
  if (!nodes.has(node.id)) nodes.set(node.id, node);
  return nodes.get(node.id);
}

function addEdge(edges, edge) {
  const key = edgeKey(edge.from, edge.to, edge.type);
  if (!edges.has(key)) {
    edges.set(key, {
      id: stableId('edge', key),
      ...edge
    });
  }
  return edges.get(key);
}

function findingNode(finding) {
  const fingerprint = finding?.fingerprint || hash(`${finding?.rule || 'finding'}:${finding?.file || ''}:${finding?.line || 0}`).slice(0, 32);
  return {
    id: stableId('finding', fingerprint),
    type: 'finding',
    label: `${String(finding?.severity || 'medium').toUpperCase()} ${finding?.rule || 'security-finding'}`,
    attributes: {
      fingerprint,
      rule: finding?.rule || null,
      severity: finding?.severity || 'medium',
      category: finding?.category || 'security',
      file: finding?.file || null,
      line: finding?.line || null,
      status: finding?.status || 'new'
    }
  };
}

function packageNode(item) {
  const identity = item.identity || item.packageUrl || [item.installName || item.name || 'package', item.version || 'unknown'].join('@');
  return {
    id: stableId('package', identity),
    type: 'package',
    label: identity,
    attributes: {
      identity,
      name: item.name || null,
      installName: item.installName || null,
      version: item.version || null,
      declaredByRoot: Array.isArray(item.declaredByRoot) ? item.declaredByRoot : [],
      installScript: item.installScript || 'not-declared',
      metadataSeverity: item.metadataSeverity || null,
      knownDependencySeverity: item.knownDependencySeverity || null
    }
  };
}

function fileNode(rel, signals = {}) {
  return {
    id: stableId('file', rel),
    type: 'file',
    label: rel,
    attributes: {
      path: rel,
      role: fileRole(rel),
      dependencyInstall: Boolean(signals.dependencyInstall),
      deployment: Boolean(signals.deployment)
    }
  };
}

function advisoryNode(finding, packageId) {
  const ghsa = finding?.dependency?.advisoryGhsaId || finding?.dependency?.advisoryUrl || finding?.fingerprint || finding?.rule || 'advisory';
  return {
    id: stableId('advisory', `${packageId}:${ghsa}`),
    type: 'advisory',
    label: finding?.dependency?.advisoryGhsaId || 'Dependency advisory',
    attributes: {
      ghsaId: finding?.dependency?.advisoryGhsaId || null,
      advisoryUrl: finding?.dependency?.advisoryUrl || null,
      severity: finding?.severity || 'medium',
      fingerprint: finding?.fingerprint || null
    }
  };
}

function derivePaths(nodes, edges) {
  const nodeMap = new Map(nodes.map(node => [node.id, node]));
  const outgoing = new Map();
  for (const edge of edges) {
    const list = outgoing.get(edge.from) || [];
    list.push(edge);
    outgoing.set(edge.from, list);
  }

  const packages = nodes.filter(node => node.type === 'package');
  const found = new Map();

  for (const start of packages) {
    const queue = [{ nodeId: start.id, nodeIds: [start.id], edgeIds: [], edgeObjects: [] }];
    const visitedDepth = new Map([[start.id, 0]]);

    while (queue.length) {
      const current = queue.shift();
      const depth = current.edgeIds.length;
      if (depth >= 5) continue;

      for (const edge of outgoing.get(current.nodeId) || []) {
        if (current.nodeIds.includes(edge.to)) continue;
        const nextNode = nodeMap.get(edge.to);
        if (!nextNode) continue;
        const nextNodeIds = [...current.nodeIds, edge.to];
        const nextEdgeIds = [...current.edgeIds, edge.id];
        const nextEdgeObjects = [...current.edgeObjects, edge];
        const nextDepth = nextEdgeIds.length;

        const score = targetScore(nextNode);
        if (score > 0) {
          const key = `${start.id}\0${nextNode.id}`;
          const contextualPenalty = nextEdgeObjects.filter(item => item.confidence !== 'direct').length * 30;
          const roleBonus = nextNode.type === 'file' && nextNode.attributes?.role === 'api-route' ? 30 : 0;
          const pathScore = score + roleBonus + (nextDepth >= 2 ? 20 : 0) - contextualPenalty - nextDepth;
          const existing = found.get(key);
          if (!existing || pathScore > existing.score || (pathScore === existing.score && nextDepth < existing.edgeIds.length)) {
            let title = 'Dependency reaches repository security context';
            let explanation = 'The graph links a dependency to security-relevant repository context through traceable edges.';
            let verification = 'Review each edge and confirm runtime reachability before treating this path as exploitable.';
            if (nextNode.type === 'finding') {
              title = 'Dependency is connected to a security finding';
              explanation = 'A dependency reaches a file or workflow that carries a deterministic DevShield finding.';
              verification = 'Confirm the dependency is executed along this import/workflow path and remediate the linked finding independently.';
            } else if (nextNode.type === 'advisory') {
              title = 'Dependency has linked advisory evidence';
              explanation = 'GitHub dependency-review evidence is attached to this package identity.';
              verification = 'Confirm the affected version and vulnerable functionality, then upgrade or replace the package.';
            } else if (nextNode.attributes?.role === 'api-route') {
              title = 'Dependency reaches an API-route import chain';
              explanation = 'Static import relationships connect this dependency to a file classified as an API route.';
              verification = 'Confirm the route executes the imported code and whether the package behavior is reachable from untrusted requests.';
            } else if (nextNode.attributes?.role === 'workflow') {
              title = nextNode.attributes?.deployment
                ? 'Dependency is connected to deployment workflow context'
                : 'Dependency is connected to CI workflow context';
              explanation = 'The repository graph links this dependency to a workflow context. Contextual install edges do not prove every package is installed in every job.';
              verification = 'Inspect the workflow job and package-manager flags to confirm whether this dependency is installed or executed.';
            }

            found.set(key, {
              id: stableId('path', `${start.id}:${nextNode.id}:${nextEdgeIds.join(',')}`),
              score: pathScore,
              confidence: weakestConfidence(nextEdgeObjects),
              title,
              explanation,
              verification,
              startNode: start.id,
              targetNode: nextNode.id,
              nodeIds: nextNodeIds,
              edgeIds: nextEdgeIds
            });
          }
        }

        const previous = visitedDepth.get(edge.to);
        if (previous == null || nextDepth < previous) {
          visitedDepth.set(edge.to, nextDepth);
          queue.push({
            nodeId: edge.to,
            nodeIds: nextNodeIds,
            edgeIds: nextEdgeIds,
            edgeObjects: nextEdgeObjects
          });
        }
      }
    }
  }

  return [...found.values()]
    .sort((a, b) => b.score - a.score || a.id.localeCompare(b.id))
    .slice(0, 40);
}

export function createRepositorySecurityGraph({
  workspace,
  repositoryFiles = [],
  findings = [],
  dependencyMission = null,
  mode = 'auto',
  maxFileBytes = 750_000,
  maxNodes = 500,
  maxEdges = 1200
} = {}) {
  const normalizedMode = ['off', 'auto', 'on'].includes(mode) ? mode : 'auto';
  if (normalizedMode === 'off') {
    return {
      schemaVersion: 1,
      graphId: 'disabled',
      mode: normalizedMode,
      state: 'disabled',
      summary: { nodes: 0, edges: 0, directEdges: 0, contextualEdges: 0, paths: 0, packages: 0, files: 0, findings: 0, advisories: 0 },
      guardrails: { exploitabilityInference: false, sourceSnippetsStored: false, secretValuesStored: false, repositoryMutation: false },
      nodes: [], edges: [], paths: []
    };
  }
  if (!workspace) throw new Error('workspace is required');

  const fileSet = new Set((Array.isArray(repositoryFiles) ? repositoryFiles : []).filter(safeRelative).slice(0, 500));
  const nodes = new Map();
  const edges = new Map();
  const workflowSignalsByFile = new Map();

  for (const rel of fileSet) {
    if (!/^\.github\/workflows\/[^/]+\.ya?ml$/i.test(rel)) continue;
    const signals = workflowSignals(readText(workspace, rel, maxFileBytes));
    workflowSignalsByFile.set(rel, signals);
    addNode(nodes, fileNode(rel, signals));
  }

  const relevantFindings = (Array.isArray(findings) ? findings : []).filter(Boolean).slice(0, 300);
  for (const finding of relevantFindings) {
    if (!safeRelative(finding.file)) continue;
    const file = addNode(nodes, fileNode(finding.file, workflowSignalsByFile.get(finding.file)));
    const findingItem = addNode(nodes, findingNode(finding));
    addEdge(edges, {
      from: file.id,
      to: findingItem.id,
      type: 'has-finding',
      confidence: 'direct',
      evidence: [{ kind: 'devshield-finding', file: finding.file, line: finding.line || 1, fingerprint: findingItem.attributes.fingerprint }]
    });
  }

  const priorityPackages = Array.isArray(dependencyMission?.priorityQueue) ? dependencyMission.priorityQueue.slice(0, 50) : [];
  for (const item of priorityPackages) {
    const pkg = addNode(nodes, packageNode(item));

    for (const rel of (item.applicationReferences || []).filter(safeRelative).slice(0, 30)) {
      const file = addNode(nodes, fileNode(rel, workflowSignalsByFile.get(rel)));
      addEdge(edges, {
        from: pkg.id,
        to: file.id,
        type: 'referenced-by',
        confidence: 'direct',
        evidence: [{ kind: 'package-import', file: rel, package: item.installName || item.name || item.identity }]
      });
    }

    for (const known of (item.knownDependencyFindings || []).slice(0, 10)) {
      if (!known?.dependency?.advisoryGhsaId && known?.rule !== 'dependency-vulnerability') continue;
      const advisory = addNode(nodes, advisoryNode(known, pkg.id));
      addEdge(edges, {
        from: pkg.id,
        to: advisory.id,
        type: 'has-advisory',
        confidence: 'direct',
        evidence: [{ kind: 'github-dependency-review', fingerprint: known.fingerprint || null, advisoryGhsaId: known.dependency?.advisoryGhsaId || null }]
      });
    }
  }

  const sourceFiles = [...fileSet].filter(rel => sourceExtensions.includes(path.posix.extname(rel).toLowerCase())).slice(0, 350);
  for (const importer of sourceFiles) {
    const content = readText(workspace, importer, maxFileBytes);
    if (!content) continue;
    for (const specifier of parseImports(content)) {
      const target = resolveRelativeImport(importer, specifier, fileSet);
      if (!target) continue;
      const targetNode = addNode(nodes, fileNode(target, workflowSignalsByFile.get(target)));
      const importerNode = addNode(nodes, fileNode(importer, workflowSignalsByFile.get(importer)));
      addEdge(edges, {
        from: targetNode.id,
        to: importerNode.id,
        type: 'consumed-by',
        confidence: 'direct',
        evidence: [{ kind: 'relative-import', file: importer, target }]
      });
      if (edges.size >= maxEdges) break;
    }
    if (edges.size >= maxEdges) break;
  }

  const installWorkflows = [...workflowSignalsByFile.entries()]
    .filter(([, signals]) => signals.dependencyInstall)
    .slice(0, 10);
  for (const item of priorityPackages.slice(0, 30)) {
    const pkgId = stableId('package', item.identity || item.packageUrl || [item.installName || item.name || 'package', item.version || 'unknown'].join('@'));
    if (!nodes.has(pkgId)) continue;
    for (const [workflow, signals] of installWorkflows) {
      const workflowNode = addNode(nodes, fileNode(workflow, signals));
      addEdge(edges, {
        from: pkgId,
        to: workflowNode.id,
        type: 'installation-context',
        confidence: 'contextual',
        evidence: [{ kind: 'workflow-package-install-command', file: workflow }]
      });
      if (edges.size >= maxEdges) break;
    }
    if (edges.size >= maxEdges) break;
  }

  let nodeArray = [...nodes.values()];
  let edgeArray = [...edges.values()];
  if (nodeArray.length > maxNodes) {
    const keep = new Set(nodeArray
      .sort((a, b) => {
        const rank = type => type === 'package' ? 5 : type === 'finding' ? 4 : type === 'advisory' ? 3 : type === 'file' ? 2 : 1;
        return rank(b.type) - rank(a.type) || a.id.localeCompare(b.id);
      })
      .slice(0, maxNodes)
      .map(node => node.id));
    nodeArray = nodeArray.filter(node => keep.has(node.id));
    edgeArray = edgeArray.filter(edge => keep.has(edge.from) && keep.has(edge.to));
  }
  if (edgeArray.length > maxEdges) edgeArray = edgeArray.slice(0, maxEdges);

  const paths = derivePaths(nodeArray, edgeArray);
  const signatures = [
    ...nodeArray.map(node => `${node.type}:${node.id}`).sort(),
    ...edgeArray.map(edge => `${edge.type}:${edge.from}:${edge.to}:${edge.confidence}`).sort()
  ];
  const counts = type => nodeArray.filter(node => node.type === type).length;

  return {
    schemaVersion: 1,
    graphId: hash(signatures.join('\n')).slice(0, 16),
    mode: normalizedMode,
    generatedAt: new Date().toISOString(),
    state: nodeArray.length || edgeArray.length ? 'ready' : 'empty',
    summary: {
      nodes: nodeArray.length,
      edges: edgeArray.length,
      directEdges: edgeArray.filter(edge => edge.confidence === 'direct').length,
      contextualEdges: edgeArray.filter(edge => edge.confidence === 'contextual').length,
      paths: paths.length,
      packages: counts('package'),
      files: counts('file'),
      findings: counts('finding'),
      advisories: counts('advisory')
    },
    guardrails: {
      exploitabilityInference: false,
      sourceSnippetsStored: false,
      secretValuesStored: false,
      repositoryMutation: false,
      contextualEdgesCannotEstablishExploitability: true,
      pathConfidenceUsesWeakestEdge: true
    },
    nodes: nodeArray.sort((a, b) => a.id.localeCompare(b.id)),
    edges: edgeArray.sort((a, b) => a.id.localeCompare(b.id)),
    paths
  };
}

export function repositorySecurityGraphMarkdown(graph) {
  if (!graph || graph.state === 'disabled') return '### Repository security graph\n\nSecurity graph: disabled.';
  const lines = [
    '### Repository security graph',
    '',
    `Graph \`${graph.graphId}\` · nodes **${graph.summary.nodes}** · edges **${graph.summary.edges}** · direct **${graph.summary.directEdges}** · contextual **${graph.summary.contextualEdges}** · paths **${graph.summary.paths}**`,
    '',
    'Every graph edge carries evidence metadata. Contextual edges and multi-hop paths are review hypotheses, not proof of exploitability.'
  ];
  if (graph.paths.length) {
    lines.push('', '**Top traceable paths**');
    for (const item of graph.paths.slice(0, 6)) {
      lines.push(`- **${item.title}** (${item.confidence}) — ${item.explanation}`);
    }
  }
  return lines.join('\n');
}

function dotEscape(value) {
  return String(value || '').replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/[\r\n]/g, ' ').slice(0, 180);
}

export function repositorySecurityGraphDot(graph) {
  const lines = ['digraph DevShieldSecurityGraph {', '  rankdir=LR;'];
  for (const node of graph.nodes.slice(0, 250)) {
    lines.push(`  "${dotEscape(node.id)}" [label="${dotEscape(nodeLabel(node))}\n${dotEscape(node.type)}"];`);
  }
  const allowed = new Set(graph.nodes.slice(0, 250).map(node => node.id));
  for (const edge of graph.edges) {
    if (!allowed.has(edge.from) || !allowed.has(edge.to)) continue;
    lines.push(`  "${dotEscape(edge.from)}" -> "${dotEscape(edge.to)}" [label="${dotEscape(edge.type)}\n${dotEscape(edge.confidence)}"];`);
  }
  lines.push('}');
  return `${lines.join('\n')}\n`;
}

export function writeRepositorySecurityGraph({ workspace, reportDir = '.devshield', graph }) {
  const dir = path.join(workspace, reportDir);
  fs.mkdirSync(dir, { recursive: true });
  const jsonFile = path.join(dir, 'devshield-security-graph.json');
  const markdownFile = path.join(dir, 'devshield-security-graph.md');
  const dotFile = path.join(dir, 'devshield-security-graph.dot');
  fs.writeFileSync(jsonFile, `${JSON.stringify(graph, null, 2)}\n`);
  fs.writeFileSync(markdownFile, `${repositorySecurityGraphMarkdown(graph)}\n`);
  fs.writeFileSync(dotFile, repositorySecurityGraphDot(graph));
  return {
    jsonFile: path.relative(workspace, jsonFile).replace(/\\/g, '/'),
    markdownFile: path.relative(workspace, markdownFile).replace(/\\/g, '/'),
    dotFile: path.relative(workspace, dotFile).replace(/\\/g, '/')
  };
}
