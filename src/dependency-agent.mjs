import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { createDependencyInventory } from './dependency-inventory.mjs';

const severityRank = { low: 1, medium: 2, high: 3, critical: 4 };

function hash(value) {
  return crypto.createHash('sha256').update(String(value)).digest('hex');
}

function safeRelative(rel) {
  const value = String(rel || '');
  if (!value || path.isAbsolute(value) || value.includes('\\') || /[\x00-\x1f\x7f]/.test(value)) return false;
  const parts = value.split('/');
  return !parts.some(part => !part || part === '.' || part === '..');
}

function shortSecurityFinding(finding) {
  return {
    fingerprint: finding.fingerprint || null,
    rule: finding.rule || null,
    severity: finding.severity || 'medium',
    category: finding.category || 'security',
    file: finding.file || null,
    line: finding.line || null,
    message: finding.message || null,
    dependency: finding.dependency ? {
      name: finding.dependency.name || null,
      version: finding.dependency.version || null,
      packageUrl: finding.dependency.packageUrl || null,
      advisoryGhsaId: finding.dependency.advisoryGhsaId || null,
      advisoryUrl: finding.dependency.advisoryUrl || null
    } : null
  };
}

function packageIdentity(pkg) {
  return pkg.packageUrl || [pkg.installName || pkg.name || pkg.location, pkg.version || 'unknown'].join('@');
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

function readReferenceFile(workspace, rel, maxFileBytes) {
  if (!safeRelative(rel) || !/\.(?:[cm]?[jt]sx?|vue|svelte)$/i.test(rel)) return '';
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

function findPackageReferences({ workspace, files, packageNames, maxFileBytes }) {
  const wanted = new Set(packageNames.filter(Boolean));
  const references = new Map([...wanted].map(name => [name, []]));
  const importPattern = /\b(?:from\s*|require\s*\(\s*|import\s*\(\s*|import\s*)['"]([^'"]+)['"]/g;

  for (const rel of (Array.isArray(files) ? files : []).slice(0, 300)) {
    const content = readReferenceFile(workspace, rel, maxFileBytes);
    if (!content) continue;
    importPattern.lastIndex = 0;
    let match;
    const seen = new Set();
    while ((match = importPattern.exec(content))) {
      const root = normalizePackageSpecifier(match[1]);
      if (!root || !wanted.has(root) || seen.has(root)) continue;
      seen.add(root);
      references.get(root).push(rel);
    }
  }
  return references;
}

function dependencyFindingMatches(finding, pkg) {
  if (finding?.category !== 'dependencies' || !finding.dependency) return false;
  const dep = finding.dependency;
  if (dep.packageUrl && pkg.packageUrl && dep.packageUrl === pkg.packageUrl) return true;
  const names = new Set([pkg.name, pkg.installName].filter(Boolean));
  return names.has(dep.name) && (!dep.version || !pkg.version || dep.version === pkg.version);
}

function inventoryFindingsFor(inventory, pkg) {
  return (inventory?.findings || []).filter(f => f.location === pkg.location);
}

function contextFrom(findings, repositoryFiles) {
  const normalizedFiles = (Array.isArray(repositoryFiles) ? repositoryFiles : []).filter(safeRelative);
  const workflows = normalizedFiles.filter(file => /^\.github\/workflows\/[^/]+\.ya?ml$/i.test(file)).slice(0, 20);
  const containerFiles = normalizedFiles.filter(file => /(^|\/)(Dockerfile(?:\.[^/]+)?|docker-compose\.ya?ml|compose\.ya?ml)$/i.test(file)).slice(0, 20);
  const infrastructureFiles = normalizedFiles.filter(file => /\.tf$/i.test(file) || /(^|\/)(k8s|kubernetes|helm|charts?)\//i.test(file)).slice(0, 20);
  const byCategory = {};
  for (const finding of findings) {
    const category = finding?.category || 'security';
    if (!byCategory[category]) byCategory[category] = [];
    if (byCategory[category].length < 10) byCategory[category].push(shortSecurityFinding(finding));
  }
  return {
    workflows,
    containerFiles,
    infrastructureFiles,
    securityFindings: byCategory
  };
}

function maxSeverity(findings) {
  let best = 'low';
  for (const finding of findings) {
    if ((severityRank[finding.severity] || 0) > (severityRank[best] || 0)) best = finding.severity;
  }
  return best;
}

function packagePriority(item, context) {
  const known = item.knownDependencyFindings.reduce((max, finding) => Math.max(max, severityRank[finding.severity] || 0), 0);
  const metadata = item.metadataFindings.reduce((max, finding) => Math.max(max, severityRank[finding.severity] || 0), 0);
  const direct = item.declaredByRoot.length ? 20 : 0;
  const references = item.applicationReferences.length ? 15 + Math.min(20, item.applicationReferences.length * 5) : 0;
  const install = item.installScript === 'declared' ? 30 : 0;
  const ci = context.workflows.length && (install || known || metadata) ? 5 : 0;
  const sensitiveCi = (context.securityFindings['ci-security']?.length || 0) && install ? 20 : 0;
  const secrets = (context.securityFindings.secrets?.length || 0) && install ? 10 : 0;
  return known * 100 + metadata * 45 + direct + references + install + ci + sensitiveCi + secrets;
}

function verificationFor(item) {
  const checks = [];
  if (item.knownDependencyFindings.length) {
    checks.push('Re-run GitHub dependency review and confirm the advisory or denied-license finding is no longer present for this package/version.');
  }
  if (item.metadataFindings.some(f => f.ruleId === 'dependency-insecure-source')) {
    checks.push('Regenerate the lockfile from a trusted HTTPS registry or secure Git transport and confirm the insecure-source metadata finding disappears.');
  }
  if (item.metadataFindings.some(f => f.ruleId === 'dependency-integrity-metadata' || f.ruleId === 'dependency-weak-integrity')) {
    checks.push('Regenerate dependency metadata from a trusted source and confirm stronger integrity metadata is recorded.');
  }
  if (item.installScript === 'declared') {
    checks.push('Inspect the package lifecycle script and validate CI/package-manager policy before installation; do not infer safety from metadata alone.');
  }
  if (item.applicationReferences.length) {
    checks.push(`Run tests that exercise the referenced application files: ${item.applicationReferences.slice(0, 5).join(', ')}.`);
  }
  if (!checks.length) checks.push('Review package provenance and rerun DevShield dependency intelligence after any dependency change.');
  return checks;
}

function buildAttackPaths(packages, context) {
  const paths = [];
  for (const item of packages) {
    const metadataRules = new Set(item.metadataFindings.map(f => f.ruleId));
    const advisoryFindings = item.knownDependencyFindings.filter(f => f.dependency?.advisoryGhsaId || f.rule === 'dependency-vulnerability');

    if (advisoryFindings.length && item.applicationReferences.length) {
      paths.push({
        id: `advisory-source-${hash(item.identity).slice(0, 10)}`,
        type: 'known-advisory-to-source-reference',
        confidence: 'evidence-linked',
        package: item.identity,
        title: 'Known dependency advisory is linked to direct application imports',
        explanation: 'Dependency review identified an advisory for this package/version and repository source directly references the package. This establishes usage evidence, not exploitability.',
        evidence: {
          advisories: advisoryFindings.map(shortSecurityFinding),
          applicationReferences: item.applicationReferences.slice(0, 10)
        },
        verification: 'Confirm whether the vulnerable API/path is actually reachable, then upgrade or replace the package and run affected tests.'
      });
    }

    if (metadataRules.has('dependency-insecure-source') && context.workflows.length) {
      paths.push({
        id: `insecure-source-ci-${hash(item.identity).slice(0, 10)}`,
        type: 'insecure-source-to-ci-build',
        confidence: 'heuristic',
        package: item.identity,
        title: 'Unencrypted dependency source may feed an automated CI build',
        explanation: 'The lockfile records an insecure transport and GitHub workflow files are present. DevShield has not proved that every workflow installs this package.',
        evidence: {
          metadataFindings: item.metadataFindings.filter(f => f.ruleId === 'dependency-insecure-source'),
          workflows: context.workflows.slice(0, 10)
        },
        verification: 'Confirm the workflow dependency-install step, replace the source with a secure transport, regenerate the lockfile, and rerun CI.'
      });
    }

    if ((metadataRules.has('dependency-integrity-metadata') || metadataRules.has('dependency-weak-integrity')) && context.workflows.length) {
      paths.push({
        id: `integrity-ci-${hash(item.identity).slice(0, 10)}`,
        type: 'integrity-gap-to-ci-build',
        confidence: 'heuristic',
        package: item.identity,
        title: 'Weak or missing integrity metadata may enter automated builds',
        explanation: 'The package has an integrity-metadata gap and CI workflows exist. This is a supply-chain review signal, not proof that package bytes were altered.',
        evidence: {
          metadataFindings: item.metadataFindings.filter(f => ['dependency-integrity-metadata', 'dependency-weak-integrity'].includes(f.ruleId)),
          workflows: context.workflows.slice(0, 10)
        },
        verification: 'Regenerate trusted lockfile metadata and confirm CI uses the reviewed lockfile with deterministic installation.'
      });
    }

    if (item.installScript === 'declared' && context.workflows.length) {
      const sensitive = [
        ...(context.securityFindings['ci-security'] || []),
        ...(context.securityFindings.secrets || [])
      ].slice(0, 10);
      paths.push({
        id: `install-script-ci-${hash(item.identity).slice(0, 10)}`,
        type: 'lifecycle-script-ci-execution-surface',
        confidence: sensitive.length ? 'heuristic-elevated' : 'contextual',
        package: item.identity,
        title: 'Declared package lifecycle script may execute in CI',
        explanation: sensitive.length
          ? 'The lockfile declares an install script, CI workflows are present, and DevShield also found sensitive CI/secret context. This increases review priority but does not prove malicious execution.'
          : 'The lockfile declares an install script and CI workflows are present. DevShield has not proved that the workflow runs lifecycle scripts for this package.',
        evidence: {
          workflows: context.workflows.slice(0, 10),
          sensitiveContext: sensitive
        },
        verification: 'Inspect the lifecycle script and CI installation command, then enforce package-manager controls appropriate to the repository.'
      });
    }

    if (advisoryFindings.length && item.applicationReferences.length && (context.containerFiles.length || context.infrastructureFiles.length)) {
      paths.push({
        id: `advisory-runtime-${hash(item.identity).slice(0, 10)}`,
        type: 'advisory-to-deployment-context',
        confidence: 'contextual',
        package: item.identity,
        title: 'Advisory-linked package is referenced in a deployable repository',
        explanation: 'A known-advisory package has direct source references and container or infrastructure files are present. Runtime reachability still requires application-specific validation.',
        evidence: {
          advisories: advisoryFindings.map(shortSecurityFinding),
          applicationReferences: item.applicationReferences.slice(0, 10),
          runtimeFiles: [...context.containerFiles, ...context.infrastructureFiles].slice(0, 10)
        },
        verification: 'Trace the referenced code into the deployed artifact and confirm whether the vulnerable functionality is reachable in production.'
      });
    }
  }
  return paths.slice(0, 30);
}

export function loadWorkspaceDependencyEvidence({ workspace, maxBytes = 20 * 1024 * 1024 } = {}) {
  if (!workspace) throw new Error('workspace is required');
  for (const sourceFile of ['npm-shrinkwrap.json', 'package-lock.json']) {
    const abs = path.join(workspace, sourceFile);
    try {
      const stat = fs.lstatSync(abs);
      if (!stat.isFile() || stat.isSymbolicLink()) {
        return { status: 'invalid', sourceFile, inventory: null, reason: 'lockfile-is-not-a-regular-file' };
      }
      if (stat.size > maxBytes) return { status: 'invalid', sourceFile, inventory: null, reason: 'lockfile-too-large' };
      const raw = fs.readFileSync(abs, 'utf8');
      try {
        return { status: 'success', sourceFile, inventory: createDependencyInventory(raw, { sourceFile }), reason: null };
      } catch {
        return { status: 'invalid', sourceFile, inventory: null, reason: 'lockfile-is-malformed-or-unsupported' };
      }
    } catch (error) {
      if (error?.code === 'ENOENT') continue;
      return { status: 'invalid', sourceFile, inventory: null, reason: 'lockfile-could-not-be-read' };
    }
  }
  return { status: 'missing', sourceFile: null, inventory: null, reason: 'no-supported-npm-lockfile' };
}

export function createDependencyMission({
  workspace,
  evidence,
  findings = [],
  repositoryFiles = [],
  mode = 'auto',
  maxFileBytes = 750_000
} = {}) {
  const normalizedMode = ['off', 'auto', 'on'].includes(mode) ? mode : 'auto';
  if (normalizedMode === 'off') {
    return {
      schemaVersion: 1,
      missionId: 'disabled',
      mode: normalizedMode,
      state: 'disabled',
      evidenceStatus: evidence?.status || 'missing',
      summary: { packages: 0, prioritizedPackages: 0, attackPaths: 0, directReferences: 0, knownDependencyFindings: 0, metadataFindings: 0 },
      context: { workflows: [], containerFiles: [], infrastructureFiles: [], securityFindings: {} },
      priorityQueue: [],
      attackPaths: [],
      tasks: [],
      guardrails: { vulnerabilityInference: false, exploitabilityInference: false, repositoryMutation: false }
    };
  }

  if (!evidence || evidence.status !== 'success' || !evidence.inventory) {
    const missionId = hash(`${evidence?.status || 'missing'}:${evidence?.sourceFile || ''}`).slice(0, 16);
    return {
      schemaVersion: 1,
      missionId,
      mode: normalizedMode,
      state: evidence?.status === 'invalid' ? 'invalid-lockfile' : 'no-lockfile',
      evidenceStatus: evidence?.status || 'missing',
      reason: evidence?.reason || 'no-supported-npm-lockfile',
      summary: { packages: 0, prioritizedPackages: 0, attackPaths: 0, directReferences: 0, knownDependencyFindings: 0, metadataFindings: 0 },
      context: { workflows: [], containerFiles: [], infrastructureFiles: [], securityFindings: {} },
      priorityQueue: [],
      attackPaths: [],
      tasks: [],
      guardrails: { vulnerabilityInference: false, exploitabilityInference: false, repositoryMutation: false }
    };
  }

  const inventory = evidence.inventory;
  const securityFindings = Array.isArray(findings) ? findings.filter(Boolean) : [];
  const context = contextFrom(securityFindings, repositoryFiles);
  const packageNames = [...new Set(inventory.packages.map(pkg => pkg.installName || pkg.name).filter(Boolean))];
  const references = findPackageReferences({ workspace, files: repositoryFiles, packageNames, maxFileBytes });

  const packages = inventory.packages.map(pkg => {
    const referenceName = pkg.installName || pkg.name;
    const knownDependencyFindings = securityFindings.filter(finding => dependencyFindingMatches(finding, pkg));
    const metadataFindings = inventoryFindingsFor(inventory, pkg);
    const applicationReferences = referenceName ? (references.get(referenceName) || []) : [];
    return {
      identity: packageIdentity(pkg),
      name: pkg.name,
      installName: pkg.installName || null,
      version: pkg.version,
      packageUrl: pkg.packageUrl,
      location: pkg.location,
      declaredByRoot: Array.isArray(pkg.declaredByRoot) ? pkg.declaredByRoot : [],
      installScript: pkg.installScript,
      source: pkg.source,
      integrity: pkg.integrity,
      license: pkg.license,
      applicationReferences,
      knownDependencyFindings,
      metadataFindings
    };
  });

  for (const item of packages) item.priority = packagePriority(item, context);

  const prioritized = packages
    .filter(item => item.priority > 0 && (
      item.knownDependencyFindings.length ||
      item.metadataFindings.length ||
      item.installScript === 'declared'
    ))
    .sort((a, b) => b.priority - a.priority || a.identity.localeCompare(b.identity))
    .slice(0, 50);

  const attackPaths = buildAttackPaths(prioritized, context);
  const knownDependencyFindings = prioritized.reduce((sum, item) => sum + item.knownDependencyFindings.length, 0);
  const metadataFindings = prioritized.reduce((sum, item) => sum + item.metadataFindings.length, 0);
  const directReferences = prioritized.reduce((sum, item) => sum + item.applicationReferences.length, 0);
  const stableParts = [
    inventory.source.sha256,
    ...prioritized.map(item => item.identity),
    ...securityFindings.filter(f => f.category === 'dependencies').map(f => f.fingerprint || `${f.rule}:${f.file}:${f.line}`).sort()
  ];

  const tasks = prioritized.slice(0, 30).map((item, index) => ({
    id: `dependency-task-${String(index + 1).padStart(2, '0')}`,
    priority: index + 1,
    score: item.priority,
    state: 'proposed',
    automaticMutationAllowed: false,
    package: {
      identity: item.identity,
      name: item.name,
      installName: item.installName,
      version: item.version,
      declaredByRoot: item.declaredByRoot,
      installScript: item.installScript
    },
    evidence: {
      metadataFindings: item.metadataFindings,
      knownDependencyFindings: item.knownDependencyFindings.map(shortSecurityFinding),
      applicationReferences: item.applicationReferences
    },
    verification: verificationFor(item)
  }));

  return {
    schemaVersion: 1,
    missionId: hash(stableParts.join('\n')).slice(0, 16),
    mode: normalizedMode,
    generatedAt: new Date().toISOString(),
    state: prioritized.length || attackPaths.length ? 'investigate' : 'no-signals',
    evidenceStatus: evidence.status,
    source: inventory.source,
    coverage: inventory.coverage,
    guardrails: {
      vulnerabilityInference: false,
      exploitabilityInference: false,
      repositoryMutation: false,
      attackPathsAreHypothesesUnlessEvidenceLinked: true
    },
    summary: {
      packages: inventory.summary.packages,
      prioritizedPackages: prioritized.length,
      attackPaths: attackPaths.length,
      directReferences,
      knownDependencyFindings,
      metadataFindings,
      installScriptsInInventory: inventory.summary.installScriptsDeclared
    },
    context,
    priorityQueue: prioritized.map(item => ({
      priority: item.priority,
      identity: item.identity,
      name: item.name,
      installName: item.installName,
      version: item.version,
      declaredByRoot: item.declaredByRoot,
      installScript: item.installScript,
      applicationReferences: item.applicationReferences,
      metadataSeverity: item.metadataFindings.length ? maxSeverity(item.metadataFindings) : null,
      knownDependencySeverity: item.knownDependencyFindings.length ? maxSeverity(item.knownDependencyFindings) : null,
      metadataFindings: item.metadataFindings,
      knownDependencyFindings: item.knownDependencyFindings.map(shortSecurityFinding)
    })),
    attackPaths,
    tasks
  };
}

export function dependencyMissionMarkdown(mission) {
  if (!mission || mission.state === 'disabled') return '### Agentic dependency intelligence\n\nDependency mission: disabled.';
  if (mission.state === 'no-lockfile') return '### Agentic dependency intelligence\n\nNo supported npm v2/v3 lockfile was found; no dependency mission was generated.';
  if (mission.state === 'invalid-lockfile') return '### Agentic dependency intelligence\n\nA supported lockfile path was found but could not be safely parsed; dependency correlation was skipped.';

  const lines = [
    '### Agentic dependency intelligence',
    '',
    `Mission \`${mission.missionId}\` · state **${mission.state}** · prioritized packages **${mission.summary.prioritizedPackages}** · candidate paths **${mission.summary.attackPaths}** · direct source references **${mission.summary.directReferences}**`,
    '',
    'Dependency metadata, source references, and repository context are correlated without treating metadata gaps as vulnerabilities or inferring exploitability.'
  ];

  if (mission.priorityQueue.length) {
    lines.push('', '**Priority packages**');
    for (const item of mission.priorityQueue.slice(0, 5)) {
      const label = item.installName || item.name || item.identity;
      const version = item.version ? `@${item.version}` : '';
      lines.push(`- **${label}${version}** — score ${item.priority}; refs ${item.applicationReferences.length}; metadata findings ${item.metadataFindings.length}; dependency-review findings ${item.knownDependencyFindings.length}`);
    }
  }

  if (mission.attackPaths.length) {
    lines.push('', '**Dependency attack-path hypotheses**');
    for (const path of mission.attackPaths.slice(0, 5)) {
      lines.push(`- **${path.title}** (${path.confidence}) — ${path.explanation}`);
    }
  }

  return lines.join('\n');
}

export function writeDependencyMission({ workspace, reportDir = '.devshield', mission }) {
  const dir = path.join(workspace, reportDir);
  fs.mkdirSync(dir, { recursive: true });
  const jsonFile = path.join(dir, 'devshield-dependency-mission.json');
  const markdownFile = path.join(dir, 'devshield-dependency-mission.md');
  fs.writeFileSync(jsonFile, `${JSON.stringify(mission, null, 2)}\n`);
  fs.writeFileSync(markdownFile, `${dependencyMissionMarkdown(mission)}\n`);
  return {
    jsonFile: path.relative(workspace, jsonFile).replace(/\\/g, '/'),
    markdownFile: path.relative(workspace, markdownFile).replace(/\\/g, '/')
  };
}
