import crypto from 'node:crypto';

const severityRank = { low: 1, medium: 2, high: 3, critical: 4 };
const confidenceRank = { low: 0, medium: 1, high: 2 };

function hash(value) {
  return crypto.createHash('sha256').update(String(value)).digest('hex');
}

function stableMissionId(findings) {
  const fingerprints = findings.map(f => f.fingerprint || `${f.rule}:${f.file}:${f.line}`).sort();
  return hash(fingerprints.join('\n')).slice(0, 16);
}

function priorityScore(finding) {
  const severity = severityRank[finding.severity] || 0;
  const confidence = confidenceRank[finding.confidence] ?? 1;
  const newFinding = finding.status === 'existing' ? 0 : 10;
  const categoryBoost = ['secrets', 'authentication', 'ci-security', 'injection'].includes(finding.category) ? 5 : 0;
  return severity * 100 + confidence * 10 + newFinding + categoryBoost;
}

function shortFinding(finding) {
  return {
    fingerprint: finding.fingerprint,
    rule: finding.rule,
    severity: finding.severity,
    category: finding.category,
    file: finding.file,
    line: finding.line,
    status: finding.status || 'new',
    confidence: finding.confidence || 'high',
    message: finding.message,
    remediation: finding.remediation
  };
}

function groupBy(findings, keyFn) {
  const groups = new Map();
  for (const finding of findings) {
    const key = keyFn(finding);
    const list = groups.get(key) || [];
    list.push(finding);
    groups.set(key, list);
  }
  return groups;
}

function buildClusters(findings) {
  const byFile = groupBy(findings, f => f.file || 'unknown');
  return [...byFile.entries()]
    .map(([file, items]) => ({
      file,
      highestSeverity: items.reduce((best, item) =>
        (severityRank[item.severity] || 0) > (severityRank[best] || 0) ? item.severity : best, 'low'),
      categories: [...new Set(items.map(i => i.category))].sort(),
      findings: items.map(shortFinding)
    }))
    .sort((a, b) => {
      const severityDelta = (severityRank[b.highestSeverity] || 0) - (severityRank[a.highestSeverity] || 0);
      return severityDelta || a.file.localeCompare(b.file);
    });
}

const pathPatterns = [
  {
    id: 'credential-to-ci',
    title: 'Credential exposure amplified by CI privileges',
    categories: ['secrets', 'ci-security'],
    explanation: 'A leaked or hardcoded credential combined with an over-privileged or injectable CI workflow can expand impact beyond the changed file.',
    verification: 'Confirm the credential is revoked/rotated and the workflow uses least privilege before treating this path as closed.'
  },
  {
    id: 'input-to-code-execution',
    title: 'Untrusted input reaching code or command execution',
    categories: ['injection', 'authentication'],
    explanation: 'Authentication weaknesses combined with code or shell injection can reduce the barriers between untrusted input and privileged execution.',
    verification: 'Verify authentication checks and replace dynamic execution with allowlisted or parameterized operations.'
  },
  {
    id: 'supply-chain-to-runner',
    title: 'Supply-chain change reaching a privileged runner',
    categories: ['supply-chain', 'ci-security'],
    explanation: 'Mutable or weakly verified dependencies/actions can become more serious when CI has write permissions or executes untrusted content.',
    verification: 'Pin immutable references, minimize token permissions, and rerun dependency/action integrity checks.'
  },
  {
    id: 'dependency-to-runner',
    title: 'Dependency risk reaching build or deployment execution',
    categories: ['dependencies', 'ci-security'],
    explanation: 'A vulnerable or policy-violating dependency can gain more impact when build or deployment automation executes with elevated repository privileges.',
    verification: 'Update or replace the dependency, then rerun dependency review and CI with least-privilege permissions.'
  },
  {
    id: 'secret-to-runtime',
    title: 'Credential exposure combined with runtime hardening gaps',
    categories: ['secrets', 'container'],
    explanation: 'Exposed credentials combined with privileged containers or host access can increase the blast radius of a compromise.',
    verification: 'Rotate credentials and remove privileged/root/container-host access before closing the path.'
  },
  {
    id: 'cloud-control-plane',
    title: 'Infrastructure exposure combined with credential risk',
    categories: ['secrets', 'iac'],
    explanation: 'Credential exposure plus permissive infrastructure policy can create a plausible route to cloud control-plane or data access.',
    verification: 'Rotate credentials and restrict IAM/network/storage policy to the minimum required scope.'
  },
  {
    id: 'auth-configuration-chain',
    title: 'Authentication weakened by insecure runtime configuration',
    categories: ['authentication', 'configuration'],
    explanation: 'Authentication defects become more consequential when TLS, CORS, or other runtime controls are also weakened.',
    verification: 'Restore signature/authentication verification and harden transport/runtime configuration together.'
  }
];

function buildAttackPaths(findings) {
  const categories = new Set(findings.map(f => f.category));
  const paths = [];
  for (const pattern of pathPatterns) {
    if (!pattern.categories.every(category => categories.has(category))) continue;
    const evidence = findings
      .filter(f => pattern.categories.includes(f.category))
      .sort((a, b) => priorityScore(b) - priorityScore(a))
      .slice(0, 4)
      .map(shortFinding);
    paths.push({
      id: pattern.id,
      title: pattern.title,
      confidence: 'heuristic',
      categories: pattern.categories,
      explanation: pattern.explanation,
      verification: pattern.verification,
      evidence
    });
  }
  return paths;
}

function verificationFor(finding) {
  const checks = [
    `Re-run DevShield and confirm fingerprint ${finding.fingerprint || finding.rule} no longer appears as a new finding.`
  ];
  if (finding.category === 'secrets') {
    checks.unshift('Rotate or revoke the exposed credential outside the repository and confirm the old credential can no longer authenticate.');
  } else if (finding.category === 'dependencies') {
    checks.unshift('Re-run dependency review after updating the dependency or license decision.');
  } else if (finding.category === 'ci-security' || finding.category === 'supply-chain') {
    checks.unshift('Review the workflow/action diff and confirm token permissions and external references are least-privilege and immutable where practical.');
  } else if (finding.category === 'authentication') {
    checks.unshift('Add or run a negative test proving invalid/unsigned credentials are rejected.');
  } else if (finding.category === 'injection' || finding.category === 'xss' || finding.category === 'deserialization') {
    checks.unshift('Add or run a hostile-input regression test that proves the unsafe execution or rendering path is no longer reachable.');
  } else if (finding.category === 'iac' || finding.category === 'container') {
    checks.unshift('Validate the resulting infrastructure/container configuration with the platform-native policy or deployment dry-run.');
  }
  return checks;
}

function buildTasks(findings) {
  return findings
    .slice()
    .sort((a, b) => priorityScore(b) - priorityScore(a))
    .slice(0, 30)
    .map((finding, index) => ({
      id: `task-${String(index + 1).padStart(2, '0')}`,
      priority: index + 1,
      score: priorityScore(finding),
      state: 'proposed',
      automaticMutationAllowed: false,
      requiresHumanApproval: finding.category === 'secrets' || finding.severity === 'critical',
      finding: shortFinding(finding),
      action: finding.remediation || 'Review and remediate the finding, then rerun DevShield.',
      verification: verificationFor(finding)
    }));
}

export function createAgenticPlan({
  findings = [],
  risk = { score: 0, level: 'low' },
  files = [],
  mode = 'plan'
} = {}) {
  const normalized = Array.isArray(findings) ? findings.filter(Boolean) : [];
  const enabled = mode !== 'off';
  const ordered = enabled
    ? normalized.slice().sort((a, b) => priorityScore(b) - priorityScore(a))
    : [];
  const paths = enabled ? buildAttackPaths(ordered) : [];
  const tasks = enabled ? buildTasks(ordered) : [];
  const missionId = stableMissionId(normalized);
  const critical = normalized.filter(f => f.severity === 'critical').length;
  const high = normalized.filter(f => f.severity === 'high').length;

  return {
    schemaVersion: 1,
    missionId,
    mode,
    generatedAt: new Date().toISOString(),
    objective: 'Reduce merge risk using an evidence-backed observe → prioritize → attack-path → remediate → verify loop.',
    guardrails: {
      mutateRepository: false,
      bypassMergeGate: false,
      rotateCredentials: false,
      executeUntrustedInstructions: false,
      requireHumanApprovalForCritical: true
    },
    state: enabled ? (tasks.length ? 'remediation-ready' : 'verified-clean') : 'disabled',
    stages: [
      { id: 'observe', status: enabled ? 'completed' : 'disabled', evidence: normalized.length },
      { id: 'prioritize', status: enabled ? 'completed' : 'disabled', evidence: ordered.length },
      { id: 'attack-path', status: enabled ? (paths.length ? 'completed' : 'no-chain-found') : 'disabled', evidence: paths.length },
      { id: 'remediate', status: enabled ? (tasks.length ? 'ready' : 'not-required') : 'disabled', evidence: tasks.length },
      { id: 'verify', status: enabled ? (tasks.length ? 'pending' : 'completed') : 'disabled', evidence: 0 }
    ],
    summary: {
      filesConsidered: Array.isArray(files) ? files.length : 0,
      findingsConsidered: normalized.length,
      critical,
      high,
      attackPaths: paths.length,
      remediationTasks: tasks.length,
      riskScore: Number(risk?.score) || 0,
      riskLevel: String(risk?.level || 'low')
    },
    priorityQueue: ordered.slice(0, 20).map((finding, index) => ({
      priority: index + 1,
      score: priorityScore(finding),
      finding: shortFinding(finding)
    })),
    clusters: enabled ? buildClusters(ordered) : [],
    attackPaths: paths,
    tasks
  };
}

export function agenticMarkdown(plan) {
  if (!plan || plan.mode === 'off') return 'Agentic security loop: disabled.';
  const lines = [
    `### Agentic security loop`,
    '',
    `Mission \`${plan.missionId}\` · state **${plan.state}** · attack paths **${plan.summary.attackPaths}** · remediation tasks **${plan.summary.remediationTasks}**`,
    '',
    'The agentic layer does not modify repository files, rotate credentials, or bypass merge gates. It produces an ordered, evidence-backed plan for human-reviewed remediation.'
  ];

  if (plan.attackPaths.length) {
    lines.push('', '**Candidate attack paths**');
    for (const path of plan.attackPaths.slice(0, 5)) {
      lines.push(`- **${path.title}** — ${path.explanation}`);
    }
  }

  if (plan.tasks.length) {
    lines.push('', '**Top remediation tasks**');
    for (const task of plan.tasks.slice(0, 5)) {
      const finding = task.finding;
      lines.push(`${task.priority}. **${finding.severity.toUpperCase()} ${finding.rule}** at \`${finding.file}:${finding.line}\` — ${task.action}`);
    }
  }

  return lines.join('\n');
}
