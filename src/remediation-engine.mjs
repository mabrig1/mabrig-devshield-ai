import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

function hash(value) {
  return crypto.createHash('sha256').update(String(value)).digest('hex');
}

function safeRelative(value) {
  const rel = String(value || '');
  if (!rel || path.isAbsolute(rel) || rel.includes('\\') || /[\x00-\x1f\x7f]/.test(rel)) return false;
  const parts = rel.split('/');
  return !parts.some(part => !part || part === '.' || part === '..');
}

function readTextFile(workspace, rel, maxBytes = 1_500_000) {
  if (!safeRelative(rel)) return null;
  const abs = path.join(workspace, rel);
  try {
    const stat = fs.lstatSync(abs);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.size > maxBytes) return null;
    const raw = fs.readFileSync(abs);
    if (raw.includes(0)) return null;
    return raw.toString('utf8');
  } catch {
    return null;
  }
}

function replaceFirst(line, pattern, replacement) {
  if (!pattern.test(line)) return null;
  pattern.lastIndex = 0;
  return line.replace(pattern, replacement);
}

function candidateFix(finding, line) {
  const rule = String(finding?.rule || '');

  if (rule === 'debug-mode') {
    const env = replaceFirst(line, /(\bDEBUG\s*=\s*)(?:true|1)\b/i, '$1false');
    if (env && env !== line) {
      return {
        strategy: 'disable-debug-flag',
        confidence: 'high',
        replacement: env,
        rationale: 'Disables an explicitly enabled debug flag without changing surrounding logic.'
      };
    }
    const objectStyle = replaceFirst(line, /(\bdebug\s*:\s*)true\b/i, '$1false');
    if (objectStyle && objectStyle !== line) {
      return {
        strategy: 'disable-debug-property',
        confidence: 'high',
        replacement: objectStyle,
        rationale: 'Disables an explicitly enabled debug property.'
      };
    }
  }

  if (rule === 'k8s-privileged') {
    const replacement = replaceFirst(line, /(\bprivileged\s*:\s*)true\b/i, '$1false');
    if (replacement && replacement !== line) {
      return {
        strategy: 'disable-kubernetes-privileged-mode',
        confidence: 'high',
        replacement,
        rationale: 'Changes an explicit privileged=true setting to false.'
      };
    }
  }

  if (rule === 'allow-privilege-escalation') {
    const replacement = replaceFirst(line, /(\ballowPrivilegeEscalation\s*:\s*)true\b/i, '$1false');
    if (replacement && replacement !== line) {
      return {
        strategy: 'disable-privilege-escalation',
        confidence: 'high',
        replacement,
        rationale: 'Changes an explicit privilege-escalation setting to false.'
      };
    }
  }

  if (rule === 'disabled-tls') {
    const node = replaceFirst(line, /(\brejectUnauthorized\s*:\s*)false\b/i, '$1true');
    if (node && node !== line) {
      return {
        strategy: 'restore-tls-certificate-verification',
        confidence: 'high',
        replacement: node,
        rationale: 'Restores TLS certificate verification for an explicit rejectUnauthorized=false setting.'
      };
    }
    const env = replaceFirst(line, /(NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*)(["']?)0\2/, '$1$21$2');
    if (env && env !== line) {
      return {
        strategy: 'restore-node-tls-verification',
        confidence: 'high',
        replacement: env,
        rationale: 'Changes NODE_TLS_REJECT_UNAUTHORIZED from 0 to 1.'
      };
    }
  }

  return null;
}

function manualReason(finding) {
  const category = finding?.category || 'security';
  if (category === 'secrets') return 'Credential findings require rotation/revocation outside source control and are never auto-applied.';
  if (category === 'dependencies') return 'Dependency changes require package/version and compatibility decisions.';
  if (category === 'ci-security' || category === 'supply-chain') return 'CI and supply-chain fixes require repository-specific permission/reference decisions.';
  if (category === 'authentication') return 'Authentication changes require application-specific trust and negative-test validation.';
  if (category === 'injection' || category === 'xss' || category === 'deserialization') return 'Unsafe-execution fixes require semantic code changes and regression tests.';
  if (category === 'iac' || category === 'container') return 'Infrastructure changes are only auto-proposed when DevShield has an exact reversible boolean hardening edit.';
  return 'No exact allowlisted remediation is available for this finding.';
}

function lineAt(content, lineNumber) {
  const lines = content.split(/\r?\n/);
  const index = Number(lineNumber) - 1;
  if (!Number.isInteger(index) || index < 0 || index >= lines.length) return null;
  return { lines, index, line: lines[index] };
}

export function createRemediationPlan({
  workspace,
  agenticPlan,
  maxFileBytes = 1_500_000
} = {}) {
  if (!workspace) throw new Error('workspace is required');
  if (!agenticPlan || typeof agenticPlan !== 'object') throw new Error('agenticPlan is required');

  const candidates = [];
  const manual = [];

  for (const task of Array.isArray(agenticPlan.tasks) ? agenticPlan.tasks : []) {
    const finding = task?.finding || {};
    const rel = finding.file;
    const content = readTextFile(workspace, rel, maxFileBytes);
    const located = content == null ? null : lineAt(content, finding.line);
    const fix = located ? candidateFix(finding, located.line) : null;

    if (!fix) {
      manual.push({
        taskId: task.id,
        finding,
        reason: content == null
          ? 'The source file could not be safely read from the workspace.'
          : located == null
            ? 'The reported source line is no longer present.'
            : manualReason(finding)
      });
      continue;
    }

    candidates.push({
      id: `fix-${String(candidates.length + 1).padStart(2, '0')}`,
      taskId: task.id,
      missionId: agenticPlan.missionId,
      file: rel,
      line: finding.line,
      rule: finding.rule,
      severity: finding.severity,
      strategy: fix.strategy,
      confidence: fix.confidence,
      rationale: fix.rationale,
      before: located.line,
      after: fix.replacement,
      beforeHash: hash(located.line),
      approvalRequired: true,
      applyPolicy: 'operator-approved-local-only'
    });
  }

  return {
    schemaVersion: 1,
    missionId: agenticPlan.missionId,
    generatedAt: new Date().toISOString(),
    mode: 'approval-gated',
    approval: {
      required: true,
      value: agenticPlan.missionId,
      description: 'Local apply requires --approve <missionId>. The GitHub Action never applies repository mutations.'
    },
    guardrails: {
      githubActionAppliesChanges: false,
      allowlistedExactEditsOnly: true,
      staleSourceRejected: true,
      symlinkPathsRejected: true,
      secretRotationAutomated: false,
      semanticCodeRewritesAutomated: false
    },
    summary: {
      tasks: Array.isArray(agenticPlan.tasks) ? agenticPlan.tasks.length : 0,
      candidates: candidates.length,
      manualOnly: manual.length
    },
    candidates,
    manualOnly: manual
  };
}

export function remediationMarkdown(plan) {
  const lines = [
    '### Approval-gated remediation',
    '',
    `Mission \`${plan.missionId}\` · exact patch candidates **${plan.summary.candidates}** · manual-only tasks **${plan.summary.manualOnly}**`,
    '',
    'The GitHub Action only proposes patches. Local mutation requires an explicit mission approval and a source-hash match.'
  ];

  if (plan.candidates.length) {
    lines.push('', '**Exact candidates**');
    for (const item of plan.candidates.slice(0, 10)) {
      lines.push(`- **${item.rule}** at \`${item.file}:${item.line}\` — ${item.strategy}`);
    }
  }

  if (plan.manualOnly.length) {
    lines.push('', `_${plan.manualOnly.length} task(s) remain human-only because no exact allowlisted edit is safe enough to apply automatically._`);
  }
  return lines.join('\n');
}

export function writeRemediationPlan({ workspace, reportDir = '.devshield', plan }) {
  const dir = path.join(workspace, reportDir);
  fs.mkdirSync(dir, { recursive: true });
  const jsonFile = path.join(dir, 'devshield-remediation-plan.json');
  const markdownFile = path.join(dir, 'devshield-remediation-plan.md');
  fs.writeFileSync(jsonFile, `${JSON.stringify(plan, null, 2)}\n`);
  fs.writeFileSync(markdownFile, `${remediationMarkdown(plan)}\n`);
  return {
    jsonFile: path.relative(workspace, jsonFile).replace(/\\/g, '/'),
    markdownFile: path.relative(workspace, markdownFile).replace(/\\/g, '/')
  };
}

export function applyApprovedRemediation({
  workspace,
  plan,
  approval,
  dryRun = false,
  maxFileBytes = 1_500_000
} = {}) {
  if (!workspace) throw new Error('workspace is required');
  if (!plan || typeof plan !== 'object') throw new Error('remediation plan is required');
  if (!plan.missionId || approval !== plan.missionId) throw new Error('Approval does not match the remediation mission ID.');

  const byFile = new Map();
  for (const candidate of Array.isArray(plan.candidates) ? plan.candidates : []) {
    if (candidate.missionId !== plan.missionId || candidate.approvalRequired !== true) {
      throw new Error('Remediation candidate is not bound to the approved mission.');
    }
    if (!safeRelative(candidate.file)) throw new Error('Unsafe remediation path.');
    const list = byFile.get(candidate.file) || [];
    list.push(candidate);
    byFile.set(candidate.file, list);
  }

  const prepared = [];
  for (const [rel, candidates] of byFile.entries()) {
    const content = readTextFile(workspace, rel, maxFileBytes);
    if (content == null) throw new Error(`Could not safely read ${rel}.`);
    const newline = content.includes('\r\n') ? '\r\n' : '\n';
    const hadFinalNewline = content.endsWith('\n');
    const lines = content.split(/\r?\n/);
    if (hadFinalNewline) lines.pop();

    for (const candidate of candidates.slice().sort((a, b) => a.line - b.line)) {
      const index = Number(candidate.line) - 1;
      if (!Number.isInteger(index) || index < 0 || index >= lines.length) throw new Error(`Stale remediation line for ${rel}.`);
      if (hash(lines[index]) !== candidate.beforeHash || lines[index] !== candidate.before) {
        throw new Error(`Source changed after planning for ${rel}:${candidate.line}; regenerate the remediation plan.`);
      }
      lines[index] = candidate.after;
    }

    prepared.push({
      file: rel,
      content: lines.join(newline) + (hadFinalNewline ? newline : ''),
      candidates
    });
  }

  if (!dryRun) {
    for (const item of prepared) {
      const abs = path.join(workspace, item.file);
      fs.writeFileSync(abs, item.content, { flag: 'w' });
    }
  }

  return {
    missionId: plan.missionId,
    dryRun: Boolean(dryRun),
    applied: prepared.flatMap(item => item.candidates.map(candidate => ({
      id: candidate.id,
      rule: candidate.rule,
      file: candidate.file,
      line: candidate.line,
      strategy: candidate.strategy
    })))
  };
}
