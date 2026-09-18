import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { applyApprovedRemediation, createRemediationPlan } from '../src/remediation-engine.mjs';

function tempWorkspace() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'devshield-remediation-'));
}

function agenticPlan(tasks) {
  return {
    missionId: 'mission-123',
    tasks: tasks.map((finding, index) => ({
      id: `task-${index + 1}`,
      finding
    }))
  };
}

test('creates exact candidates only for allowlisted reversible hardening edits', () => {
  const workspace = tempWorkspace();
  fs.writeFileSync(path.join(workspace, 'config.js'), 'export const config = { debug: true };\n');
  fs.writeFileSync(path.join(workspace, 'app.js'), 'eval(userInput);\n');

  const plan = createRemediationPlan({
    workspace,
    agenticPlan: agenticPlan([
      { rule: 'debug-mode', severity: 'low', category: 'configuration', file: 'config.js', line: 1 },
      { rule: 'dangerous-eval', severity: 'high', category: 'injection', file: 'app.js', line: 1 }
    ])
  });

  assert.equal(plan.summary.candidates, 1);
  assert.equal(plan.summary.manualOnly, 1);
  assert.equal(plan.candidates[0].after, 'export const config = { debug: false };');
  assert.equal(plan.candidates[0].approvalRequired, true);
});

test('requires mission approval before applying', () => {
  const workspace = tempWorkspace();
  fs.writeFileSync(path.join(workspace, 'pod.yml'), 'privileged: true\n');
  const plan = createRemediationPlan({
    workspace,
    agenticPlan: agenticPlan([
      { rule: 'k8s-privileged', severity: 'critical', category: 'container', file: 'pod.yml', line: 1 }
    ])
  });

  assert.throws(
    () => applyApprovedRemediation({ workspace, plan, approval: 'wrong' }),
    /Approval does not match/
  );
  assert.equal(fs.readFileSync(path.join(workspace, 'pod.yml'), 'utf8'), 'privileged: true\n');
});

test('applies an approved exact edit and preserves final newline', () => {
  const workspace = tempWorkspace();
  fs.writeFileSync(path.join(workspace, 'pod.yml'), 'allowPrivilegeEscalation: true\n');
  const plan = createRemediationPlan({
    workspace,
    agenticPlan: agenticPlan([
      { rule: 'allow-privilege-escalation', severity: 'high', category: 'container', file: 'pod.yml', line: 1 }
    ])
  });

  const result = applyApprovedRemediation({ workspace, plan, approval: 'mission-123' });
  assert.equal(result.applied.length, 1);
  assert.equal(fs.readFileSync(path.join(workspace, 'pod.yml'), 'utf8'), 'allowPrivilegeEscalation: false\n');
});

test('rejects stale source after planning', () => {
  const workspace = tempWorkspace();
  fs.writeFileSync(path.join(workspace, 'config.js'), 'DEBUG=true\n');
  const plan = createRemediationPlan({
    workspace,
    agenticPlan: agenticPlan([
      { rule: 'debug-mode', severity: 'low', category: 'configuration', file: 'config.js', line: 1 }
    ])
  });

  fs.writeFileSync(path.join(workspace, 'config.js'), 'DEBUG=custom\n');
  assert.throws(
    () => applyApprovedRemediation({ workspace, plan, approval: 'mission-123' }),
    /Source changed after planning/
  );
});

test('dry-run validates without writing', () => {
  const workspace = tempWorkspace();
  fs.writeFileSync(path.join(workspace, 'tls.js'), 'const opts = { rejectUnauthorized: false };\n');
  const plan = createRemediationPlan({
    workspace,
    agenticPlan: agenticPlan([
      { rule: 'disabled-tls', severity: 'high', category: 'configuration', file: 'tls.js', line: 1 }
    ])
  });

  const result = applyApprovedRemediation({ workspace, plan, approval: 'mission-123', dryRun: true });
  assert.equal(result.applied.length, 1);
  assert.equal(fs.readFileSync(path.join(workspace, 'tls.js'), 'utf8'), 'const opts = { rejectUnauthorized: false };\n');
});
