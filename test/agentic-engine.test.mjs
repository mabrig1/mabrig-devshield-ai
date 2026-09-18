import test from 'node:test';
import assert from 'node:assert/strict';
import { createAgenticPlan, agenticMarkdown } from '../src/agentic-engine.mjs';

const finding = (overrides = {}) => ({
  fingerprint: overrides.fingerprint || 'fp-default',
  rule: overrides.rule || 'dangerous-eval',
  severity: overrides.severity || 'high',
  category: overrides.category || 'injection',
  file: overrides.file || 'app.js',
  line: overrides.line || 10,
  status: overrides.status || 'new',
  confidence: overrides.confidence || 'high',
  message: overrides.message || 'Risky operation',
  remediation: overrides.remediation || 'Replace risky operation.',
  ...overrides
});

test('agentic plan prioritizes critical findings and never enables automatic mutation', () => {
  const plan = createAgenticPlan({
    findings: [
      finding({ fingerprint: 'low', severity: 'low', category: 'configuration', file: 'a.js' }),
      finding({ fingerprint: 'critical', severity: 'critical', category: 'secrets', rule: 'github-token', file: '.env' })
    ],
    risk: { score: 32, level: 'critical' },
    files: ['a.js', '.env'],
    mode: 'plan'
  });

  assert.equal(plan.priorityQueue[0].finding.fingerprint, 'critical');
  assert.equal(plan.tasks[0].requiresHumanApproval, true);
  assert.equal(plan.tasks[0].automaticMutationAllowed, false);
  assert.equal(plan.guardrails.mutateRepository, false);
  assert.equal(plan.guardrails.bypassMergeGate, false);
});

test('agentic plan links evidence into heuristic attack paths', () => {
  const plan = createAgenticPlan({
    findings: [
      finding({ fingerprint: 'secret', severity: 'critical', category: 'secrets', rule: 'github-token', file: 'config.js' }),
      finding({ fingerprint: 'ci', severity: 'high', category: 'ci-security', rule: 'workflow-write-all', file: '.github/workflows/ci.yml' })
    ],
    risk: { score: 45, level: 'critical' },
    mode: 'plan'
  });

  assert.equal(plan.attackPaths.length, 1);
  assert.equal(plan.attackPaths[0].id, 'credential-to-ci');
  assert.equal(plan.attackPaths[0].confidence, 'heuristic');
  assert.equal(plan.attackPaths[0].evidence.length, 2);
});

test('agentic plan is deterministic in mission identity for the same finding set', () => {
  const a = createAgenticPlan({ findings: [finding({ fingerprint: 'a' }), finding({ fingerprint: 'b' })] });
  const b = createAgenticPlan({ findings: [finding({ fingerprint: 'b' }), finding({ fingerprint: 'a' })] });
  assert.equal(a.missionId, b.missionId);
});

test('off mode emits no tasks or paths', () => {
  const plan = createAgenticPlan({ findings: [finding()], mode: 'off' });
  assert.equal(plan.state, 'disabled');
  assert.deepEqual(plan.tasks, []);
  assert.deepEqual(plan.attackPaths, []);
});

test('markdown is concise and includes guardrail statement', () => {
  const plan = createAgenticPlan({ findings: [finding({ fingerprint: 'x' })], mode: 'plan' });
  const md = agenticMarkdown(plan);
  assert.match(md, /Agentic security loop/);
  assert.match(md, /does not modify repository files/);
});
