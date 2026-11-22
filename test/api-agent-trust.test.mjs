import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import {
  analyzeApiAgentTrustFile,
  apiAgentTrustSarif,
  scanApiAgentTrust,
  shouldFailApiAgentTrust
} from '../src/api-agent-trust.mjs';

test('detects credentialed wildcard CORS and hardcoded JWT secrets', () => {
  const source = [
    'app.use(cors({ origin: "*", credentials: true }));',
    'jwt.sign(payload, "hardcoded-super-secret");'
  ].join('\n');

  const findings = analyzeApiAgentTrustFile('server.js', source);
  const rules = new Set(findings.map(item => item.rule));

  assert.ok(rules.has('api-cors-wildcard-credentials'));
  assert.ok(rules.has('api-jwt-hardcoded-secret'));
});

test('detects unsigned webhooks, public secrets, and missing admin auth signals', () => {
  const source = [
    'const NEXT_PUBLIC_PAYSTACK_SECRET_KEY = process.env.NEXT_PUBLIC_PAYSTACK_SECRET_KEY;',
    'router.post("/api/admin/users", async (req, res) => res.json({ ok: true }));',
    'router.post("/api/payments/webhook", async (req, res) => processEvent(req.body));'
  ].join('\n');

  const findings = analyzeApiAgentTrustFile('src/pages/api.js', source);
  const rules = new Set(findings.map(item => item.rule));

  assert.ok(rules.has('api-client-secret-exposure'));
  assert.ok(rules.has('api-admin-route-no-auth-signal'));
  assert.ok(rules.has('api-webhook-unverified'));
});

test('detects agent authority and model-output-to-shell patterns', () => {
  const source = [
    'const agent = { allowedTools: ["*"], require_approval: false };',
    'exec(result);'
  ].join('\n');

  const findings = analyzeApiAgentTrustFile('agent-runner.mjs', source);
  const rules = new Set(findings.map(item => item.rule));

  assert.ok(rules.has('agent-human-approval-disabled'));
  assert.ok(rules.has('agent-unbounded-tool-authority'));
  assert.ok(rules.has('agent-model-output-to-shell'));
});

test('detects privileged provider key names in public namespaces without revealing values', () => {
  for (const prefix of ['NEXT_PUBLIC', 'VITE', 'REACT_APP', 'PUBLIC']) {
    for (const key of ['OPENROUTER_API_KEY', 'OPENAI_API_KEY', 'ANTHROPIC_API_KEY', 'RESEND_API_KEY', 'SUPABASE_SERVICE_ROLE_KEY']) {
      const source = `const key = process.env.${prefix}_${key};\n`;
      const findings = analyzeApiAgentTrustFile('src/client.ts', source);
      assert.ok(findings.some(item => item.rule === 'api-client-secret-exposure'), `${prefix}_${key}`);
    }
  }
  for (const target of ['window', 'globalThis']) {
    const source = `// client configuration\n${target}.RESEND_API_KEY = "fixture-value-never-log";`;
    const finding = analyzeApiAgentTrustFile('public/app.js', source)
      .find(item => item.rule === 'api-client-secret-exposure');
    assert.ok(finding, target);
    assert.equal(finding.line, 2);
    assert.equal(JSON.stringify(finding).includes('fixture-value-never-log'), false);
  }
});

test('does not treat server credentials or intentionally public identifiers as provider secrets', () => {
  for (const name of [
    'OPENROUTER_API_KEY', 'RESEND_API_KEY', 'SUPABASE_SERVICE_ROLE_KEY',
    'NEXT_PUBLIC_SUPABASE_ANON_KEY', 'VITE_SUPABASE_PUBLISHABLE_KEY',
    'NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY', 'VITE_PAYSTACK_PUBLIC_KEY',
    'NEXT_PUBLIC_API_URL', 'NEXT_PUBLIC_OPENAI_API_KEY_LABEL',
    'NOT_NEXT_PUBLIC_RESEND_API_KEY'
  ]) {
    const findings = analyzeApiAgentTrustFile('config.ts', `const config = process.env.${name};`);
    assert.equal(findings.some(item => item.rule === 'api-client-secret-exposure'), false, name);
  }
});

test('repository scan catches public provider references and emits value-free SARIF', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'devshield-public-provider-'));
  try {
    fs.writeFileSync(path.join(root, 'client.ts'), 'export const key = import.meta.env.VITE_OPENROUTER_API_KEY;');
    const report = scanApiAgentTrust({ workspace: root });
    assert.equal(report.counts.critical, 1);
    assert.equal(shouldFailApiAgentTrust(report, 'critical'), true);
    const result = apiAgentTrustSarif(report).runs[0].results[0];
    assert.equal(result.ruleId, 'api-client-secret-exposure');
    assert.equal(result.locations[0].physicalLocation.artifactLocation.uri, 'client.ts');
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('does not flag a representative hardened API file', () => {
  const source = [
    'const cors = { "Access-Control-Allow-Origin": origin };',
    'const user = await requireAuth(request, env, ["admin"]);',
    'const valid = await verifySignature(raw, request.headers.get("x-paystack-signature"));',
    'const idempotencyKey = request.headers.get("Idempotency-Key");',
    'const jwtSecret = env.JWT_SECRET;'
  ].join('\n');

  const findings = analyzeApiAgentTrustFile('worker/src/index.js', source);
  assert.equal(findings.length, 0);
});

test('repository scan writes deterministic severity evidence and SARIF', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'devshield-api-trust-'));
  try {
    fs.mkdirSync(path.join(root, 'src'), { recursive: true });
    fs.writeFileSync(
      path.join(root, 'src', 'api.js'),
      'router.post("/api/payments/webhook", async (req, res) => charge(req.body));\n'
    );
    fs.writeFileSync(path.join(root, 'src', 'safe.js'), 'export const ok = true;\n');

    const report = scanApiAgentTrust({ workspace: root });
    assert.equal(report.scannedFiles, 2);
    assert.ok(report.findings.some(item => item.rule === 'api-webhook-unverified'));
    assert.equal(shouldFailApiAgentTrust(report, 'high'), true);
    assert.equal(shouldFailApiAgentTrust(report, 'critical'), false);

    const sarif = apiAgentTrustSarif(report);
    assert.equal(sarif.version, '2.1.0');
    assert.ok(sarif.runs[0].results.length >= 1);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
