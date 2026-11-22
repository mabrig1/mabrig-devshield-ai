import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { answerSecurityQuestion, parseLookbackHours } from '../public/security-briefing.js';

const example = {
  schema: 'devshield.browser-preview.v1',
  generatedAt: '2026-11-22T21:00:00.000Z',
  filesReviewed: 2,
  incomplete: false,
  findings: [
    { rule: 'powershell-encoded-command', severity: 'high', remediation: 'Inspect the command without executing it.' },
    { rule: 'private-key-material', severity: 'critical', remediation: 'Rotate a genuine exposed key.' }
  ]
};

test('a live attack question never becomes a made-up metric', () => {
  for (const q of ['Were we attacked today?', 'What countries sent the requests?', 'How many attacks did Cloudflare block?', 'Is my website safe?']) {
    const r = answerSecurityQuestion(q, example);
    assert.match(r.answer, /Unknown/);
    assert.match(r.source, /Not connected/);
  }
});

test('a scan briefing uses only actual local indicator counts', () => {
  const r = answerSecurityQuestion('What did the scan find?', example);
  assert.match(r.answer, /2 indicator\(s\)/);
  assert.match(r.answer, /1 critical, 1 high, 0 medium, and 0 low/);
  assert.match(r.source, /2026-11-22/);
  assert.doesNotMatch(r.answer, /attacks? observed|attacks? blocked/i);
});

test('recommendations are scoped to review, never automatic action', () => {
  const r = answerSecurityQuestion('What should I do next?', example);
  assert.match(r.answer, /private-key-material/);
  assert.match(r.answer, /Rotate a genuine exposed key/);
  assert.match(r.answer, /Never execute untrusted material/);
});

test('missing and incomplete scans do not imply safety', () => {
  assert.match(answerSecurityQuestion('Summarize the scan').answer, /no completed local scan/i);
  const empty = { ...example, findings: [], incomplete: true };
  const r = answerSecurityQuestion('Summarize the scan', empty);
  assert.match(r.answer, /0 indicator\(s\)/);
  assert.match(r.answer, /incomplete/i);
  assert.match(answerSecurityQuestion('Is the code safe?', empty).answer, /Unknown/);
});

test('briefing client uses only a fixed read-only public NVD endpoint and no local storage', () => {
  const js = readFileSync(new URL('../public/security-briefing.js', import.meta.url), 'utf8');
  assert.match(js, /fetch\('\/api\/v1\/public-vulnerabilities\?hours='/);
  assert.doesNotMatch(js, /\bXMLHttpRequest\b|\bsendBeacon\b|localStorage|sessionStorage/);
  assert.doesNotMatch(js, /\.innerHTML\s*=/);
  assert.match(js, /SpeechRecognition/);
  assert.match(js, /speechSynthesis/);
  assert.match(js, /devshield:local-report/);
});

test('natural language time windows accept numeric and spoken hours', () => {
  for (const [question, expected] of [
    ['Check cyber security worldwide in the last 6 hours', 6],
    ['the past seven hours', 7],
    ['Check the last 12 hrs', 12],
    ['What happened in the last twenty-four hours?', 24],
    ['Check the last 24h', 24],
    ['last 8 hours', null],
    ['last 6 days', null]
  ]) {
    assert.equal(parseLookbackHours(question), expected);
  }
});
