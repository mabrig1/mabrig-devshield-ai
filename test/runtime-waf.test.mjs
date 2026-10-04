import assert from 'node:assert/strict';
import test from 'node:test';
import {
  combineInspection,
  decideWafAction,
  inspectBodyText,
  inspectRequestMetadata,
  normalizeWafPolicy,
  rateLimitDescriptor,
  routePolicyFor,
  safeLogEvent,
  verifyWebhookSignature
} from '../src/runtime-waf.mjs';

function request(url, options = {}) {
  return new Request(url, {
    method: options.method || 'GET',
    headers: options.headers || {},
    body: options.body
  });
}

test('normalizes to observe mode and safe defaults', () => {
  const policy = normalizeWafPolicy({});
  assert.equal(policy.mode, 'observe');
  assert.equal(policy.blockScore, 70);
  assert.equal(policy.rateLimit.enabled, true);
  assert.equal(policy.routes.length, 0);
});

test('detects SQL injection and XSS-shaped payloads', () => {
  const sql = inspectBodyText('username=admin OR 1=1');
  const xss = inspectBodyText('<script>alert(1)</script>');

  assert.ok(sql.reasons.some(item => item.rule === 'sql-injection'));
  assert.ok(xss.reasons.some(item => item.rule === 'xss'));
});

test('route policy enforces auth and method restrictions', () => {
  const policy = normalizeWafPolicy({
    mode: 'block',
    routes: [{
      id: 'admin',
      pathPrefix: '/api/admin',
      methods: ['GET'],
      requireAuth: true
    }]
  });

  const req = request('https://example.com/api/admin/users', { method: 'POST' });
  const route = routePolicyFor(req.url, req.method, policy);
  const inspection = inspectRequestMetadata(req, policy, route);

  assert.ok(inspection.reasons.some(item => item.rule === 'method-not-allowed'));
  assert.ok(inspection.reasons.some(item => item.rule === 'missing-auth'));
  assert.equal(decideWafAction(inspection, policy), 'block');
});

test('observe mode reports high risk without blocking', () => {
  const policy = normalizeWafPolicy({ mode: 'observe', blockScore: 50 });
  const req = request('https://example.com/?q=../etc/passwd');
  const inspection = inspectRequestMetadata(req, policy, null);

  assert.ok(inspection.score >= 50);
  assert.equal(decideWafAction(inspection, policy), 'observe-high-risk');
});

test('rejects bearer tokens declaring alg none', () => {
  const header = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url');
  const req = request('https://example.com/api/admin', {
    headers: { authorization: 'Bearer ' + header + '.payload.' }
  });
  const policy = normalizeWafPolicy({ mode: 'block' });
  const inspection = inspectRequestMetadata(req, policy, null);

  assert.ok(inspection.reasons.some(item => item.rule === 'jwt-none-algorithm'));
  assert.equal(decideWafAction(inspection, policy), 'block');
});

test('rate limit descriptor can scope by IP and path', () => {
  const policy = normalizeWafPolicy({
    rateLimit: { enabled: true, requests: 5, windowSeconds: 30, key: 'ip-path' }
  });
  const req = request('https://example.com/api/orders', {
    headers: { 'cf-connecting-ip': '203.0.113.7' }
  });
  const descriptor = rateLimitDescriptor(req, policy, null);

  assert.equal(descriptor.requests, 5);
  assert.equal(descriptor.windowSeconds, 30);
  assert.match(descriptor.key, /203\.0\.113\.7:\/api\/orders$/);
});

test('webhook HMAC verification supports SHA-512 hex', async () => {
  const raw = '{"event":"charge.success"}';
  const secret = 'unit-test-secret';
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-512' },
    false,
    ['sign']
  );
  const bytes = new Uint8Array(
    await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(raw))
  );
  const signature = [...bytes].map(b => b.toString(16).padStart(2, '0')).join('');

  assert.equal(
    await verifyWebhookSignature(raw, signature, secret, { algorithm: 'SHA-512', encoding: 'hex' }),
    true
  );
  assert.equal(
    await verifyWebhookSignature(raw, 'deadbeef', secret, { algorithm: 'SHA-512', encoding: 'hex' }),
    false
  );
});

test('safe log events omit IP, user-agent, body, and authorization data', () => {
  const policy = normalizeWafPolicy({ mode: 'block' });
  const req = request('https://example.com/api/orders', {
    headers: {
      'cf-connecting-ip': '203.0.113.9',
      'user-agent': 'private-agent',
      authorization: 'Bearer secret'
    }
  });
  const inspection = inspectRequestMetadata(req, policy, null);
  const event = safeLogEvent(inspection, 'allow');
  const raw = JSON.stringify(event);

  assert.equal(raw.includes('203.0.113.9'), false);
  assert.equal(raw.includes('private-agent'), false);
  assert.equal(raw.includes('Bearer secret'), false);
});

test('combined inspection deduplicates matching rules', () => {
  const metadata = {
    score: 55,
    reasons: [{ rule: 'xss', category: 'injection', weight: 55, message: 'xss' }],
    requestId: 'x',
    method: 'POST',
    path: '/api',
    ip: 'unknown',
    country: '',
    userAgent: ''
  };
  const body = {
    score: 55,
    reasons: [{ rule: 'xss', category: 'injection', weight: 55, message: 'xss' }]
  };
  const combined = combineInspection(metadata, body);

  assert.equal(combined.reasons.length, 1);
  assert.equal(combined.score, 55);
});
