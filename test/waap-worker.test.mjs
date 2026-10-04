import assert from 'node:assert/strict';
import test from 'node:test';
import worker from '../runtime-waf/worker/src/index.js';

test('WAAP Worker blocks unknown API endpoints when known-route enforcement is enabled', async () => {
  const policy = {
    mode: 'block',
    waap: { apiDiscovery: { enabled: true, apiPrefixes: ['/api/'], unknownAction: 'block' } },
    routes: [{ id: 'known', pathPrefix: '/api/known', methods: ['GET'] }]
  };
  const response = await worker.fetch(
    new Request('https://edge.example.com/api/shadow'),
    { WAF_POLICY_JSON: JSON.stringify(policy), UPSTREAM_ORIGIN: 'https://origin.example.com' }
  );
  assert.equal(response.status, 403);
  assert.equal(response.headers.get('x-devshield-waap'), 'block');
});

test('WAAP Worker blocks invalid JSON contracts before origin execution', async () => {
  const policy = {
    mode: 'block',
    waap: { apiDiscovery: { enabled: true, apiPrefixes: ['/api/'], unknownAction: 'observe' } },
    routes: [{
      id: 'orders',
      pathPrefix: '/api/orders',
      methods: ['POST'],
      requestContentTypes: ['application/json'],
      requestSchema: {
        allowedFields: ['items'],
        rejectUnknownFields: true,
        fields: { items: { type: 'array', required: true } }
      }
    }]
  };
  const response = await worker.fetch(
    new Request('https://edge.example.com/api/orders', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ role: 'admin' })
    }),
    { WAF_POLICY_JSON: JSON.stringify(policy), UPSTREAM_ORIGIN: 'https://origin.example.com' }
  );
  assert.equal(response.status, 403);
});

test('WAAP Worker forwards valid requests and strips origin fingerprint headers', async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (_url, init) => {
    assert.equal(init.headers.get('x-devshield-waap'), 'pass');
    return new Response(JSON.stringify({ ok: true }), {
      status: 200,
      headers: { 'content-type': 'application/json', 'server': 'origin-server', 'x-powered-by': 'framework' }
    });
  };

  try {
    const policy = {
      mode: 'block',
      waap: { apiDiscovery: { enabled: true, apiPrefixes: ['/api/'], unknownAction: 'block' } },
      routes: [{ id: 'known', pathPrefix: '/api/known', methods: ['GET'] }]
    };
    const response = await worker.fetch(
      new Request('https://edge.example.com/api/known'),
      { WAF_POLICY_JSON: JSON.stringify(policy), UPSTREAM_ORIGIN: 'https://origin.example.com' }
    );
    assert.equal(response.status, 200);
    assert.equal(response.headers.get('server'), null);
    assert.equal(response.headers.get('x-powered-by'), null);
    assert.equal(response.headers.get('x-devshield-waap'), 'pass');
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('WAAP health endpoint advertises both WAF and API protection layers', async () => {
  const response = await worker.fetch(
    new Request('https://edge.example.com/_devshield/waap/health'),
    { UPSTREAM_ORIGIN: 'https://origin.example.com' }
  );
  const body = await response.json();
  assert.equal(response.status, 200);
  assert.equal(body.version, '3.2.0');
  assert.deepEqual(body.layers, ['waf','api-protection']);
});
