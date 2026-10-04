import assert from 'node:assert/strict';
import test from 'node:test';
import {
  analyzeGraphql,
  endpointObservation,
  graphqlQueryFromRequest,
  inspectApiDiscovery,
  inspectApiVersion,
  inspectContentType,
  inspectJsonRequest,
  inspectParameterPollution,
  inspectRequiredHeaders,
  inspectResponseText,
  normalizeWaapPolicy,
  normalizeWaapRoute,
  safeEndpointFingerprint,
  validateJsonContract
} from '../src/waap.mjs';

function req(url, options = {}) {
  return new Request(url, {
    method: options.method || 'GET',
    headers: options.headers || {},
    body: options.body
  });
}

test('shadow API discovery observes unknown API endpoints by default', () => {
  const waap = normalizeWaapPolicy({});
  const policy = { routes: [{ id: 'known', pathPrefix: '/api/known' }] };
  const result = inspectApiDiscovery(req('https://example.com/api/unknown'), policy, waap);
  assert.equal(result.block, false);
  assert.ok(result.reasons.some(item => item.rule === 'waap-shadow-api'));
});

test('shadow API discovery can enforce known route inventory', () => {
  const waap = normalizeWaapPolicy({ apiDiscovery: { unknownAction: 'block' } });
  const result = inspectApiDiscovery(req('https://example.com/api/unknown'), { routes: [] }, waap);
  assert.equal(result.block, true);
  assert.equal(result.reasons[0].weight, 100);
});

test('JSON contract rejects missing, unknown, and invalid fields', () => {
  const route = normalizeWaapRoute({
    requestSchema: {
      allowedFields: ['email','quantity','tier'],
      rejectUnknownFields: true,
      maxFields: 4,
      fields: {
        email: { type: 'string', required: true, maxLength: 120 },
        quantity: { type: 'integer', required: true, min: 1, max: 1000 },
        tier: { type: 'string', enum: ['retail','wholesale'] }
      }
    }
  });
  const errors = validateJsonContract({ quantity: 0, tier: 'root', admin: true }, route.requestSchema);
  assert.ok(errors.some(item => item.code === 'required-field-missing' && item.field === 'email'));
  assert.ok(errors.some(item => item.code === 'unknown-field' && item.field === 'admin'));
  assert.ok(errors.some(item => item.code === 'number-below-min' && item.field === 'quantity'));
  assert.ok(errors.some(item => item.code === 'enum-not-allowed' && item.field === 'tier'));
});

test('JSON request inspection blocks malformed JSON and contract violations', () => {
  const route = normalizeWaapRoute({
    requestSchema: { requiredFields: ['name'], allowedFields: ['name'], rejectUnknownFields: true }
  });
  const malformed = inspectJsonRequest('{"name":', route);
  const unknown = inspectJsonRequest('{"name":"A","role":"admin"}', route);
  assert.equal(malformed.block, true);
  assert.ok(malformed.reasons.some(item => item.rule === 'waap-json-invalid'));
  assert.equal(unknown.block, true);
  assert.ok(unknown.reasons.some(item => item.rule === 'waap-json-contract-violation'));
});

test('Content-Type and required headers are enforced per API route', () => {
  const route = normalizeWaapRoute({ requestContentTypes: ['application/json'], requiredHeaders: ['x-request-id'] });
  const request = req('https://example.com/api/orders', { method: 'POST', headers: { 'content-type': 'text/plain' }, body: 'hello' });
  assert.equal(inspectContentType(request, route).block, true);
  assert.equal(inspectRequiredHeaders(request, route).block, true);
});

test('parameter pollution is detected without leaking values', () => {
  const waap = normalizeWaapPolicy({ parameterPollution: { action: 'block' } });
  const result = inspectParameterPollution(req('https://example.com/api/items?id=1&id=2&safe=x'), waap);
  assert.equal(result.block, true);
  assert.ok(result.reasons[0].message.includes('id'));
  assert.equal(result.reasons[0].message.includes('1'), false);
  assert.equal(result.reasons[0].message.includes('2'), false);
});

test('API version policy detects missing and disallowed versions', () => {
  const waap = normalizeWaapPolicy({ apiVersions: { allowed: ['2026-10'], header: 'x-api-version', action: 'block' } });
  const route = normalizeWaapRoute({ apiVersionRequired: true });
  const missing = inspectApiVersion(req('https://example.com/api'), route, waap);
  const old = inspectApiVersion(req('https://example.com/api', { headers: { 'x-api-version': '2025-01' } }), route, waap);
  assert.equal(missing.block, true);
  assert.equal(old.block, true);
  assert.ok(old.reasons.some(item => item.rule === 'waap-api-version-not-allowed'));
});

test('GraphQL controls block introspection, excessive depth, and alias fan-out', () => {
  const config = normalizeWaapPolicy({ graphql: { enabled: true, allowIntrospection: false, maxDepth: 3, maxAliases: 1 } }).graphql;
  const query = 'query { __schema { queryType { name } } first: viewer { account { profile { name } } } second: viewer { id } }';
  const result = analyzeGraphql(query, config);
  const rules = new Set(result.reasons.map(item => item.rule));
  assert.equal(result.block, true);
  assert.ok(rules.has('waap-graphql-introspection'));
  assert.ok(rules.has('waap-graphql-depth'));
  assert.ok(rules.has('waap-graphql-aliases'));
});

test('GraphQL query extraction supports JSON and application/graphql bodies', () => {
  assert.equal(graphqlQueryFromRequest('query { viewer { id } }', 'application/graphql'), 'query { viewer { id } }');
  assert.equal(graphqlQueryFromRequest('{"query":"query { viewer { id } }"}', 'application/json'), 'query { viewer { id } }');
});

test('response inspection identifies secret-like material without returning the secret', () => {
  const config = normalizeWaapPolicy({ responseInspection: { enabled: true, inspectJson: true, blockOnSecrets: true } }).responseInspection;
  const findings = inspectResponseText('{"token":"github_pat_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456789"}', config);
  assert.ok(findings.some(item => item.rule === 'waap-response-secret-github-token'));
  assert.equal(JSON.stringify(findings).includes('ABCDEFGHIJKLMNOPQRSTUVWXYZ'), false);
});

test('endpoint inventory fingerprint is stable and omits query values', () => {
  const first = req('https://example.com/api/orders?token=secret');
  const second = req('https://example.com/api/orders?token=other');
  assert.equal(safeEndpointFingerprint(first), safeEndpointFingerprint(second));
  const observation = endpointObservation(first, { id: 'orders' }, { score: 0 });
  assert.equal(observation.path, '/api/orders');
  assert.equal(JSON.stringify(observation).includes('secret'), false);
});

test('auth abuse settings are normalized safely', () => {
  const route = normalizeWaapRoute({ authAbuse: { failures: 8, windowSeconds: 600, statuses: [401,403,500] } });
  assert.equal(route.authAbuse.failures, 8);
  assert.equal(route.authAbuse.windowSeconds, 600);
  assert.deepEqual(route.authAbuse.statuses, [401,403]);
});
