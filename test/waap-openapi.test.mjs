import assert from 'node:assert/strict';
import test from 'node:test';
import { openApiToWaapPolicy, openApiToWaapRoutes } from '../src/waap-openapi.mjs';
import { normalizeWafPolicy, routePolicyFor } from '../src/runtime-waf.mjs';

const spec = {
  openapi: '3.1.0',
  security: [{ bearerAuth: [] }],
  paths: {
    '/api/orders/{id}': {
      get: { operationId: 'getOrder' },
      patch: {
        operationId: 'updateOrder',
        parameters: [{ in: 'header', name: 'X-API-Version', required: true }],
        requestBody: {
          content: {
            'application/json': {
              schema: {
                type: 'object',
                additionalProperties: false,
                required: ['status'],
                properties: {
                  status: { type: 'string', enum: ['Pending','Delivered'] },
                  note: { type: 'string', maxLength: 200 }
                }
              }
            }
          }
        }
      }
    },
    '/api/auth/login': {
      post: {
        operationId: 'login',
        security: [],
        'x-devshield-auth-abuse': { failures: 5, windowSeconds: 300 },
        requestBody: {
          content: {
            'application/json': {
              schema: {
                type: 'object',
                required: ['email','password'],
                properties: {
                  email: { type: 'string', maxLength: 254 },
                  password: { type: 'string', maxLength: 128 }
                }
              }
            }
          }
        }
      }
    }
  },
  components: { securitySchemes: { bearerAuth: { type: 'http', scheme: 'bearer' } } }
};

test('OpenAPI generator creates method-specific path-template routes', () => {
  const routes = openApiToWaapRoutes(spec);
  assert.equal(routes.length, 3);
  const getRoute = routes.find(r => r.id === 'getorder');
  const patchRoute = routes.find(r => r.id === 'updateorder');
  assert.equal(getRoute.pathTemplate, '/api/orders/{id}');
  assert.deepEqual(getRoute.methods, ['GET']);
  assert.deepEqual(patchRoute.methods, ['PATCH']);
  assert.equal(patchRoute.apiVersionRequired, true);
  assert.ok(patchRoute.requiredHeaders.includes('x-api-version'));
});

test('OpenAPI generator preserves public operation overrides and auth-abuse extension', () => {
  const routes = openApiToWaapRoutes(spec);
  const login = routes.find(r => r.id === 'login');
  assert.equal(login.requireAuth, false);
  assert.equal(login.authAbuse.failures, 5);
  assert.equal(login.requestSchema.fields.email.required, true);
});

test('method-aware route selection chooses the matching OpenAPI operation', () => {
  const generated = openApiToWaapPolicy(spec);
  const policy = normalizeWafPolicy(generated);
  const getRoute = routePolicyFor('https://example.com/api/orders/123', 'GET', policy);
  const patchRoute = routePolicyFor('https://example.com/api/orders/123', 'PATCH', policy);
  assert.equal(getRoute.id, 'getorder');
  assert.equal(patchRoute.id, 'updateorder');
});

test('OpenAPI policy defaults to observe mode and includes API discovery', () => {
  const policy = openApiToWaapPolicy(spec);
  assert.equal(policy.mode, 'observe');
  assert.equal(policy.waap.apiDiscovery.enabled, true);
  assert.equal(policy.routes.length, 3);
});

test('non-OpenAPI-3 documents are rejected', () => {
  assert.throws(() => openApiToWaapRoutes({ swagger: '2.0', paths: {} }), /OpenAPI 3/);
});
