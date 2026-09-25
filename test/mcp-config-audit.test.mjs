import assert from 'node:assert/strict';
import test from 'node:test';
import { auditMcpConfig } from '../src/mcp-config-audit.mjs';

test('audits structured MCP config trust boundaries', () => {
  const content = JSON.stringify({
    mcpServers: {
      remote: { url: 'http://agent.example.invalid/mcp' },
      local: {
        command: 'npx',
        args: ['-y', '@example/mcp-server'],
        env: { SERVICE_TOKEN: 'ABCDEFGHIJKLMNOPQRSTUVWX' }
      }
    }
  }, null, 2);

  const findings = auditMcpConfig('.cursor/mcp.json', content);
  const ids = new Set(findings.map(x => x.id));
  assert.equal(ids.has('mcp-plain-http'), true);
  assert.equal(ids.has('mcp-unpinned-npx-server'), true);
  assert.equal(ids.has('mcp-hardcoded-env-secret'), true);
});

test('accepts localhost HTTP, pinned npx package, and env placeholders', () => {
  const content = JSON.stringify({
    mcpServers: {
      local: {
        url: 'http://localhost:3000/mcp',
        command: 'npx',
        args: ['-y', '@example/mcp-server@2.4.1'],
        env: { SERVICE_TOKEN: '${SERVICE_TOKEN}' }
      }
    }
  }, null, 2);

  assert.deepEqual(auditMcpConfig('mcp.json', content), []);
});

test('does not treat arbitrary JSON as MCP configuration', () => {
  const content = JSON.stringify({
    servers: {
      cache: { url: 'http://cache.example.invalid', env: { TOKEN: 'ABCDEFGHIJKLMNOPQRSTUVWX' } }
    }
  });
  assert.deepEqual(auditMcpConfig('config.json', content), []);
});


test('MCP 2026 authorization and deprecation checks', () => {
  const content = JSON.stringify({
    mcpServers: {
      remote: {
        url: 'https://agent.example.invalid/sse',
        transport: 'sse',
        headers: {
          Authorization: 'Bearer ABCDEFGHIJKLMNOPQRSTUVWXYZ'
        },
        oauth: {
          issuer: 'http://auth.example.invalid',
          authorization_endpoint: 'http://auth.example.invalid/authorize',
          token_endpoint: 'http://auth.example.invalid/token',
          client_secret: 'super-secret-client-value',
          dynamic_client_registration: true,
          scopes: ['*']
        }
      }
    }
  }, null, 2);

  const findings = auditMcpConfig('mcp.json', content);
  const byId = new Map(findings.map(x => [x.id, x]));
  for (const expected of [
    'mcp-legacy-sse-transport',
    'mcp-oauth-plain-http',
    'mcp-oauth-client-secret',
    'mcp-dcr-deprecated',
    'mcp-oauth-broad-scope',
    'mcp-hardcoded-auth-header'
  ]) {
    assert.equal(byId.has(expected), true, `missing ${expected}`);
  }
  assert.equal(byId.get('mcp-oauth-broad-scope').strictOnly, true);
});

test('accepts modern MCP auth config with HTTPS, placeholders, and narrow scopes', () => {
  const content = JSON.stringify({
    mcpServers: {
      remote: {
        url: 'https://agent.example.invalid/mcp',
        transport: 'streamable-http',
        headers: {
          Authorization: 'Bearer ${MCP_ACCESS_TOKEN}'
        },
        oauth: {
          issuer: 'https://auth.example.invalid',
          authorization_endpoint: 'https://auth.example.invalid/authorize',
          token_endpoint: 'https://auth.example.invalid/token',
          client_secret: '${MCP_CLIENT_SECRET}',
          scopes: ['files.read']
        }
      }
    }
  }, null, 2);

  assert.deepEqual(auditMcpConfig('.vscode/mcp.json', content), []);
});
