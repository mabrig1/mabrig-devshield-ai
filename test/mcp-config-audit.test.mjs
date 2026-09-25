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
