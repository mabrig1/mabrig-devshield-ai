import path from 'node:path';

const SECRET_KEY = /(?:token|secret|password|passwd|api[_-]?key|access[_-]?key|private[_-]?key)/i;
const PLACEHOLDER = /^(?:\$\{?[A-Z0-9_]+\}?|env:|example|dummy|test|changeme|change-me|replace-me|your[-_])/i;

function lineOf(content, needle) {
  if (!needle) return 1;
  const lines = String(content || '').split(/\r?\n/);
  const text = String(needle);
  const idx = lines.findIndex(line => line.includes(text));
  return idx >= 0 ? idx + 1 : 1;
}

function isMcpConfigPath(rel, content) {
  const normalized = String(rel || '').replace(/\\/g, '/').toLowerCase();
  const base = path.posix.basename(normalized);
  return base === 'mcp.json' ||
    base === '.mcp.json' ||
    base === 'claude_desktop_config.json' ||
    normalized.endsWith('/.cursor/mcp.json') ||
    normalized.endsWith('/.vscode/mcp.json') ||
    /["']mcpServers["']\s*:/.test(String(content || ''));
}

function collectServers(doc, rel) {
  const roots = [];
  if (doc?.mcpServers && typeof doc.mcpServers === 'object') roots.push(doc.mcpServers);
  if (doc?.mcp?.servers && typeof doc.mcp.servers === 'object') roots.push(doc.mcp.servers);
  if (isMcpConfigPath(rel, JSON.stringify(doc)) && doc?.servers && typeof doc.servers === 'object') roots.push(doc.servers);
  const merged = {};
  for (const root of roots) {
    for (const [name, value] of Object.entries(root)) {
      if (value && typeof value === 'object' && !Array.isArray(value)) merged[name] = value;
    }
  }
  return merged;
}

function npxPackage(args) {
  if (!Array.isArray(args)) return '';
  for (let i = 0; i < args.length; i++) {
    const value = String(args[i] ?? '').trim();
    if (!value) continue;
    if (value === '-p' || value === '--package') {
      const next = String(args[i + 1] ?? '').trim();
      if (next) return next;
      continue;
    }
    if (value.startsWith('-')) continue;
    if (/^(?:\.|\/|[A-Za-z]:\\)/.test(value)) continue;
    return value;
  }
  return '';
}

function hasImmutablePackageVersion(spec) {
  const value = String(spec || '').trim();
  if (!value || /^(?:latest|next|beta|canary)$/i.test(value)) return false;
  if (/^(?:git\+|https?:|github:|file:)/i.test(value)) return /#[a-f0-9]{7,64}$/i.test(value);
  if (value.startsWith('@')) {
    const slash = value.indexOf('/');
    const versionAt = slash >= 0 ? value.indexOf('@', slash + 1) : -1;
    return versionAt > slash + 1 && !/@(?:latest|next|beta|canary|\*)$/i.test(value);
  }
  const at = value.lastIndexOf('@');
  return at > 0 && !/@(?:latest|next|beta|canary|\*)$/i.test(value);
}

function isRemotePlainHttp(raw) {
  try {
    const u = new URL(String(raw));
    if (u.protocol !== 'http:') return false;
    const h = u.hostname.toLowerCase();
    return !['localhost', '127.0.0.1', '::1'].includes(h) && !h.endsWith('.localhost');
  } catch {
    return false;
  }
}

export function auditMcpConfig(rel, content) {
  if (!isMcpConfigPath(rel, content)) return [];
  let doc;
  try { doc = JSON.parse(String(content || '')); } catch { return []; }
  const servers = collectServers(doc, rel);
  const findings = [];

  for (const [name, server] of Object.entries(servers)) {
    const rawUrl = server.url ?? server.serverUrl ?? server.server_url ?? server.mcpUrl ?? server.mcp_url;
    if (typeof rawUrl === 'string' && isRemotePlainHttp(rawUrl)) {
      findings.push({
        id: 'mcp-plain-http',
        severity: 'high',
        category: 'ai-security',
        line: lineOf(content, rawUrl),
        lineText: rawUrl,
        message: `MCP server "${name}" uses plain HTTP for a remote endpoint.`,
        cwe: 'CWE-319',
        remediation: 'Use HTTPS for remote MCP servers and validate the server before granting tool access.'
      });
    }

    const command = String(server.command ?? '').trim();
    if (/^(?:npx|npx\.cmd)$/i.test(path.basename(command))) {
      const spec = npxPackage(server.args);
      if (spec && !hasImmutablePackageVersion(spec)) {
        findings.push({
          id: 'mcp-unpinned-npx-server',
          severity: 'medium',
          category: 'supply-chain',
          line: lineOf(content, spec),
          lineText: spec,
          message: `MCP server "${name}" is launched through npx with an unpinned package reference.`,
          cwe: 'CWE-829',
          remediation: 'Pin the MCP server package to a reviewed exact version or immutable source revision before executing it.'
        });
      }
    }

    if (server.env && typeof server.env === 'object' && !Array.isArray(server.env)) {
      for (const [key, rawValue] of Object.entries(server.env)) {
        if (!SECRET_KEY.test(key) || typeof rawValue !== 'string') continue;
        const value = rawValue.trim();
        if (value.length < 16 || PLACEHOLDER.test(value)) continue;
        findings.push({
          id: 'mcp-hardcoded-env-secret',
          severity: 'critical',
          category: 'secrets',
          line: lineOf(content, key),
          lineText: key,
          message: `MCP server "${name}" embeds a secret-looking literal in env.${key}.`,
          cwe: 'CWE-798',
          remediation: 'Remove the literal, rotate it if real, and inject the credential from a protected environment or secret manager.'
        });
      }
    }
  }

  return findings;
}
