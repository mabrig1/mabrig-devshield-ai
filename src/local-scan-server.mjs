// Local-only authenticated scanning API. No inbound network exposure or third-party calls.
import http from 'node:http';
import crypto from 'node:crypto';
import { scanLocal, scanSarif, MODES } from './local-scan-api.mjs';

function equalSecrets(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const ha = crypto.createHash('sha256').update(a).digest();
  const hb = crypto.createHash('sha256').update(b).digest();
  return crypto.timingSafeEqual(ha, hb);
}
function reply(res, status, json) {
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store',
    'x-content-type-options': 'nosniff', 'referrer-policy': 'no-referrer',
    'content-security-policy': "default-src 'none'"
  });
  res.end(JSON.stringify(json));
}
async function parseJson(req) {
  if (!/^application\/json(?:\s*;|$)/i.test(req.headers['content-type'] || '')) throw Error('JSON content type required');
  const chunks = [];
  let total = 0;
  for await (const chunk of req) {
    total += chunk.length;
    if (total > 8192) throw Error('Request too large');
    chunks.push(chunk);
  }
  const value = JSON.parse(Buffer.concat(chunks).toString('utf8'));
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw Error('Invalid JSON request');
  if (Object.keys(value).some(k => !['spec', 'format'].includes(k))) throw Error('Unexpected request field');
  if (value.format != null && !['json', 'sarif'].includes(value.format)) throw Error('Invalid output format');
  if (value.spec != null && (typeof value.spec !== 'string' || value.spec.length > 300)) throw Error('Invalid spec');
  return value;
}
export function createLocalScanServer({ workspace, token } = {}) {
  if (typeof token !== 'string' || token.length < 32 || token.length > 512) throw Error('Set a strong API token of at least 32 characters');
  if (typeof workspace !== 'string' || !workspace) throw Error('Workspace required');
  let scanning = false;
  const server = http.createServer(async (req, res) => {
    if (req.headers.origin) return reply(res, 403, { error: 'browser_origins_disabled' });
    if (!/^Bearer [A-Za-z0-9_-]{32,512}$/.test(req.headers.authorization || '') ||
        !equalSecrets(req.headers.authorization.slice(7), token)) {
      return reply(res, 401, { error: 'unauthorized' });
    }
    if (!/^127\.0\.0\.1(?::[0-9]{1,5})?$/.test(req.headers.host || '')) {
      return reply(res, 400, { error: 'invalid_host' });
    }
    const pathname = new URL(req.url || '/', 'http://127.0.0.1').pathname;
    if (req.method === 'GET' && pathname === '/v1/capabilities') {
      return reply(res, 200, { transport: 'localhost-only', sourceUpload: false,
        runtimeExecution: false, modes: MODES, formats: ['json', 'sarif'] });
    }
    if (req.method !== 'POST' || !pathname.startsWith('/v1/scans/')) return reply(res, 404, { error: 'not_found' });
    const mode = pathname.slice('/v1/scans/'.length);
    if (!MODES.includes(mode)) return reply(res, 404, { error: 'unsupported_mode' });
    if (scanning) return reply(res, 429, { error: 'busy' });
    scanning = true;
    try {
      const request = await parseJson(req);
      const result = scanLocal({ workspace, mode, spec: request.spec || 'openapi.json' });
      return reply(res, 200, request.format === 'sarif' ? scanSarif(result) : result);
    } catch {
      // Do not disclose source paths, file content, or parser error details to API callers.
      return reply(res, 422, { error: 'scan_could_not_complete' });
    } finally { scanning = false; }
  });
  server.requestTimeout = 15000;
  server.headersTimeout = 10000;
  server.maxRequestsPerSocket = 40;
  return server;
}
