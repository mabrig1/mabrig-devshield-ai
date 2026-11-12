import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, statSync } from 'node:fs';
import worker from '../src/index.mjs';

const config = JSON.parse(readFileSync(new URL('../wrangler.json', import.meta.url), 'utf8'));
const rootConfig = JSON.parse(readFileSync(new URL('../../wrangler.jsonc', import.meta.url), 'utf8'));
const assets = {
  async fetch(request) {
    const pathname = new URL(request.url).pathname;
    const file = pathname === '/app.css' ? '../public/app.css' :
      pathname === '/app.js' ? '../public/app.js' :
      pathname === '/favicon.svg' ? '../public/favicon.svg' : null;
    if (!file) return new Response('not found', { status: 404 });
    const content = readFileSync(new URL(file, import.meta.url));
    return new Response(request.method === 'HEAD' ? null : content, { status: 200 });
  }
};

test('Wrangler configuration publishes website assets under existing Worker name', () => {
  assert.equal(config.name, 'mabrig-devshield-ai');
  assert.equal(config.main, 'src/index.mjs');
  assert.equal(config.workers_dev, false);
  assert.deepEqual(config.previews, {}, 'Nested Worker preview must opt in explicitly');
  assert.equal(config.assets.binding, 'ASSETS');
  assert.equal(config.assets.run_worker_first, true);
  assert.equal(config.assets.directory, './public');
  assert.equal(rootConfig.name, config.name);
  assert.deepEqual(rootConfig.previews, {}, 'Root Worker preview must opt in explicitly');
  assert.ok(!('d1_databases' in rootConfig), 'Do not wire production DB into previews');
  assert.equal(rootConfig.main, 'cloudflare-deploy/src/index.mjs');
  assert.equal(rootConfig.assets.directory, './cloudflare-deploy/public');
  assert.equal(rootConfig.assets.binding, config.assets.binding);
  assert.equal(rootConfig.assets.run_worker_first, true);
  assert.ok(!('d1_databases' in config), 'Do not invent a D1 binding');
  assert.ok(!('vars' in config), 'Never put secrets into tracked vars');
  for (const name of ['app.css', 'app.js', 'favicon.svg']) {
    assert.ok(statSync(new URL('../public/' + name, import.meta.url)).size > 0);
  }
});
test('homepage renders an accessible interactive local preview, not Hello World', async () => {
  const response = await worker.fetch(new Request('https://devshield.mabrigkorie.org/'), { ASSETS: assets });
  assert.equal(response.status, 200);
  assert.match(response.headers.get('content-type'), /text\/html/);
  assert.match(response.headers.get('content-security-policy'), /connect-src 'none'/);
  assert.match(response.headers.get('content-security-policy'), /script-src 'self'/);
  assert.doesNotMatch(response.headers.get('content-security-policy'), /unsafe-inline/);
  const html = await response.text();
  assert.match(html, /DevShield AI/);
  assert.match(html, /id="scanner"/);
  assert.match(html, /id="scan-button"/);
  assert.match(html, /No code upload/);
  assert.doesNotMatch(html, /Hello world/);
  assert.doesNotMatch(html, /onerror=|onclick=|style=/);
  const head = await worker.fetch(new Request('https://devshield.mabrigkorie.org/', { method: 'HEAD' }));
  assert.equal(head.status, 200);
  assert.equal(await head.text(), '');
});
test('public asset binding returns script and stylesheet', async () => {
  for (const path of ['/app.css', '/app.js', '/favicon.svg']) {
    const response = await worker.fetch(new Request('https://devshield.mabrigkorie.org' + path), { ASSETS: assets });
    assert.equal(response.status, 200);
    assert.ok((await response.text()).length > 100);
  }
  const noAssets = await worker.fetch(new Request('https://devshield.mabrigkorie.org/app.js'));
  assert.equal(noAssets.status, 503);
});
test('health reveals truthful scope and API fails closed', async () => {
  const response = await worker.fetch(new Request('https://devshield.mabrigkorie.org/health'));
  assert.equal(response.status, 200);
  const body = await response.json();
  assert.equal(body.ok, true);
  assert.equal(body.hostedScanning, false);
  assert.equal(body.billing, false);
  assert.equal(body.browserPreview, 'client-only');
  const api = await worker.fetch(new Request('https://devshield.mabrigkorie.org/api/v1/scans'));
  assert.equal(api.status, 503);
  assert.equal((await api.json()).error, 'api_not_configured');
  const missing = await worker.fetch(new Request('https://devshield.mabrigkorie.org/unsupported'));
  assert.equal(missing.status, 404);
  const write = await worker.fetch(new Request('https://devshield.mabrigkorie.org/health', { method: 'POST' }));
  assert.equal(write.status, 405);
});
test('browser scanner does not contain network calls and has bounded file selection', () => {
  const script = readFileSync(new URL('../public/app.js', import.meta.url), 'utf8');
  assert.doesNotMatch(script, /\bfetch\s*\(|\bXMLHttpRequest\b|\bsendBeacon\b/);
  assert.match(script, /const maxFiles = 30;/);
  assert.match(script, /const maxBytes = 256 \* 1024;/);
  assert.match(script, /previewScan/);
  assert.match(script, /textContent/);
  assert.doesNotMatch(script, /\.innerHTML\s*=/);
});
