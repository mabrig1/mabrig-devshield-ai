import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import worker from '../src/index.mjs';

test('Wrangler configuration names the existing dashboard Worker and has a real entry point', () => {
  const config = JSON.parse(readFileSync(new URL('../wrangler.json', import.meta.url), 'utf8'));
  assert.equal(config.name, 'mabrig-devshield-ai');
  assert.equal(config.main, 'src/index.mjs');
  assert.equal(config.workers_dev, false);
  assert.ok(!('d1_databases' in config), 'Do not invent a D1 binding');
  assert.ok(!('vars' in config), 'Never put credentials in vars');
});

test('health endpoint responds without public secrets or API claims', async () => {
  const response = await worker.fetch(new Request('https://example.test/health'));
  assert.equal(response.status, 200);
  const data = await response.json();
  assert.equal(data.cloudScanning, false);
  assert.equal(data.billing, false);
});

test('API surface fails closed until actually configured', async () => {
  const api = await worker.fetch(new Request('https://example.test/api/v1/scans'));
  assert.equal(api.status, 503);
  assert.equal((await api.json()).error, 'api_not_configured');
  const missing = await worker.fetch(new Request('https://example.test/private'));
  assert.equal(missing.status, 404);
  const write = await worker.fetch(new Request('https://example.test/health', { method: 'POST' }));
  assert.equal(write.status, 405);
});
