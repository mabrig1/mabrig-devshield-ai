import test from 'node:test';
import assert from 'node:assert/strict';
import { verifyPublicDevShield } from '../src/public-deployment-smoke.mjs';

function makeResponses(overrides = {}) {
  const pages = {
    '/': ['<!doctype html><title>DevShield AI — Security</title><section id="scanner"><button id="scan-button">Scan</button></section>', 'text/html; charset=utf-8'],
    '/health': [JSON.stringify({
      ok: true, component: 'DevShield Website', website: 'available',
      hostedScanning: false, billing: false
    }), 'application/json'],
    '/app.js': ['const previewScan = () => "local"; ' + 'const demo = 1;'.repeat(10), 'text/javascript'],
    '/app.css': ['body { font-family: sans-serif; }' + '.button { margin: 1px; }'.repeat(10), 'text/css']
  };
  return async (url, options) => {
    assert.equal(options.method, 'GET');
    assert.equal(options.redirect, 'manual');
    assert.equal(options.signal.aborted, false);
    assert.equal(new URL(url).origin, 'https://devshield.mabrigkorie.org');
    const page = new URL(url).pathname;
    const [text, type] = overrides[page] || pages[page] || ['Not Found', 'text/plain'];
    return new Response(text, {
      status: page in pages ? 200 : 404,
      headers: { 'content-type': type }
    });
  };
}

test('live-site smoke validates content, assets and truthful service scope', async () => {
  const report = await verifyPublicDevShield(makeResponses());
  assert.equal(report.ok, true);
  assert.equal(report.hostedScanning, false);
  assert.equal(report.browserInteractionTested, false);
  assert.equal(report.checks.length, 5);
});

test('placeholder Hello World fails even if endpoint responds 200', async () => {
  const fake = makeResponses({
    '/': ['<html><title>Hello World</title><h1>Hello World</h1></html>', 'text/html']
  });
  await assert.rejects(() => verifyPublicDevShield(fake), /Hello World/);
});

test('wrong homepage and dead or misleading /health fail closed', async () => {
  await assert.rejects(() => verifyPublicDevShield(makeResponses({
    '/': ['<html><title>Other Product</title></html>', 'text/html']
  })), /homepage\/scanner/);
  await assert.rejects(() => verifyPublicDevShield(makeResponses({
    '/health': ['{"ok":true,"component":"Other Product"}', 'application/json']
  })), /health response/);
  await assert.rejects(() => verifyPublicDevShield(makeResponses({
    '/health': ['not-json', 'application/json']
  })), /invalid JSON/);
});

test('missing frontend asset fails rather than reporting deployment success', async () => {
  await assert.rejects(() => verifyPublicDevShield(makeResponses({
    '/app.js': ['not found', 'text/plain']
  })), /JavaScript asset/);
  await assert.rejects(() => verifyPublicDevShield(makeResponses({
    '/app.css': ['not found', 'text/plain']
  })), /CSS asset/);
});

test('redirects are not followed to a different origin', async () => {
  await assert.rejects(() => verifyPublicDevShield(async (url, options) => {
    if (new URL(url).pathname === '/') return new Response('redirect', { status: 302, headers: { location: 'https://attacker.example/' } });
    return makeResponses()(url, options);
  }), /HTTP 302/);
});
