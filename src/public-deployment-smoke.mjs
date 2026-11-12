// Public, read-only post-deployment check. No credentials and no source upload.
const ORIGIN = 'https://devshield.mabrigkorie.org';

function fail(message) { throw new Error('DevShield public smoke check: ' + message); }
async function get(fetcher, pathname) {
  let response;
  try {
    response = await fetcher(ORIGIN + pathname, {
      method: 'GET',
      redirect: 'manual',
      headers: { accept: pathname === '/health' ? 'application/json' : '*/*' },
      signal: AbortSignal.timeout(10000)
    });
  } catch {
    fail(pathname + ' cannot be reached');
  }
  if (response.status !== 200) fail(pathname + ' returned HTTP ' + response.status);
  if (response.url) {
    let url;
    try { url = new URL(response.url); } catch { fail(pathname + ' has an invalid response URL'); }
    if (url.origin !== ORIGIN || url.pathname !== pathname) {
      fail(pathname + ' unexpectedly redirected or served from another origin');
    }
  }
  const type = (response.headers.get('content-type') || '').toLowerCase();
  const declaredSize = Number(response.headers.get('content-length') || 0);
  if (declaredSize > 256 * 1024) fail(pathname + ' exceeds expected response cap');
  const content = await response.text();
  if (content.length > 256 * 1024) fail(pathname + ' response exceeds expected cap');
  return { type, content };
}

/**
 * Verify the actual, public Worker deployment—not only local Wrangler compilation.
 * This deliberately checks an informational site rather than asserting commercial
 * API availability. The caller never sends source code, API keys or private URLs.
 */
export async function verifyPublicDevShield(fetcher = globalThis.fetch) {
  if (typeof fetcher !== 'function') throw new TypeError('fetcher required');
  const [homepage, health, script, stylesheet] = await Promise.all([
    get(fetcher, '/'), get(fetcher, '/health'),
    get(fetcher, '/app.js'), get(fetcher, '/app.css')
  ]);
  if (!homepage.type.includes('text/html')) fail('homepage is not HTML');
  if (/<title>\s*hello\s+world\s*<\/title>/i.test(homepage.content) ||
      /<h1[^>]*>\s*hello\s+world\s*<\/h1>/i.test(homepage.content)) {
    fail('placeholder Hello World remains in production');
  }
  if (!/<title>[^<]*DevShield AI/i.test(homepage.content) ||
      !/id=["']scanner["']/.test(homepage.content) ||
      !/id=["']scan-button["']/.test(homepage.content)) {
    fail('expected DevShield homepage/scanner is missing');
  }
  if (!health.type.includes('application/json')) fail('health is not JSON');
  let state;
  try { state = JSON.parse(health.content); } catch { fail('health contains invalid JSON'); }
  if (state.ok !== true || state.component !== 'DevShield Website' ||
      state.website !== 'available' ||
      typeof state.hostedScanning !== 'boolean' ||
      typeof state.billing !== 'boolean') {
    fail('health response is inconsistent or missing essential service flags');
  }
  if (!/javascript|ecmascript/.test(script.type) || script.content.trim().length < 100) {
    fail('browser scanner JavaScript asset is missing');
  }
  if (!stylesheet.type.includes('text/css') || stylesheet.content.trim().length < 100) {
    fail('browser scanner CSS asset is missing');
  }
  return {
    ok: true, origin: ORIGIN,
    checks: ['homepage-not-placeholder', 'browser-scanner-present',
      'health-json-consistent', 'browser-js-served', 'browser-css-served'],
    hostedScanning: state.hostedScanning,
    billing: state.billing,
    // Avoid false claims: this smoke test does not execute browser JavaScript.
    browserInteractionTested: false
  };
}
