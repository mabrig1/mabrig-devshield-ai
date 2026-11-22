import test from 'node:test';
import assert from 'node:assert/strict';
import worker from '../src/index.mjs';
import { fetchPublicVulnerabilities, nvdWindow, SUPPORTED_HOURS } from '../src/public-vulnerabilities.mjs';

const now = Date.UTC(2026, 10, 22, 20, 8, 0);
const cv = (id, published) => ({
  cve: {
    id, published,
    descriptions: [{ lang: 'en', value: 'A publicly disclosed software vulnerability.' }],
    metrics: { cvssMetricV31: [{ type: 'Primary', cvssData: { baseSeverity: 'HIGH' } }] }
  }
});

test('only specifically requested hour windows are available', () => {
  assert.deepEqual(SUPPORTED_HOURS, [6, 7, 12, 24]);
  for (const h of SUPPORTED_HOURS) {
    const w = nvdWindow(h, now);
    assert.equal(w.hours, h);
    assert.equal(Date.parse(w.end) - Date.parse(w.start), h * 3600000);
    assert.equal(Date.parse(w.end), Date.UTC(2026, 10, 22, 20, 5));
  }
  assert.equal(nvdWindow(48, now), null);
  assert.equal(nvdWindow(-1, now), null);
});

test('NVD lookup is fixed-origin, bounded and contains only official evidence', async () => {
  let requests = 0;
  const result = await fetchPublicVulnerabilities(6, {
    now,
    fetchImpl: async (url, options) => {
      requests++;
      const parsed = new URL(url);
      assert.equal(parsed.origin, 'https://services.nvd.nist.gov');
      assert.equal(parsed.pathname, '/rest/json/cves/2.0');
      assert.equal(parsed.searchParams.get('resultsPerPage'), '20');
      assert.equal(options.redirect, 'error');
      assert.equal(options.headers.accept, 'application/json');
      return new Response(JSON.stringify({
        totalResults: 2, vulnerabilities: [
          cv('CVE-2026-123456', '2026-11-22T19:30:00.000Z'),
          cv('CVE-2026-123457', '2026-11-22T19:45:00.000Z')
        ]
      }), { status: 200 });
    }
  });
  assert.equal(requests, 1);
  assert.equal(result.status, 'ok');
  assert.equal(result.reportedTotal, 2);
  assert.equal(result.items[0].id, 'CVE-2026-123457');
  assert.match(result.items[0].url, /^https:\/\/nvd\.nist\.gov\/vuln\/detail\/CVE-/);
  assert.match(result.scopeNote, /not a complete world cybersecurity news feed or proof of live attacks/i);
});

test('unverified, malformed and throttled data fail closed', async () => {
  for (const response of [
    new Response('Too many requests', { status: 429 }),
    new Response(JSON.stringify({ vulnerabilities: [], totalResults: '0' }), { status: 200 }),
    new Response('bad JSON', { status: 200 })
  ]) {
    const result = await fetchPublicVulnerabilities(7, { now, fetchImpl: async () => response });
    assert.equal(result.status, 'unavailable');
    assert.equal(result.error, 'official_source_unavailable');
    assert.equal(result.reportedTotal, undefined);
  }
});

test('no new published CVEs is never represented as no cyber attacks', async () => {
  const result = await fetchPublicVulnerabilities(12, { now, fetchImpl: async () =>
    new Response(JSON.stringify({ totalResults: 0, vulnerabilities: [] }), { status: 200 })
  });
  assert.equal(result.reportedTotal, 0);
  assert.match(result.scopeNote, /not.*proof of live attacks/i);
});

test('unsupported hours fail before a network call; legacy private APIs remain disabled', async () => {
  const fail = await fetchPublicVulnerabilities(42, { now, fetchImpl: async () => { throw Error('must not fetch'); } });
  assert.equal(fail.error, 'unsupported_hours');
  const bad = await worker.fetch(new Request('https://devshield.mabrigkorie.org/api/v1/public-vulnerabilities?hours=30'));
  assert.equal(bad.status, 400);
  const privateApi = await worker.fetch(new Request('https://devshield.mabrigkorie.org/api/v1/scans'));
  assert.equal(privateApi.status, 503);
  assert.equal((await privateApi.json()).error, 'api_not_configured');
});
