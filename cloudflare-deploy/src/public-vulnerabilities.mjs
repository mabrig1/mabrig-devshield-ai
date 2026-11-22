// Public, read-only NIST NVD CVE publication lookup.
// This is NOT live intrusion monitoring or evidence of attacks against a website.
export const SUPPORTED_HOURS = [6, 7, 12, 24];
const source = 'NIST National Vulnerability Database (NVD)';
const endpoint = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
const limit = 20;

export function nvdWindow(hours, now = Date.now()) {
  if (!SUPPORTED_HOURS.includes(Number(hours))) return null;
  // Five-minute UTC time buckets enable upstream caching without implying
  // second-by-second freshness; the actual window is returned to callers.
  const end = Math.floor(now / 300000) * 300000;
  const start = end - Number(hours) * 3600000;
  return { hours: Number(hours), start: new Date(start).toISOString(), end: new Date(end).toISOString() };
}
function pickDescription(cve) {
  const descriptions = Array.isArray(cve.descriptions) ? cve.descriptions : [];
  const english = descriptions.find(d => d?.lang === 'en' && typeof d?.value === 'string');
  return english ? english.value.slice(0, 360) : 'Description not supplied by NVD.';
}
function pickSeverity(cve) {
  const metrics = cve?.metrics || {};
  for (const type of ['cvssMetricV40','cvssMetricV31','cvssMetricV30']) {
    const entries = metrics[type];
    if (!Array.isArray(entries)) continue;
    const item = entries.find(e => e?.type === 'Primary') || entries[0];
    const value = item?.cvssData?.baseSeverity || item?.baseSeverity;
    if (typeof value === 'string' && /^(critical|high|medium|low|none)$/i.test(value)) return value.toUpperCase();
  }
  return 'UNKNOWN';
}

export async function fetchPublicVulnerabilities(hours, options = {}) {
  const window = nvdWindow(hours, options.now ?? Date.now());
  if (!window) return { error: 'unsupported_hours', supportedHours: SUPPORTED_HOURS };
  const api = new URL(endpoint);
  api.searchParams.set('pubStartDate', window.start);
  api.searchParams.set('pubEndDate', window.end);
  api.searchParams.set('resultsPerPage', String(limit));
  const upstreamFetch = options.fetchImpl || fetch;
  try {
    const response = await upstreamFetch(api.toString(), {
      headers: { accept: 'application/json' },
      redirect: 'error',
      signal: AbortSignal.timeout(6500),
      cf: { cacheEverything: true, cacheTtl: 300 }
    });
    if (!response.ok) throw Error('upstream_unavailable');
    const data = await response.json();
    if (!Array.isArray(data?.vulnerabilities) || !Number.isSafeInteger(data?.totalResults) || data.totalResults < 0) {
      throw Error('invalid_upstream_response');
    }
    const items = data.vulnerabilities.map(entry => entry?.cve).filter(cve => (
      typeof cve?.id === 'string' && /^CVE-\d{4}-\d{4,}$/.test(cve.id) &&
      Number.isFinite(Date.parse(cve.published)) &&
      Date.parse(cve.published) >= Date.parse(window.start) &&
      Date.parse(cve.published) <= Date.parse(window.end)
    )).map(cve => ({
      id: cve.id,
      published: cve.published,
      severity: pickSeverity(cve),
      description: pickDescription(cve),
      url: 'https://nvd.nist.gov/vuln/detail/' + cve.id
    })).sort((a, b) => Date.parse(b.published) - Date.parse(a.published)).slice(0, limit);
    return {
      status: 'ok',
      dataType: 'newly-published-cves',
      source,
      sourceUrl: 'https://nvd.nist.gov/developers/vulnerabilities',
      window,
      fetchedAt: new Date(options.now ?? Date.now()).toISOString(),
      reportedTotal: data.totalResults,
      returned: items.length,
      partial: data.totalResults > limit,
      items,
      scopeNote: 'NVD publications are not a complete world cybersecurity news feed or proof of live attacks, exploitation or compromise. Results can be delayed.'
    };
  } catch {
    return {
      status: 'unavailable',
      dataType: 'newly-published-cves',
      source,
      window,
      error: 'official_source_unavailable',
      scopeNote: 'The official data source could not be verified. No zero-incident or no-vulnerability claim is made.'
    };
  }
}
