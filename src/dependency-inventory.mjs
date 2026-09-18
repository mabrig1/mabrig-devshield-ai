import crypto from 'node:crypto';

const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const hash = value => crypto.createHash('sha256').update(value).digest('hex');
const text = value => typeof value === 'string' && value.length <= 2048 ? value : '';
const versionPattern = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;
const namePattern = /^(?:@[a-z0-9._~-]+\/)?[a-z0-9._~-]+$/i;

function integrityEvidence(value) {
  const raw = text(value).trim();
  if (!raw) return { status: 'missing', algorithms: [] };
  const algorithms = raw.split(/\s+/).flatMap(token => {
    const match = /^(sha1|sha256|sha384|sha512)-([A-Za-z0-9+/]+={0,2})$/.exec(token);
    if (!match) return [];
    const lengths = { sha1: 20, sha256: 32, sha384: 48, sha512: 64 };
    const bytes = Buffer.from(match[2], 'base64');
    if (bytes.length !== lengths[match[1]] || bytes.toString('base64').replace(/=+$/, '') !== match[2].replace(/=+$/, '')) return [];
    return [match[1]];
  });
  const unique = [...new Set(algorithms)].sort();
  return { status: unique.length ? 'recorded-unverified' : 'invalid', algorithms: unique };
}

function sourceEvidence(entry) {
  const resolved = text(entry.resolved);
  if (entry.link === true) return { kind: 'workspace-link', transport: null };
  if (/^(?:git(?:\+[^:]+)?|ssh):/i.test(resolved) || /^git@/i.test(resolved)) {
    return { kind: 'git', transport: /^(?:git:|git\+http:)/i.test(resolved) ? 'insecure' : 'other' };
  }
  if (resolved.startsWith('file:') || (resolved && !/^[a-z][a-z0-9+.-]*:/i.test(resolved) && !resolved.startsWith('//'))) {
    return { kind: 'local', transport: null };
  }
  try {
    const url = new URL(resolved);
    if (url.protocol === 'http:' || url.protocol === 'https:') {
      return { kind: 'remote-archive', transport: url.protocol === 'https:' ? 'https' : 'insecure' };
    }
  } catch { /* Missing and unrecognised sources remain unknown. */ }
  return { kind: 'unknown', transport: null };
}

/** Parse metadata only: never install packages, execute scripts, or query a registry. */
export function createDependencyInventory(raw, { sourceFile = 'package-lock.json' } = {}) {
  let lock;
  try { lock = JSON.parse(raw); } catch { throw new Error('Lockfile is not valid JSON.'); }
  if (!object(lock) || ![2, 3].includes(lock.lockfileVersion) || !object(lock.packages)) {
    throw new Error('Expected an npm v2 or v3 lockfile with a packages object.');
  }
  const entries = Object.entries(lock.packages);
  if (entries.length > 100_000) throw new Error('Lockfile exceeds the 100000 package limit.');
  const packages = [];
  const findings = [];
  for (const [location, entry] of entries.sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0)) {
    if (!object(entry)) throw new Error('Lockfile contains an invalid package entry.');
    if (!location) continue; // The root project is not an installed dependency.
    if (location.length > 2048 || location.includes('\\') || location.startsWith('/') || /[\x00-\x1f\x7f]/.test(location) || location.split('/').some(p => p === '..' || p === '.' || !p)) {
      throw new Error('Lockfile contains an unsafe package location.');
    }
    const inferred = location.includes('node_modules/') ? location.split('node_modules/').at(-1) : '';
    const candidateName = text(entry.name) || inferred;
    const name = namePattern.test(candidateName) ? candidateName : null;
    const version = versionPattern.test(text(entry.version)) ? entry.version : null;
    const license = text(entry.license).trim();
    const declaredLicense = license && /^[A-Za-z0-9.+() -]{1,200}$/.test(license) ? license : null;
    const source = sourceEvidence(entry);
    const integrity = integrityEvidence(entry.integrity);
    const local = ['local', 'workspace-link'].includes(source.kind) || !location.includes('node_modules/');
    const issues = [];
    const add = (ruleId, severity, message, remediation) => issues.push({ ruleId, severity, message, remediation });
    if (source.transport === 'insecure') add('dependency-insecure-source', 'high', 'Dependency source uses an unencrypted transport.', 'Use an HTTPS registry/archive or an authenticated secure Git transport.');
    if (!local && source.kind !== 'git' && integrity.status !== 'recorded-unverified') add('dependency-integrity-metadata', 'medium', 'Dependency integrity metadata is missing or invalid.', 'Regenerate the lockfile from a trusted registry and review the resulting changes.');
    if (!local && integrity.algorithms.length === 1 && integrity.algorithms[0] === 'sha1') add('dependency-weak-integrity', 'low', 'Only a SHA-1 integrity digest is recorded.', 'Where supported, refresh metadata to include SHA-512 integrity.');
    if (!local && source.kind === 'unknown') add('dependency-source-unknown', 'low', 'Dependency source is not recorded or recognised.', 'Review registry configuration and package origin before installation.');
    const item = {
      location, name, version,
      packageUrl: name && version ? `pkg:npm/${name.split('/').map(encodeURIComponent).join('/')}@${encodeURIComponent(version)}` : null,
      source,
      license: { status: declaredLicense ? 'declared-unverified' : 'unknown', expression: declaredLicense },
      integrity: local ? { status: 'not-applicable', algorithms: [] } : integrity,
      developmentOnly: entry.dev === true, optional: entry.optional === true,
      installScript: entry.hasInstallScript === true ? 'declared' : 'not-declared',
      evidence: { sourceFile, jsonPointer: `/packages/${location.replace(/~/g, '~0').replace(/\//g, '~1')}` }
    };
    packages.push(item);
    findings.push(...issues.map(issue => ({ ...issue, location, packageUrl: item.packageUrl, fingerprint: hash(`${issue.ruleId}\0${location}\0${name || ''}\0${version || ''}`), evidence: item.evidence })));
  }
  return {
    schemaVersion: 1,
    tool: 'MABRIG DevShield AI',
    source: { file: sourceFile, sha256: hash(raw), lockfileVersion: lock.lockfileVersion, snapshot: 'working-tree' },
    coverage: { ecosystem: 'npm', networkAccess: false, vulnerabilityCheck: 'not-performed', signatureCheck: 'not-performed', artifactIntegrityCheck: 'not-performed', licenseVerification: 'not-performed' },
    summary: {
      packages: packages.length, findings: findings.length,
      unknownLicenses: packages.filter(p => p.license.status === 'unknown').length,
      installScriptsDeclared: packages.filter(p => p.installScript === 'declared').length,
      bySeverity: Object.fromEntries(['high', 'medium', 'low'].map(s => [s, findings.filter(f => f.severity === s).length]))
    },
    packages, findings
  };
}

export function inventoryBlocks(report, severity = 'high') {
  const ranks = { none: Infinity, low: 1, medium: 2, high: 3, critical: 4 };
  if (!Object.hasOwn(ranks, severity)) throw new Error('Invalid fail-on severity.');
  return report.findings.some(f => ranks[f.severity] >= ranks[severity]);
}

export function inventoryMarkdown(report) {
  const counts = report.summary;
  return `# MABRIG DevShield dependency evidence\n\n` +
    `Packages inventoried: ${counts.packages}. Metadata findings: ${counts.findings} ` +
    `(high: ${counts.bySeverity.high}, medium: ${counts.bySeverity.medium}, low: ${counts.bySeverity.low}).\n\n` +
    `Unknown licenses: ${counts.unknownLicenses}. Declared install scripts: ${counts.installScriptsDeclared}.\n\n` +
    `Lockfile SHA-256: ${report.source.sha256}\n\n` +
    `This is an offline working-tree metadata review. It does not check current vulnerabilities, ` +
    `verify package contents or signatures, or establish legal license compliance. ` +
    `Recorded integrity digests are unverified. Zero findings does not certify a dependency as safe.\n\n` +
    `See dependency-inventory.json for package identities, JSON pointers, stable fingerprints, and remediation. ` +
    `Resolved URLs are omitted to avoid copying URL credentials, query strings, or fragments into reports.\n`;
}
