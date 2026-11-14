// Curated November 2026 modern-app advisories.
// Deterministic, offline, exact installed npm lockfile version matching.
// These are advisory-version matches, NEVER evidence of exploitability or runtime compromise.
import crypto from 'node:crypto';

export const CATALOG_AS_OF = '2026-11-14';
const FIXED = 'Upgrade to a patched release in the same supported version line; rebuild and verify the deployed dependency tree.';

// Bounds are [inclusive minimum, exclusive maximum]. No ranges are inferred
// from package names alone, manifest semver specifiers or source-code strings.
export const KNOWN_ADVISORIES = Object.freeze([
  {
    id: 'GHSA-xqc2-xf4c-x3h3', cve: 'CVE-2026-126187',
    title: 'React Server Components: unauthenticated RCE in typed-array Flight payloads',
    packages: ['react-server-dom-webpack', 'react-server-dom-turbopack', 'react-server-dom-parcel'],
    ranges: [['19.0.0', '19.0.9'], ['19.1.0', '19.1.10'], ['19.2.0', '19.2.9'], ['19.3.0', '19.3.1']],
    severity: 'critical',
    fixed: '19.0.9 / 19.1.10 / 19.2.9 / 19.3.1',
    preconditions: 'Only applications using React Server Components with an affected Flight payload shape; presence of a package alone does not prove exposure.',
    recommendation: FIXED,
    url: 'https://github.com/advisories/GHSA-xqc2-xf4c-x3h3'
  },
  {
    id: 'GHSA-673q-mjm6-r5xr',
    title: 'Next.js: unauthenticated RCE in use cache functions returning typed arrays',
    packages: ['next'], ranges: [['16.0.0', '16.4.1']],
    severity: 'critical', fixed: '16.4.1 (minimum)',
    preconditions: 'Affected Next.js App Router applications using Cache Components and a use cache function returning multiple typed arrays with attacker-controlled content.',
    recommendation: FIXED, url: 'https://github.com/advisories/GHSA-673q-mjm6-r5xr'
  },
  {
    id: 'GHSA-2464-fhr4-w9xw',
    title: 'Next.js: unauthenticated image-optimizer RCE involving SVG',
    packages: ['next'], ranges: [['10.0.0', '15.5.28'], ['16.0.0', '16.4.1']],
    severity: 'critical', fixed: '15.5.28 / 16.4.1 (minimum)',
    preconditions: 'Affected Next.js servers exposing the vulnerable image optimization path; exploitability depends on actual configuration and request routing.',
    recommendation: FIXED, url: 'https://github.com/advisories/GHSA-2464-fhr4-w9xw'
  },
  {
    id: 'GHSA-pcrw-h46h-c93h', cve: 'CVE-2026-125120',
    title: 'Mongoose: sanitizeFilter not applied to countDocuments',
    packages: ['mongoose'],
    ranges: [[null, '6.13.11'], ['7.0.0', '7.8.12'], ['8.0.0', '8.24.3'], ['9.0.0', '9.9.2']],
    severity: 'critical', fixed: '6.13.11 / 7.8.12 / 8.24.3 / 9.9.2 (minimum)',
    preconditions: 'Relevant when the application relies on sanitizeFilter and passes attacker-controlled filters to countDocuments; not every installation is exploitable.',
    recommendation: FIXED, url: 'https://github.com/advisories/GHSA-pcrw-h46h-c93h'
  },
  {
    id: 'GHSA-965c-763c-88jm', cve: 'CVE-2026-114607',
    title: 'Better Auth: OAuth state can authenticate as another user through Magic Link',
    packages: ['better-auth'], ranges: [['1.4.0-beta.18', '1.7.7']],
    severity: 'critical', fixed: '1.7.7 (minimum)',
    preconditions: 'Requires Magic Link plus social/Generic OAuth, vulnerable token-storage/identifier settings, and database-backed OAuth state or an affected OAuth proxy path.',
    recommendation: FIXED, url: 'https://github.com/advisories/GHSA-965c-763c-88jm'
  },
  {
    id: 'GHSA-qx66-fv34-fjm8', cve: 'CVE-2026-102989',
    title: 'TanStack Start: reflected XSS in server function responses',
    packages: ['@tanstack/react-start'],
    ranges: [['1.143.12', '1.168.60']], severity: 'critical', fixed: '1.168.60 (minimum)',
    preconditions: 'Affected TanStack Start server-function endpoints; review public exposure and downstream browser execution context.',
    recommendation: FIXED, url: 'https://github.com/advisories/GHSA-qx66-fv34-fjm8'
  },
  {
    id: 'GHSA-qx66-fv34-fjm8', cve: 'CVE-2026-102989',
    title: 'TanStack Start: reflected XSS in server function responses',
    packages: ['@tanstack/solid-start'],
    ranges: [['1.143.12', '1.168.57']], severity: 'critical', fixed: '1.168.57 (minimum)',
    preconditions: 'Affected TanStack Start server-function endpoints; review public exposure and downstream browser execution context.',
    recommendation: FIXED, url: 'https://github.com/advisories/GHSA-qx66-fv34-fjm8'
  },
  {
    id: 'GHSA-qx66-fv34-fjm8', cve: 'CVE-2026-102989',
    title: 'TanStack Start: reflected XSS in server function responses',
    packages: ['@tanstack/vue-start'],
    ranges: [['1.143.12', '1.168.56']], severity: 'critical', fixed: '1.168.56 (minimum)',
    preconditions: 'Affected TanStack Start server-function endpoints; review public exposure and downstream browser execution context.',
    recommendation: FIXED, url: 'https://github.com/advisories/GHSA-qx66-fv34-fjm8'
  },
  {
    id: 'GHSA-qx66-fv34-fjm8', cve: 'CVE-2026-102989',
    title: 'TanStack Start: reflected XSS in server function responses',
    packages: ['@tanstack/start-server-core'],
    ranges: [['1.143.12', '1.169.39']], severity: 'critical', fixed: '1.169.39 (minimum)',
    preconditions: 'Affected TanStack Start server-function endpoints; review public exposure and downstream browser execution context.',
    recommendation: FIXED, url: 'https://github.com/advisories/GHSA-qx66-fv34-fjm8'
  },
  {
    id: 'GHSA-cg2g-xh64-v4q7',
    title: 'DOMPurify: SAFE_FOR_TEMPLATES bypass inside attached shadow roots',
    packages: ['dompurify'],
    ranges: [['3.4.4', '3.4.17']], severity: 'critical', fixed: '3.4.17 (minimum)',
    preconditions: 'Requires SAFE_FOR_TEMPLATES with DOM-returning or IN_PLACE mode and attacker-controlled shadow-root content; string-only output is not affected by this issue.',
    recommendation: FIXED, url: 'https://github.com/advisories/GHSA-cg2g-xh64-v4q7'
  },
  {
    id: 'GHSA-f2ph-cmg5-wxc8', cve: 'CVE-2026-114125',
    title: 'Storybook: unvalidated Origin permits dev-server preview code injection',
    packages: ['storybook', '@storybook/addon-vitest'],
    ranges: [['9.0.0', '9.1.21'], ['10.0.0', '10.6.2']],
    severity: 'critical', fixed: '9.1.21 / 10.6.2 (minimum)',
    preconditions: 'Requires running and visiting an affected Storybook development server; published static Storybook builds are not impacted by this advisory.',
    recommendation: FIXED, url: 'https://github.com/advisories/GHSA-f2ph-cmg5-wxc8'
  },
  {
    id: 'GHSA-f2ph-cmg5-wxc8', cve: 'CVE-2026-114125',
    title: 'Storybook: unvalidated Origin permits dev-server preview code injection',
    packages: ['storybook', '@storybook/core', '@storybook/core-server', '@storybook/experimental-addon-test'],
    ranges: [['8.0.0', '8.6.19']],
    severity: 'critical', fixed: '8.6.19 (minimum)',
    preconditions: 'Requires an affected running and visited Storybook development server; built Storybook sites are not impacted.',
    recommendation: FIXED, url: 'https://github.com/advisories/GHSA-f2ph-cmg5-wxc8'
  },
  {
    id: 'GHSA-f2ph-cmg5-wxc8', cve: 'CVE-2026-114125',
    title: 'Storybook: unvalidated Origin permits dev-server preview code injection',
    packages: ['@storybook/addon-mcp'],
    ranges: [['10.6.0', '10.6.2']],
    severity: 'critical', fixed: '10.6.2 (minimum)',
    preconditions: 'Requires an affected Storybook dev server and client browser context; no automatic inference of code execution.',
    recommendation: FIXED, url: 'https://github.com/advisories/GHSA-f2ph-cmg5-wxc8'
  }
]);

// A conservative SemVer 2.0 comparator for exact lockfile-installed versions.
// 1.4.0-beta.18 < 1.4.0; build metadata never influences ordering.
export function parseExactVersion(raw) {
  if (typeof raw !== 'string' || raw.length > 100) return null;
  const match = /^(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/.exec(raw);
  if (!match) return null;
  const pre = match[4] ? match[4].split('.') : [];
  if (pre.some(v => /^\d+$/.test(v) && v.length > 1 && v.startsWith('0'))) return null;
  return { major: Number(match[1]), minor: Number(match[2]), patch: Number(match[3]), pre };
}
export function compareVersions(a, b) {
  const x = typeof a === 'string' ? parseExactVersion(a) : a;
  const y = typeof b === 'string' ? parseExactVersion(b) : b;
  if (!x || !y) throw new TypeError('Compare only valid exact semver versions');
  for (const key of ['major', 'minor', 'patch']) {
    if (x[key] !== y[key]) return x[key] < y[key] ? -1 : 1;
  }
  if (!x.pre.length && !y.pre.length) return 0;
  if (!x.pre.length) return 1;
  if (!y.pre.length) return -1;
  for (let i = 0; i < Math.min(x.pre.length, y.pre.length); i++) {
    const aId = x.pre[i], bId = y.pre[i];
    if (aId === bId) continue;
    const aNum = /^\d+$/.test(aId), bNum = /^\d+$/.test(bId);
    if (aNum && bNum) return Number(aId) < Number(bId) ? -1 : 1;
    if (aNum !== bNum) return aNum ? -1 : 1;
    return aId < bId ? -1 : 1;
  }
  return Math.sign(x.pre.length - y.pre.length);
}
function affected(version, ranges) {
  return ranges.some(([min, max]) => (!min || compareVersions(version, min) >= 0) && (!max || compareVersions(version, max) < 0));
}

/** Takes the existing npm v2/v3 inventory object; never imports/executes packages. */
export function scanKnownNpmAdvisories(inventory, { maxFindings = 1000 } = {}) {
  if (!inventory || !Array.isArray(inventory.packages) || inventory.coverage?.ecosystem !== 'npm') {
    throw new TypeError('Expected a DevShield npm lockfile inventory');
  }
  if (!Number.isSafeInteger(maxFindings) || maxFindings < 1 || maxFindings > 10000) {
    throw new TypeError('maxFindings must be 1..10000');
  }
  const definitionsByPackage = new Map();
  for (const def of KNOWN_ADVISORIES) {
    for (const name of def.packages) {
      if (!definitionsByPackage.has(name)) definitionsByPackage.set(name, []);
      definitionsByPackage.get(name).push(def);
    }
  }
  const findings = [];
  let candidateInstallations = 0;
  let unassessedCandidateVersions = 0;
  let excludedLocalInstallations = 0;
  let affectedInstallations = 0;
  let truncated = false;
  for (const pkg of inventory.packages) {
    const name = pkg.name || pkg.installName;
    const definitions = definitionsByPackage.get(name);
    if (!definitions) continue;
    candidateInstallations++;
    if (pkg.source?.kind === 'workspace-link' || pkg.source?.kind === 'local') {
      excludedLocalInstallations++;
      continue;
    }
    const v = parseExactVersion(pkg.version);
    if (!v) { unassessedCandidateVersions++; continue; }
    let matchedInstallation = false;
    for (const advisory of definitions) {
      if (!affected(v, advisory.ranges)) continue;
      matchedInstallation = true;
      if (findings.length >= maxFindings) { truncated = true; continue; }
      const evidence = {
        sourceFile: inventory.source?.file || 'package-lock.json',
        jsonPointer: pkg.evidence?.jsonPointer || null
      };
      findings.push({
        rule: 'known-npm-advisory', advisoryId: advisory.id, cve: advisory.cve || null,
        severity: advisory.severity, category: 'dependencies',
        package: name, version: pkg.version, location: pkg.location,
        packageUrl: pkg.packageUrl, advisoryUrl: advisory.url,
        title: advisory.title, fixedVersions: advisory.fixed,
        message: name + '@' + pkg.version + ' matches affected installed-version range in ' + advisory.id + '.',
        preconditions: advisory.preconditions, remediation: advisory.recommendation,
        confidence: 'installed-lockfile-version-match-only',
        evidence,
        fingerprint: crypto.createHash('sha256').update(
          ['devshield-known-advisory', advisory.id, name, pkg.version, pkg.location].join('\0')
        ).digest('hex')
      });
    }
    if (matchedInstallation) affectedInstallations++;
  }
  findings.sort((a, b) =>
    a.location.localeCompare(b.location) || a.advisoryId.localeCompare(b.advisoryId));
  return {
    schemaVersion: 1, tool: 'MABRIG DevShield Known npm Advisories',
    asOf: CATALOG_AS_OF, mode: 'offline-curated-snapshot', status: (truncated || unassessedCandidateVersions) ? 'incomplete' : 'reviewed',
    scope: 'curated subset of npm advisories; not a complete live vulnerability database',
    coverage: {
      networkAccess: false, codeExecution: false,
      packageSourceVerified: false, dependencyRuntimeUseVerified: false,
      exploitabilityInferred: false, unverifiedOrNonRegistryPackagesMayRequireIndependentReview: true
    },
    summary: {
      catalogEntries: KNOWN_ADVISORIES.length,
      totalInstallations: inventory.packages.length,
      candidateInstallations, excludedLocalInstallations,
      unassessedCandidateVersions, affectedInstallations,
      advisoryMatches: findings.length, truncated
    }, findings
  };
}
export function knownAdvisoriesSarif(report) {
  const rules = [...new Set(report.findings.map(x => x.advisoryId))].map(id =>
    ({ id, name: id, shortDescription: { text: 'Installed npm version matches published security advisory' } }));
  return {
    version: '2.1.0', $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    runs: [{ tool: { driver: { name: 'MABRIG DevShield Known npm Advisories', rules } },
      results: report.findings.map(f => ({
        ruleId: f.advisoryId, level: f.severity === 'critical' || f.severity === 'high' ? 'error' : 'warning',
        message: { text: f.message + ' Review conditions: ' + f.preconditions },
        locations: [{ physicalLocation: { artifactLocation: { uri: f.evidence.sourceFile } } }],
        fingerprints: { 'devshield/known-advisory': f.fingerprint },
        properties: {
          installedVersion: f.version, package: f.package, jsonPointer: f.evidence.jsonPointer,
          advisoryUrl: f.advisoryUrl, fixedVersions: f.fixedVersions,
          confidence: f.confidence, severity: f.severity,
          exploitabilityAssessed: false
        }
      })) }]
  };
}
export function knownAdvisoriesBlock(report, failOn = 'critical') {
  const levels = { none: Infinity, low: 1, medium: 2, high: 3, critical: 4 };
  if (!Object.hasOwn(levels, failOn)) throw new Error('Invalid fail-on severity');
  return report.status !== 'reviewed' || report.findings.some(f => levels[f.severity] >= levels[failOn]);
}
