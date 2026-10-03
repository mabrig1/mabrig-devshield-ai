// Deterministic web-framework threat intelligence for advisories that may lag
// generic package-vulnerability feeds. Keep this module dependency-free.

function issue(id, severity, message, cwe, remediation, line, extra = {}) {
  return { id, severity, category: extra.category || 'web-framework', message, cwe, remediation, line, ...extra };
}

function parseExactVersion(spec) {
  const match = String(spec || '').trim().match(/^v?(\d+)\.(\d+)\.(\d+)(?:-[0-9A-Za-z.-]+)?$/);
  if (!match) return null;
  return match.slice(1).map(Number);
}

function compare(a, b) {
  for (let i = 0; i < 3; i++) {
    if (a[i] !== b[i]) return a[i] < b[i] ? -1 : 1;
  }
  return 0;
}

function inRange(version, min, maxExclusive) {
  return compare(version, min) >= 0 && compare(version, maxExclusive) < 0;
}

function nextDependency(packageJson) {
  return packageJson?.dependencies?.next ?? packageJson?.devDependencies?.next ?? null;
}

function dependencyLine(content) {
  const lines = content.split(/\r?\n/);
  const index = lines.findIndex(line => /["']next["']\s*:/.test(line));
  return index >= 0 ? index + 1 : 1;
}

function sourceLine(content, re) {
  const lines = content.split(/\r?\n/);
  const index = lines.findIndex(line => re.test(line));
  return index >= 0 ? index + 1 : 1;
}

export function scanWebThreatIntel(rel, content) {
  const normalized = String(rel || '').replace(/\\/g, '/');
  const findings = [];

  if (/(^|\/)package\.json$/i.test(normalized)) {
    let pkg;
    try { pkg = JSON.parse(content); } catch { pkg = null; }
    const spec = nextDependency(pkg);
    const version = parseExactVersion(spec);
    if (version) {
      const line = dependencyLine(content);
      const versionText = version.join('.');

      if (inRange(version, [16, 2, 0], [16, 3, 6])) {
        findings.push(issue(
          'nextjs-image-response-rce-version',
          'critical',
          `Next.js ${versionText} is in the affected range for GHSA-vcvr-r3jv-pc5j / CVE-2026-94545, a critical next/og ImageResponse remote-code-execution advisory.`,
          'CWE-1395',
          'Upgrade Next.js to 16.3.6 or later and keep eslint-config-next aligned. Review any Node.js next/og ImageResponse code that renders attacker-controlled SVG content, attributes, or styles.',
          line,
          { category: 'dependencies', advisory: 'GHSA-vcvr-r3jv-pc5j', fixedVersion: '16.3.6' }
        ));
      }

      if (
        inRange(version, [10, 0, 0], [15, 5, 24]) ||
        inRange(version, [16, 0, 0], [16, 3, 3])
      ) {
        findings.push(issue(
          'nextjs-avif-image-optimization-rce-version',
          'critical',
          `Next.js ${versionText} is in the affected range for GHSA-2xp9-vwfh-vxw4, an unauthenticated RCE affecting AVIF image optimization through the image stack.`,
          'CWE-1395',
          'Upgrade to a patched Next.js release (15.5.24+ on the 15.x line or 16.3.3+ on the 16.x line). Do not rely on WAF rules as a substitute for patching.',
          line,
          { category: 'dependencies', advisory: 'GHSA-2xp9-vwfh-vxw4' }
        ));
      }

      if (
        inRange(version, [12, 0, 0], [15, 5, 21]) ||
        inRange(version, [16, 0, 0], [16, 2, 11])
      ) {
        findings.push(issue(
          'nextjs-july-2026-security-cluster',
          'high',
          `Next.js ${versionText} is in the vendor-affected range for the July 2026 security cluster, including SSRF in attacker-influenced rewrite destinations and related App Router / Server Action boundary issues.`,
          'CWE-918',
          'Upgrade to at least Next.js 15.5.21 on 15.x or 16.2.11 on 16.x, then review dynamic rewrites/redirects, Server Actions, middleware/proxy authorization, and request-size limits.',
          line,
          { category: 'dependencies', advisory: 'GHSA-p9j2-gv94-2wf4' }
        ));
      }
    } else if (typeof spec === 'string' && spec.trim()) {
      findings.push(issue(
        'nextjs-nonexact-version-review',
        'low',
        `Next.js uses a non-exact version specifier (${spec}); deterministic advisory matching was not attempted.`,
        'CWE-1104',
        'Resolve and review the lockfile version against current Next.js security advisories; prefer an exact or tightly bounded release for production applications.',
        dependencyLine(content),
        { category: 'dependencies', strictOnly: true }
      ));
    }
  }

  if (/\.(?:[cm]?[jt]sx?)$/i.test(normalized)) {
    const hasNextOg = /from\s+["']next\/og["']|require\(\s*["']next\/og["']\s*\)/.test(content);
    const hasImageResponse = /\bnew\s+ImageResponse\s*\(/.test(content);
    const hasSvg = /<svg\b|["']<svg\b/i.test(content);
    const hasRequestInput = /searchParams|get\(["'][^"']+["']\)|request\.url|\bparams\b|headers\s*\(|cookies\s*\(/.test(content);
    const explicitlyEdge = /export\s+const\s+runtime\s*=\s*["']edge["']/.test(content);
    if (hasNextOg && hasImageResponse && hasSvg && hasRequestInput && !explicitlyEdge) {
      findings.push(issue(
        'nextjs-image-response-untrusted-svg',
        'critical',
        'Node.js next/og ImageResponse appears to combine SVG generation with request-controlled input, matching the vulnerable pattern described in GHSA-vcvr-r3jv-pc5j.',
        'CWE-94',
        'Upgrade Next.js to 16.3.6+ and prevent attacker-controlled values from reaching SVG content, attributes, or styles. If appropriate, use the Edge ImageResponse implementation after validating compatibility.',
        sourceLine(content, /new\s+ImageResponse/),
        { advisory: 'GHSA-vcvr-r3jv-pc5j', confidence: 'high' }
      ));
    }
  }

  if (/(^|\/)next\.config\.(?:js|mjs|cjs|ts)$/i.test(normalized)) {
    const dynamicExternalHost = /destination\s*:\s*[\`"']https?:\/\/(?:\$\{|:)[^/\`"']+/i.test(content);
    if (dynamicExternalHost) {
      findings.push(issue(
        'nextjs-dynamic-rewrite-host-ssrf',
        'high',
        'A Next.js rewrite or redirect appears to construct an external destination hostname from a dynamic segment, a pattern covered by GHSA-p9j2-gv94-2wf4.',
        'CWE-918',
        'Upgrade Next.js and replace attacker-controlled destination hostnames with an explicit allowlist or tightly constrained hostname-safe values.',
        sourceLine(content, /destination\s*:/),
        { advisory: 'GHSA-p9j2-gv94-2wf4', confidence: 'high' }
      ));
    }
  }

  return findings;
}
