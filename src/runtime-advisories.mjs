import { createHash } from 'node:crypto';

// Reviewed, offline advisory snapshot. Updating this file requires source review and tests.
// Repository declarations are evidence to investigate, never proof of deployment or compromise.
export const ADVISORY_SNAPSHOT = {
  id: '2026-10-25',
  reviewedAt: '2026-10-25',
  node: {
    source: 'https://nodejs.org/en/blog/vulnerability/october-2026-security-releases',
    fixed: { '22': '22.23.4', '24': '24.22.1', '26': '26.12.1' },
    cves: ['CVE-2026-111497', 'CVE-2026-105482', 'CVE-2026-106069'],
    severity: 'high'
  },
  php: {
    source: 'https://www.php.net/archive/2026.php',
    fixed: { '8.2': '8.2.35', '8.3': '8.3.36', '8.4': '8.4.27', '8.5': '8.5.12' },
    cves: ['CVE-2026-109618', 'CVE-2026-109619'],
    severity: 'critical',
    followUp: 'CVE-2026-115560: review the October 23 session upload-progress advisory, including after applying the October 21 patches. An unusual serialize-handler change at runtime remains relevant.'
  },
  litellm: {
    source: 'https://docs.litellm.ai/blog/security-incident-oct-21-2026',
    version: '1.107.0',
    imageDigest: 'sha256:1bbcb1443bc962e45f5aad53fe3d2c30600e0379715fb6c664cdd3ac126c339e'
  }
};

const exactVersion = value => {
  if (typeof value !== 'string') return null;
  const match = value.trim().match(/^v?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/);
  return match && match.slice(1).every(x => Number.isSafeInteger(Number(x))) ? match.slice(1).map(Number) : null;
};
const compare = (a, b) => a[0] - b[0] || a[1] - b[1] || a[2] - b[2];
const evidenceHash = value => createHash('sha256').update(String(value).trim()).digest('hex');

export function assessRuntimeVersion(runtime, value) {
  const advisory = ADVISORY_SNAPSHOT[runtime];
  if (!['node', 'php'].includes(runtime)) throw new Error('Unsupported runtime');
  const parsed = exactVersion(value);
  const result = {
    runtime, version: parsed ? parsed.join('.') : null,
    status: 'needs-verification', severity: 'medium', fixedVersion: null,
    snapshot: ADVISORY_SNAPSHOT.id, source: advisory.source,
    cves: advisory.cves,
    limitation: 'Version evidence does not establish deployment, reachability, exploitation, or overall security. Vendor backports need separate verification.'
  };
  if (runtime === 'php') result.followUp = advisory.followUp;
  if (!parsed) return result;
  const branch = runtime === 'node' ? String(parsed[0]) : `${parsed[0]}.${parsed[1]}`;
  const fixed = advisory.fixed[branch];
  if (fixed) {
    result.fixedVersion = fixed;
    result.status = compare(parsed, exactVersion(fixed)) < 0 ? 'below-fixed-release' : 'meets-listed-fix';
    result.severity = result.status === 'below-fixed-release' ? advisory.severity : null;
  } else if ((runtime === 'node' && parsed[0] < 26) || (runtime === 'php' && compare(parsed, [8, 2, 0]) < 0)) {
    result.status = 'unsupported-release';
    result.severity = 'high';
  }
  // Future/unlisted branches and prereleases never silently receive a clean assessment.
  return result;
}

function runtimeIssue(runtime, value, line, context = 'pin') {
  const evidence = assessRuntimeVersion(runtime, value);
  if (context === 'constraint' || context === 'digest') {
    evidence.status = 'needs-verification';
    evidence.severity = 'medium';
  }
  if (evidence.status === 'meets-listed-fix') return null;
  const labels = { node: 'Node.js', php: 'PHP' };
  const label = labels[runtime];
  const below = evidence.status === 'below-fixed-release';
  const unsupported = evidence.status === 'unsupported-release';
  return {
    id: `${runtime}-${below ? 'october-2026-runtime' : unsupported ? 'unsupported-runtime' : 'runtime-unverified'}`,
    severity: evidence.severity, category: 'runtime-security', cwe: 'CWE-1104', line,
    message: below
      ? `${label} declaration ${evidence.version} is below the October security release ${evidence.fixedVersion}; deployed runtime and vendor backports are unverified.`
      : unsupported
        ? `${label} declaration uses an unsupported upstream release; verify vendor security support or migrate to a supported patched release.`
        : `${label} runtime cannot be verified from this ${context === 'constraint' ? 'compatibility constraint' : context === 'digest' ? 'digest-pinned image' : 'version declaration'}; check the resolved deployed version.`,
    remediation: `Verify the running ${label} version and vendor patch evidence. ${below ? `Update to ${evidence.fixedVersion} or a later supported patched release, rebuild/restart and verify the active runtime. ` : ''}A source scan or WAF is not a runtime patch. ${runtime === 'php' ? `${evidence.followUp} ` : ''}Source: ${evidence.source}`,
    evidence: { ...evidence, context, declarationHash: evidenceHash(value), deploymentVerified: false }
  };
}

// Native JSON validation followed by a bounded location walk keeps duplicate scalar values
// attached to the correct key/path for changed-line and staged scans.
function jsonScalars(content) {
  try { JSON.parse(content); } catch { return []; }
  const out = [];
  let offset = 0;
  let line = 1;
  const advance = () => { if (content[offset++] === '\n') line++; };
  const space = () => { while (/\s/.test(content[offset] || '') && offset < content.length) advance(); };
  const string = () => {
    const start = offset++;
    while (offset < content.length) {
      if (content[offset] === '\\') { offset += 2; continue; }
      if (content[offset++] === '"') break;
    }
    return JSON.parse(content.slice(start, offset));
  };
  const visit = (keys, depth = 0) => {
    if (depth > 64) throw new Error('JSON nesting limit');
    space();
    const startLine = line;
    if (content[offset] === '{') {
      advance(); space();
      const seenKeys = new Set();
      while (content[offset] !== '}') {
        const keyLine = line;
        const key = string(); space(); advance();
        if (seenKeys.has(key)) throw new Error('Ambiguous duplicate JSON key');
        seenKeys.add(key);
        visit([...keys, key], depth + 1);
        // Attribute scalar findings to their key as well when key and value span lines.
        const last = out.at(-1);
        if (last && JSON.stringify(last.keys) === JSON.stringify([...keys, key])) last.keyLine = keyLine;
        space(); if (content[offset] !== ',') break;
        advance(); space();
      }
      advance();
    } else if (content[offset] === '[') {
      advance(); space(); let i = 0;
      while (content[offset] !== ']') {
        visit([...keys, String(i++)], depth + 1);
        space(); if (content[offset] !== ',') break;
        advance(); space();
      }
      advance();
    } else if (content[offset] === '"') {
      out.push({ keys, value: string(), line: startLine, keyLine: startLine });
    } else {
      while (offset < content.length && !/[\s,\]}]/.test(content[offset])) advance();
    }
  };
  try { visit([]); return out; } catch { return []; }
}

const incidentRecovery = `If an affected artifact was installed or executed, isolate the environment, preserve evidence, rebuild from trusted artifacts and rotate accessible credentials from a clean system. Do not start Python/pip in a suspected environment. A new version alone does not remove persistence or revoke stolen credentials. Source: ${ADVISORY_SNAPSHOT.litellm.source}`;

function litellmIssue(line, confirmedReference, context) {
  return {
    id: confirmedReference ? 'litellm-october-2026-artifact' : 'litellm-october-2026-review',
    severity: confirmedReference ? 'critical' : 'medium', category: 'supply-chain', cwe: 'CWE-506', line,
    message: confirmedReference
      ? 'Reference matches a LiteLLM release or digest implicated in the October 21 supply-chain incident; this is not proof the artifact was installed or executed.'
      : 'LiteLLM artifact is unresolved or uses a mutable incident-era tag; review resolved digest, origin and installation history before concluding exposure.',
    remediation: incidentRecovery,
    evidence: { snapshot: ADVISORY_SNAPSHOT.id, source: ADVISORY_SNAPSHOT.litellm.source, context, deploymentVerified: false }
  };
}

function imageIssues(image, line) {
  const issues = [];
  const [tagged, digest] = image.split('@');
  const split = tagged.lastIndexOf(':');
  const hasTag = split > tagged.lastIndexOf('/');
  const name = hasTag ? tagged.slice(0, split) : tagged;
  const tag = hasTag ? tagged.slice(split + 1) : 'latest';
  const official = name.match(/^(?:(?:docker\.io\/)?library\/|docker\.io\/)?(node|php)$/);
  if (official) {
    // Only known official OS/SAPI suffixes are stripped; prereleases stay unresolved.
    const version = tag.replace(/-(?:alpine|slim|bookworm|bullseye|trixie|buster|fpm|apache|cli|zts)(?:[\w.-]*)$/, '');
    const issue = runtimeIssue(official[1], version, line, digest ? 'digest' : 'pin');
    if (issue) issues.push(issue);
  }
  if (/^(?:(?:docker\.io\/)?berriai\/litellm|ghcr\.io\/berriai\/litellm(?:-database|-non_root)?)$/.test(name)) {
    const knownDigest = digest === ADVISORY_SNAPSHOT.litellm.imageDigest;
    if (knownDigest || (!digest && tag === 'v1.107.0')) issues.push(litellmIssue(line, true, 'container-reference'));
    else if (digest || ['latest', 'main-latest', 'main-stable'].includes(tag)) issues.push(litellmIssue(line, false, 'container-reference'));
  }
  for (const issue of issues) issue.evidence.referenceHash = evidenceHash(image);
  return issues;
}

export function auditRuntimeAdvisories(file, content) {
  const normalized = file.replace(/\\/g, '/');
  const base = normalized.split('/').at(-1);
  const lines = content.split(/\r?\n/);
  const issues = [];
  const add = issue => { if (issue) issues.push(issue); };
  if (['.nvmrc', '.node-version', '.php-version'].includes(base)) {
    const index = lines.findIndex(x => x.trim() && !x.trim().startsWith('#'));
    if (index >= 0) add(runtimeIssue(base === '.php-version' ? 'php' : 'node', lines[index].trim(), index + 1));
  }
  if (base === '.tool-versions') {
    lines.forEach((text, i) => {
      const match = text.match(/^\s*(nodejs|php)\s+([^#]+?)(?:\s*#.*)?$/);
      if (match) add(runtimeIssue(match[1] === 'nodejs' ? 'node' : 'php', match[2].trim(), i + 1));
    });
  }
  if (['package.json', 'composer.json'].includes(base)) {
    for (const item of jsonScalars(content)) {
      const matches = (...keys) => keys.length === item.keys.length && keys.every((key, index) => item.keys[index] === key);
      let issue;
      if (base === 'package.json' && (matches('engines', 'node') || matches('volta', 'node'))) {
        issue = runtimeIssue('node', item.value, item.line, matches('engines', 'node') ? 'constraint' : 'pin');
      }
      if (base === 'composer.json' && (matches('require', 'php') || matches('require-dev', 'php') || matches('config', 'platform', 'php'))) {
        issue = runtimeIssue('php', item.value, item.line, 'constraint');
      }
      if (issue) { issue.relatedLines = [item.keyLine]; add(issue); }
    }
  }
  if (/^(?:Dockerfile(?:\..*)?|.*\.Dockerfile|Containerfile(?:\..*)?)$/i.test(base)) {
    lines.forEach((text, i) => {
      const match = text.match(/^\s*FROM\s+(?:--platform=\S+\s+)?([^\s]+)(?:\s|$)/i);
      if (match) issues.push(...imageIssues(match[1], i + 1));
    });
  }
  if (/^(?:docker-)?compose(?:[.-].*)?\.ya?ml$/i.test(base)) {
    lines.forEach((text, i) => {
      const match = text.match(/^\s*image\s*:\s*["']?([^\s"'#]+)["']?\s*(?:#.*)?$/);
      if (match) issues.push(...imageIssues(match[1], i + 1));
    });
  }
  if (/^requirements(?:[-_.].*)?\.(?:txt|in)$/i.test(base) || /(?:^|\/)requirements\/[^/]+\.(?:txt|in)$/i.test(normalized)) {
    lines.forEach((text, i) => {
      // Literal requirement only; do not interpret VCS URLs, comments, or install commands.
      const match = text.match(/^\s*litellm(?:\[[\w, -]+\])?(?=\s|[<>=!~;#@]|$)\s*(.*)$/i);
      if (!match) return;
      const requirement = match[1].split(/[;#]/)[0].trim();
      const pin = requirement.match(/^==\s*(\d+\.\d+\.\d+)(?=\s|$)/);
      const issue = pin?.[1] === ADVISORY_SNAPSHOT.litellm.version ? litellmIssue(i + 1, true, 'requirement')
        : !pin ? litellmIssue(i + 1, false, 'requirement') : null;
      if (issue) { issue.evidence.declarationHash = evidenceHash(text.trim()); add(issue); }
    });
  }
  if (/^(?:php(?:[.-].*)?\.ini|.*\.ini)$/i.test(base)) {
    const active = lines.map(text => text.replace(/\s*;.*$/, ''));
    const handler = active.findLastIndex(text => /^\s*session\.serialize_handler\s*=/i.test(text));
    const conditionalHandler = handler >= 0 && /^\s*session\.serialize_handler\s*=\s*["']?(?:php_binary|php_serialize)["']?\s*$/i.test(active[handler]);
    const upload = active.findLastIndex(text => /^\s*session\.upload_progress\.enabled\s*=/i.test(text));
    const disabled = upload >= 0 && /^\s*session\.upload_progress\.enabled\s*=\s*["']?(?:0|off|false|no)["']?\s*$/i.test(active[upload]);
    if (conditionalHandler && !disabled) add({
      id: 'php-session-upload-progress-review', severity: 'medium', category: 'runtime-security', cwe: 'CWE-1104',
      line: handler + 1, relatedLines: upload >= 0 ? [upload + 1] : [],
      message: 'PHP session configuration needs review for the October 23 follow-up; a runtime switch to the php serializer before session_start is an additional prerequisite not established here.',
      remediation: `Review CVE-2026-115560 with the application owner. PHP recommends session.upload_progress.enabled=0 until the next regular bugfix release for relevant configurations. Validate upload behavior before changing it. Source: ${ADVISORY_SNAPSHOT.php.source}`,
      evidence: { snapshot: ADVISORY_SNAPSHOT.id, source: ADVISORY_SNAPSHOT.php.source, cves: ['CVE-2026-115560'], deploymentVerified: false }
    });
  }
  return issues;
}
