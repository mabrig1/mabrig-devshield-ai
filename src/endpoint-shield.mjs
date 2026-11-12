// Developer endpoint threat guard: offline, bounded, read-only, heuristic.
// Never execute untrusted source, archives, build tools, package hooks, or scripts.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { detectRepositoryThreats } from './repository-preflight.mjs';
import { rules } from './rules.mjs';

const IGNORED = new Set(['.git', 'node_modules', '.venv', 'venv', 'vendor', '.next', '.nuxt', 'coverage']);
const TEXT = /\.(?:js|jsx|mjs|cjs|ts|tsx|json|ya?ml|sh|ps1|psm1|psd1|py|go|cmd|bat|suo|csproj|vbproj|fsproj|targets|props|xml|tf|env|txt|md)$/i;
const ARCHIVE = /\.(?:zip|jar|vsix|nupkg|whl)$/i;
const EXECUTABLE = /\.(?:exe|dll|msi|dmg|appimage|bin)$/i;
const MAX_FILES = 2000;
const MAX_SINGLE = 2 * 1024 * 1024;
const MAX_TOTAL = 48 * 1024 * 1024;
const MAX_DEPTH = 32;
const SEVERITY = { low: 1, medium: 2, high: 3, critical: 4 };

function lineAt(text, pos) {
  return text.slice(0, pos).split('\n').length;
}
function finding(rule, severity, rel, line, message, remediation, category = 'supply-chain') {
  return { rule, severity, category, file: rel, line, message, remediation,
    evidence: 'static-indicator-not-proof-of-malware',
    fingerprint: crypto.createHash('sha256').update([rule, rel, line].join('\0')).digest('hex').slice(0, 24) };
}
export function inspectLifecycleScripts(raw, rel) {
  let pkg;
  try { pkg = JSON.parse(raw); } catch { return []; }
  if (!pkg || typeof pkg !== 'object' || Array.isArray(pkg) ||
      !pkg.scripts || typeof pkg.scripts !== 'object') return [];
  const results = [];
  for (const name of ['preinstall', 'install', 'postinstall', 'prepare', 'prepublish', 'prepack']) {
    const command = pkg.scripts[name];
    if (typeof command !== 'string' || command.length > 10000) continue;
    if (/\b(?:curl|wget)\b[^\r\n|]{0,250}\|\s*(?:sudo\s+)?(?:bash|sh)\b/i.test(command) ||
        /\b(?:invoke-webrequest|iwr)\b[^\r\n|]{0,200}\|\s*(?:iex|invoke-expression)\b/i.test(command)) {
      results.push(finding('lifecycle-download-and-execute', 'critical', rel, 1,
        'Package lifecycle hook appears to pipe downloaded content directly to an interpreter.',
        'Do not run package installation; inspect the source and verify the full script provenance.'));
    } else if (/\b(?:powershell|pwsh)(?:\.exe)?\b[^\r\n]{0,200}-(?:enc|encodedcommand)\b/i.test(command) ||
               /\b(?:mshta|certutil)\b[^\r\n]{0,200}(?:https?:\/\/|-urlcache)\b/i.test(command)) {
      results.push(finding('lifecycle-obfuscated-or-remote-script', 'high', rel, 1,
        'Package lifecycle hook contains an encoded interpreter or remote-execution utility.',
        'Disable the hook until its code, network targets and publisher can be independently verified.'));
    }
  }
  return results;
}
// Read only ZIP central-directory metadata. Never extract archives or inspect contents.
export function inspectZipDirectory(bytes, rel) {
  const findings = [];
  if (bytes.length < 22) throw new Error('Archive shorter than EOCD');
  let eocd = -1;
  for (let pos = bytes.length - 22; pos >= Math.max(0, bytes.length - 65557); pos--) {
    if (bytes.readUInt32LE(pos) === 0x06054b50 &&
        pos + 22 + bytes.readUInt16LE(pos + 20) === bytes.length) { eocd = pos; break; }
  }
  if (eocd < 0) throw new Error('ZIP directory not found');
  const count = bytes.readUInt16LE(eocd + 10);
  const size = bytes.readUInt32LE(eocd + 12);
  const start = bytes.readUInt32LE(eocd + 16);
  if (count === 0xffff || size === 0xffffffff || start === 0xffffffff || count > 1000 ||
      start > bytes.length || size > bytes.length - start || start + size > eocd) {
    throw new Error('Unsupported or oversized ZIP central directory');
  }
  let position = start;
  let executables = 0;
  for (let i = 0; i < count; i++) {
    if (position + 46 > start + size || bytes.readUInt32LE(position) !== 0x02014b50)
      throw new Error('Invalid ZIP directory entry');
    const compressed = bytes.readUInt32LE(position + 20);
    const expanded = bytes.readUInt32LE(position + 24);
    const nameSize = bytes.readUInt16LE(position + 28);
    const extraSize = bytes.readUInt16LE(position + 30);
    const commentSize = bytes.readUInt16LE(position + 32);
    const next = position + 46 + nameSize + extraSize + commentSize;
    if (next > start + size || nameSize > 512) throw new Error('Invalid ZIP name or length');
    const entry = bytes.subarray(position + 46, position + 46 + nameSize).toString('utf8');
    if (/^[\\/]/.test(entry) || /^[A-Za-z]:/.test(entry) ||
        entry.includes('\\') || entry.split('/').includes('..') || entry.includes('\0')) {
      findings.push(finding('archive-path-traversal', 'high', rel, 1,
        'Archive contains an unsafe extraction path.',
        'Do not extract this archive with tools that fail to validate paths; verify its origin.'));
    }
    if (expanded > 25 * 1024 * 1024 || (expanded > 1024 * 1024 && expanded > compressed * 200)) {
      findings.push(finding('archive-expansion-risk', 'high', rel, 1,
        'Archive declares an unusually large or highly compressed entry.',
        'Avoid unpacking outside an isolated, resource-limited environment.'));
    }
    if (/\.(?:exe|dll|ps1|bat|cmd|sh|msi)$/i.test(entry)) executables++;
    position = next;
    if (findings.length >= 40) break;
  }
  return { entries: count, executableEntries: executables, findings };
}

function safeRead(absolute, limit) {
  const fd = fs.openSync(absolute, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
  try {
    const stat = fs.fstatSync(fd);
    if (!stat.isFile() || stat.size > limit) throw new Error('oversized-or-invalid-file');
    const data = fs.readFileSync(fd);
    if (data.length > limit) throw new Error('file-grew-during-read');
    return data;
  } finally { fs.closeSync(fd); }
}
function inspectText(text, rel) {
  const findings = [];
  if (/\/package\.json$/i.test('/' + rel) || rel === 'package.json') {
    findings.push(...inspectLifecycleScripts(text, rel));
  }
  findings.push(...detectRepositoryThreats(text, rel).map(f =>
    finding(f.id, f.severity, rel, f.line, f.message, f.remediation)));
  for (const rule of rules.filter(r => r.category === 'secrets')) {
    if (rule.file && !rule.file.test(rel)) continue;
    rule.re.lastIndex = 0;
    const m = rule.re.exec(text);
    if (!m) continue;
    findings.push(finding(rule.id, rule.severity, rel, lineAt(text, m.index),
      rule.message, rule.remediation, 'secrets'));
  }
  return findings;
}

export function scanEndpoint(target, limits = {}) {
  const caps = {
    maxFiles: limits.maxFiles ?? MAX_FILES,
    maxFileBytes: limits.maxFileBytes ?? MAX_SINGLE,
    maxTotalBytes: limits.maxTotalBytes ?? MAX_TOTAL,
    maxDepth: limits.maxDepth ?? MAX_DEPTH
  };
  for (const [name, maximum] of Object.entries({
    maxFiles: MAX_FILES, maxFileBytes: MAX_SINGLE,
    maxTotalBytes: MAX_TOTAL, maxDepth: MAX_DEPTH
  })) {
    if (!Number.isSafeInteger(caps[name]) || caps[name] < 1 || caps[name] > maximum)
      throw new Error('Invalid scan limit: ' + name);
  }
  const root = path.resolve(target);
  const rootInfo = fs.lstatSync(root);
  if (rootInfo.isSymbolicLink() || (!rootInfo.isDirectory() && !rootInfo.isFile())) throw new Error('Target must be an ordinary directory or file');
  const report = {
    schemaVersion: 1, engine: 'devshield-endpoint-threat-guard',
    profile: 'developer-artifact-heuristic', mode: 'offline-read-only',
    complete: true, filesInspected: 0, bytesInspected: 0, archivesInspected: 0,
    unsupportedExecutables: 0, archiveExecutableEntries: 0,
    skippedDirectories: [], errors: [], findings: [], hashes: []
  };
  let visits = 0;
  function error(rel, reason) {
    report.complete = false;
    if (report.errors.length < 100) report.errors.push({ file: rel, reason });
  }
  function inspect(file, rel) {
    let st;
    try { st = fs.lstatSync(file); } catch { error(rel, 'unreadable-path'); return; }
    if (st.isSymbolicLink()) { error(rel, 'symlink-not-followed'); return; }
    if (!st.isFile()) { error(rel, 'nonregular-file'); return; }
    if (st.size > caps.maxFileBytes) { error(rel, 'file-exceeds-size-limit'); return; }
    if (st.size + report.bytesInspected > caps.maxTotalBytes) {
      error(rel, 'total-byte-limit-exceeded'); return;
    }
    let bytes;
    try { bytes = safeRead(file, caps.maxFileBytes); } catch { error(rel, 'read-failed-or-unsafe'); return; }
    report.filesInspected++;
    report.bytesInspected += bytes.length;
    if (report.hashes.length < 300) {
      report.hashes.push({ file: rel, sha256: crypto.createHash('sha256').update(bytes).digest('hex') });
    }
    if (ARCHIVE.test(rel)) {
      try {
        const archive = inspectZipDirectory(bytes, rel);
        report.archivesInspected++;
        report.archiveExecutableEntries += archive.executableEntries;
        report.findings.push(...archive.findings);
      } catch { error(rel, 'archive-metadata-unreadable-or-unsupported'); }
    } else if (EXECUTABLE.test(rel)) {
      report.unsupportedExecutables++;
      error(rel, 'binary-executable-not-analyzed');
    } else if (TEXT.test(rel)) {
      if (bytes.includes(0) && !/\.suo$/i.test(rel)) { error(rel, 'binary-text-input'); return; }
      const text = /\.suo$/i.test(rel)
        ? bytes.toString('latin1') + '\n' + bytes.toString('utf16le')
        : bytes.toString('utf8');
      report.findings.push(...inspectText(text, rel));
    }
  }
  function walk(dir, depth) {
    if (depth > caps.maxDepth) { error(path.relative(root, dir), 'max-depth-reached'); return; }
    let handle;
    try { handle = fs.opendirSync(dir); }
    catch { error(path.relative(root, dir), 'directory-unreadable'); return; }
    try {
      for (let entry = handle.readSync(); entry !== null; entry = handle.readSync()) {
        const file = path.join(dir, entry.name);
        const rel = path.relative(root, file).replace(/\\/g, '/');
        if (++visits > caps.maxFiles) { error(rel, 'max-file-count-reached'); break; }
        if (entry.isSymbolicLink()) { error(rel, 'symlink-not-followed'); continue; }
        if (entry.isDirectory()) {
          if (IGNORED.has(entry.name)) { report.skippedDirectories.push(rel); continue; }
          walk(file, depth + 1);
        } else inspect(file, rel);
      }
    } catch { error(path.relative(root, dir), 'directory-traversal-failed'); }
    finally { handle.closeSync(); }
  }
  if (rootInfo.isFile()) inspect(root, path.basename(root));
  else walk(root, 0);
  const dedupe = new Map();
  for (const item of report.findings) if (!dedupe.has(item.fingerprint)) dedupe.set(item.fingerprint, item);
  report.findings = [...dedupe.values()].sort((a, b) =>
    a.file.localeCompare(b.file) || a.line - b.line || a.rule.localeCompare(b.rule)).slice(0, 500);
  if (dedupe.size > 500) error('', 'finding-report-limit-reached');
  report.summary = {
    totalFindings: report.findings.length,
    highestSeverity: report.findings.reduce((best, f) =>
      (SEVERITY[f.severity] || 0) > (SEVERITY[best] || 0) ? f.severity : best, 'none'),
    status: report.complete ? (report.findings.length ? 'suspicious' : 'no-indicators-observed') : 'incomplete',
    zeroFindingsProveSafe: false,
    usesVirusSignatures: false, realTimeBlocking: false, quarantinesFiles: false
  };
  return report;
}
export function endpointSarif(report) {
  return { version: '2.1.0', runs: [{ tool: { driver: { name: 'MABRIG DevShield Endpoint Threat Guard',
    rules: [...new Set(report.findings.map(f => f.rule))].map(id => ({ id })) } },
    results: report.findings.map(f => ({
      ruleId: f.rule, level: SEVERITY[f.severity] >= 3 ? 'error' : 'warning',
      message: { text: f.message },
      locations: [{ physicalLocation: { artifactLocation: { uri: f.file },
        region: { startLine: f.line } } }],
      fingerprints: { devshield: f.fingerprint }
    })) }] };
}
