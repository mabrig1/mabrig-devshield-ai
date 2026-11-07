// Offline, read-only repository preflight. Never import or execute target code.
import fs from 'node:fs';
import path from 'node:path';

const IGNORED_DIRS = new Set(['.git', 'node_modules', '.next', '.nuxt', 'dist', 'build', 'coverage', 'vendor', '.venv', 'venv']);
const TARGET_FILES = /(?:^|\/)(?:Dockerfile(?:\..*)?|Makefile|\.github\/workflows\/[^/]+\.ya?ml)$/i;
const TARGET_EXT = /\.(?:csproj|vbproj|fsproj|targets|props|suo|ps1|psm1|psd1|bat|cmd|py|go|js|mjs|cjs|jsx|ts|tsx|json|ya?ml|sh)$/i;
const MSBUILD = /\.(?:csproj|vbproj|fsproj|targets|props)$/i;
const SOURCE = /\.(?:csproj|vbproj|fsproj|targets|props|suo|ps1|psm1|psd1|bat|cmd|py|go|js|mjs|cjs|jsx|ts|tsx|json|ya?ml|sh)$/i;
const IOC = /\b(?:muckanthropic(?:\.|\[\.\])com|muckcoding(?:\.|\[\.\])com|muckdeveloper(?:\.|\[\.\])com|muckduck(?:\.|\[\.\])duckdns(?:\.|\[\.\])org|130(?:\.|\[\.\])12(?:\.|\[\.\])182(?:\.|\[\.\])172)\b/i;
const severityValue = { none: 99, low: 1, medium: 2, high: 3, critical: 4 };
const LIMITS = { maxFiles: 2000, maxFileBytes: 1_500_000, maxDepth: 40 };

function lineAt(source, offset) {
  return 1 + (source.slice(0, offset).match(/\n/g) || []).length;
}

function addMatch(findings, source, rel, re, rule, severity, message, remediation) {
  const match = re.exec(source);
  if (!match) return;
  findings.push({
    id: rule, severity, path: rel, line: lineAt(source, match.index),
    message, remediation
  });
}

export function detectRepositoryThreats(source, rel) {
  const findings = [];
  const file = rel.replace(/\\/g, '/');
  if (!SOURCE.test(file)) return findings;

  // Exact indicators are only leads. They are not an attribution or proof of execution.
  addMatch(findings, source, file, IOC, 'drweb-2026-campaign-ioc', 'critical',
    'Source references a network indicator reported in the November 2026 Dr.Web GitHub campaign.',
    'Investigate this reference and verify against the published intelligence; do not execute the project.');

  if (MSBUILD.test(file)) {
    const events = /<(?:PreBuildEvent|PostBuildEvent)\b[^>]*>([\s\S]{0,2000}?)<\/(?:PreBuildEvent|PostBuildEvent)>/gi;
    for (const event of source.matchAll(events)) {
      if (/\b(?:powershell|pwsh|mshta|certutil|curl|wget|invoke-webrequest|downloadstring|iex)\b/i.test(event[1])) {
        findings.push({
          id: 'msbuild-event-script-execution', severity: 'critical', path: file,
          line: lineAt(source, event.index),
          message: 'MSBuild build event invokes a script interpreter or downloader before/during compilation.',
          remediation: 'Remove the build event until its exact commands and origins have been independently verified.'
        });
      }
    }
    addMatch(findings, source, file,
      /<Exec\b[^>]{0,1500}\bCommand\s*=\s*["'][^"']{0,1000}\b(?:powershell|pwsh|mshta|certutil)\b/i,
      'msbuild-exec-interpreter', 'critical',
      'MSBuild Exec task invokes a Windows script interpreter or download utility.',
      'Review the complete MSBuild task and eliminate untrusted command execution.');
  }

  if (/\.suo$/i.test(file)) {
    addMatch(findings, source, file, /\b(?:powershell|pwsh)(?:\.exe)?\b/i,
      'visual-studio-suo-powershell', 'high',
      'Visual Studio user-options data contains a PowerShell reference.',
      'Treat this binary-file string as an investigative clue; inspect the file with trusted forensic tooling.');
  }

  addMatch(findings, source, file,
    /\b(?:powershell|pwsh)(?:\.exe)?\b[^\r\n]{0,220}-(?:encodedcommand|enc)\b/i,
    'powershell-encoded-command', 'high',
    'PowerShell is invoked with an encoded command.',
    'Decode and review the command offline in an isolated analysis environment; do not execute it.');

  addMatch(findings, source, file,
    /(?:\biex\s*\([^\r\n]{0,140}(?:iwr|invoke-webrequest|downloadstring)\b|\b(?:iwr|invoke-webrequest|downloadstring)\b[^\r\n]{0,140}\|\s*(?:iex|invoke-expression)\b)/i,
    'powershell-download-and-execute', 'critical',
    'Code appears to download remote content for immediate PowerShell execution.',
    'Remove download-to-execute behavior and require pinned, independently verified artifacts.');

  if (/\.py$/i.test(file)) {
    addMatch(findings, source, file,
      /^(?: {120,}|\t{8,})[ \t]*(?:exec|eval|subprocess\.|os\.system|urllib\.request|requests\.get)\b/gm,
      'python-whitespace-concealed-execution', 'high',
      'An execution or network operation appears after unusually long leading whitespace.',
      'Inspect the entire line in a whitespace-visible editor; review the code without running it.');
    addMatch(findings, source, file,
      /\bexec\s*\(\s*(?:compile\s*\(\s*)?(?:base64\.b64decode|zlib\.decompress)\s*\(/,
      'python-decoded-payload-execution', 'critical',
      'Python directly executes a decoded or decompressed payload.',
      'Decode into inert data in a sandbox for review; never execute untrusted decoded source.');
  }

  if (/\.go$/i.test(file)) {
    addMatch(findings, source, file,
      /^(?: {120,}|\t{8,})[ \t]*(?:exec\.Command|http\.Get|base64\.StdEncoding)\b/gm,
      'go-whitespace-concealed-operation', 'high',
      'An execution or network operation appears after unusually long leading whitespace.',
      'Examine the full source line, imports, and control flow before building.');
    addMatch(findings, source, file,
      /\bexec\.Command(?:Context)?\s*\(\s*["'](?:powershell|pwsh)(?:\.exe)?["']/i,
      'go-powershell-execution', 'high',
      'Go source launches PowerShell using os/exec.',
      'Inspect command arguments and provenance and remove untrusted execution.');
  }
  return findings;
}

function decodeFile(buffer, rel) {
  if (/\.suo$/i.test(rel)) {
    // .suo is an OLE compound binary; these two string views are heuristic only.
    return buffer.toString('latin1') + '\n' + buffer.toString('utf16le');
  }
  if (buffer[0] === 0xff && buffer[1] === 0xfe) return buffer.subarray(2).toString('utf16le');
  if (buffer.includes(0)) throw new Error('Binary/NUL data in expected source file');
  return buffer.toString('utf8');
}

export function scanRepository(root, limits = {}) {
  for (const [key, fallback] of Object.entries(LIMITS)) {
    const value = limits[key] ?? fallback;
    if (!Number.isSafeInteger(value) || value < 1 || value > fallback * 20) {
      throw new Error(`Invalid ${key}; use an integer from 1 to ${fallback * 20}`);
    }
  }
  const caps = { ...LIMITS, ...limits };
  const base = path.resolve(root);
  const stat = fs.lstatSync(base);
  if (!stat.isDirectory() || stat.isSymbolicLink()) throw new Error('Input must be a real directory, not a symlink');
  const report = {
    schema: 'devshield.repository-preflight.v1',
    mode: 'offline-static-only', root: base,
    complete: true, filesScanned: 0, filesSkippedByType: 0,
    skippedDirectories: [...IGNORED_DIRS], findings: [], errors: []
  };
  let visited = 0;
  function problem(rel, message) {
    report.complete = false;
    report.errors.push({ path: rel, message });
  }
  function walk(dir, depth) {
    if (depth > caps.maxDepth) { problem(path.relative(base, dir), 'Maximum depth exceeded'); return; }
    let children;
    try { children = fs.readdirSync(dir, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name)); }
    catch { problem(path.relative(base, dir), 'Directory unreadable'); return; }
    for (const item of children) {
      const absolute = path.join(dir, item.name);
      const relative = path.relative(base, absolute).replace(/\\/g, '/');
      if (item.isDirectory() && IGNORED_DIRS.has(item.name)) continue;
      if (++visited > caps.maxFiles) { problem(relative, 'Maximum file and directory count exceeded'); return; }
      let info;
      try { info = fs.lstatSync(absolute); } catch { problem(relative, 'Path unreadable'); continue; }
      if (info.isSymbolicLink()) { problem(relative, 'Symlink not followed; target not scanned'); continue; }
      if (info.isDirectory()) { walk(absolute, depth + 1); continue; }
      if (!info.isFile()) { problem(relative, 'Non-regular file not scanned'); continue; }
      if (!TARGET_EXT.test(relative) && !TARGET_FILES.test(relative)) { report.filesSkippedByType++; continue; }
      if (info.size > caps.maxFileBytes) { problem(relative, 'Source file exceeds scan byte limit'); continue; }
      let fd;
      try {
        fd = fs.openSync(absolute, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
        const opened = fs.fstatSync(fd);
        if (!opened.isFile() || opened.size > caps.maxFileBytes) throw new Error('Not an eligible regular file');
        const buffer = fs.readFileSync(fd);
        if (buffer.byteLength > caps.maxFileBytes) throw new Error('Source grew past scan byte limit');
        const content = decodeFile(buffer, relative);
        report.filesScanned++;
        report.findings.push(...detectRepositoryThreats(content, relative));
      } catch { problem(relative, 'Source file unreadable or unsupported encoding'); }
      finally { if (fd !== undefined) fs.closeSync(fd); }
    }
  }
  walk(base, 0);
  report.findings.sort((a, b) => a.path.localeCompare(b.path) || a.line - b.line || a.id.localeCompare(b.id));
  report.status = !report.complete ? 'incomplete' : report.findings.length ? 'suspicious' : 'no-indicators-observed';
  return report;
}

export function shouldBlockPreflight(report, threshold = 'high') {
  if (!(threshold in severityValue)) throw new Error('Unknown fail-on severity');
  return !report.complete || report.findings.some(f => severityValue[f.severity] >= severityValue[threshold]);
}
