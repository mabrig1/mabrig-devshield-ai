// Offline local API scan adapter. Untrusted repository source is only read as data.
// No npm install, scripts, build commands, app imports, executable probes, AI or network calls.
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { scanRepository, detectRepositoryThreats } from './repository-preflight.mjs';
import { scanApiAgentTrust, collectCandidateFiles } from './api-agent-trust.mjs';
import { scanLegalCompliance } from './legal-compliance.mjs';
import { createDependencyInventory } from './dependency-inventory.mjs';
import { createRepositorySecurityGraph } from './security-graph.mjs';
import { openApiToWaapPolicy } from './waap-openapi.mjs';

export const MODES = Object.freeze([
  'full', 'staged-diff', 'preflight', 'dependency-inventory', 'api-agent-trust',
  'legal-compliance', 'waap-policy', 'security-graph'
]);
const PRIORITY = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
const MAX_FILES = 600;
const MAX_FINDINGS = 250;

function validRoot(root) {
  const absolute = path.resolve(root);
  const st = fs.lstatSync(absolute);
  if (!st.isDirectory() || st.isSymbolicLink()) throw new Error('Workspace must be a real directory');
  return fs.realpathSync(absolute);
}
function safeFile(root, relative, maxBytes = 1024 * 1024) {
  if (typeof relative !== 'string' || relative.length > 500 || !relative ||
    path.isAbsolute(relative) || relative.includes('\\') ||
    /[\x00-\x1f\x7f]/.test(relative) ||
    relative.split('/').some(p => !p || p === '.' || p === '..')) throw new Error('Unsafe file path');
  let current = root;
  for (const part of relative.split('/')) {
    current = path.join(current, part);
    const st = fs.lstatSync(current);
    if (st.isSymbolicLink()) throw new Error('Symbolic links not scanned');
  }
  const stat = fs.statSync(current);
  if (!stat.isFile() || stat.size > maxBytes) throw new Error('File exceeds limit or is not regular');
  const fd = fs.openSync(current, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
  try {
    const opened = fs.fstatSync(fd);
    if (!opened.isFile() || opened.size > maxBytes) throw new Error('Input changed during read');
    const data = fs.readFileSync(fd);
    if (data.byteLength > maxBytes || data.includes(0)) throw new Error('Binary or oversized input');
    return data.toString('utf8');
  } finally { fs.closeSync(fd); }
}
function mapped(report, category) {
  return (report.findings || []).map(f => ({
    rule: String(f.rule || f.id || 'review').slice(0, 100),
    severity: PRIORITY[f.severity] === undefined ? 'low' : f.severity,
    category, file: String(f.file || f.path || '').slice(0, 500),
    line: Number.isSafeInteger(f.line) && f.line > 0 ? f.line : 1,
    message: String(f.message || f.title || 'Review finding').slice(0, 300),
    remediation: String(f.remediation || f.recommendation || 'Review evidence and context').slice(0, 400),
    confidence: String(f.confidence || 'heuristic').slice(0, 30)
  }));
}
function inventory(root) {
  const rel = fs.existsSync(path.join(root, 'npm-shrinkwrap.json'))
    ? 'npm-shrinkwrap.json' : 'package-lock.json';
  try { return { state: 'ready', report: createDependencyInventory(safeFile(root, rel, 20 * 1024 * 1024), { sourceFile: rel }) }; }
  catch (error) {
    if (error.code === 'ENOENT') return { state: 'not-present', report: null };
    return { state: 'incomplete', reason: 'Unable to read or parse bounded npm lockfile', report: null };
  }
}
function staged(root) {
  let output;
  try {
    output = execFileSync('git', ['-c', 'core.quotePath=false', 'diff', '--cached',
      '--name-only', '-z', '--diff-filter=ACMR', '--no-ext-diff'], {
      cwd: root, encoding: 'buffer', timeout: 10000, maxBuffer: 2 * 1024 * 1024,
      env: { ...process.env, GIT_OPTIONAL_LOCKS: '0', GIT_CONFIG_NOSYSTEM: '1' },
      stdio: ['ignore', 'pipe', 'ignore']
    });
  } catch { throw new Error('Unable to determine staged files; use a trusted Git checkout'); }
  const files = output.toString('utf8').split('\0').filter(Boolean);
  if (files.length > MAX_FILES) throw new Error('Staged file count exceeds scan cap');
  const candidates = [];
  const findings = [];
  const errors = [];
  for (const file of files) {
    try {
      const source = safeFile(root, file, 1_500_000);
      candidates.push(file);
      findings.push(...detectRepositoryThreats(source, file));
    } catch {
      errors.push({ path: file, reason: 'File unavailable, unsafe, binary or oversized' });
    }
  }
  const agent = scanApiAgentTrust({ workspace: root, files: candidates });
  return { findings: [...mapped({ findings }, 'preflight'), ...mapped(agent, 'api-agent-trust')],
    scannedFiles: candidates.length, complete: errors.length === 0, errors };
}
function specToWaap(root, relative) {
  const content = safeFile(root, relative || 'openapi.json', 1024 * 1024);
  const data = JSON.parse(content);
  if (!data || typeof data !== 'object' || !/^3\./.test(String(data.openapi || ''))) throw new Error('Expected OpenAPI 3.x JSON');
  return openApiToWaapPolicy(data, {});
}
export function scanLocal({ workspace, mode = 'preflight', spec = 'openapi.json' } = {}) {
  if (!MODES.includes(mode)) throw new Error('Unsupported scan mode');
  const root = validRoot(workspace || '.');
  const parts = {};
  let findings = [];
  let complete = true;
  let graph = null;
  let waapPolicy = null;
  if (mode === 'preflight' || mode === 'full') {
    const result = scanRepository(root);
    parts.preflight = { status: result.status, filesScanned: result.filesScanned, errors: result.errors };
    findings.push(...mapped(result, 'preflight'));
    complete = complete && result.complete;
  }
  if (mode === 'api-agent-trust' || mode === 'full') {
    const result = scanApiAgentTrust({ workspace: root, maxFiles: MAX_FILES, maxFileBytes: 750000 });
    parts.apiAgentTrust = { status: 'ready', filesScanned: result.scannedFiles };
    findings.push(...mapped(result, 'api-agent-trust'));
  }
  if (mode === 'legal-compliance' || mode === 'full') {
    const result = scanLegalCompliance(root);
    parts.legalCompliance = { status: 'advisory', findings: result.summary.total };
    findings.push(...mapped(result, 'legal-compliance'));
  }
  if (mode === 'dependency-inventory' || mode === 'full') {
    const result = inventory(root);
    parts.dependencyInventory = { status: result.state, summary: result.report?.summary || null };
    if (result.report) findings.push(...mapped(result.report, 'dependency-inventory'));
    if (result.state === 'incomplete') complete = false;
  }
  if (mode === 'staged-diff') {
    const result = staged(root);
    findings = result.findings;
    parts.stagedDiff = { status: result.complete ? 'ready' : 'incomplete',
      filesScanned: result.scannedFiles, errors: result.errors };
    complete = result.complete;
  }
  if (mode === 'security-graph' || mode === 'full') {
    const repositoryFiles = collectCandidateFiles(root, { maxFiles: MAX_FILES, maxFileBytes: 750000 });
    graph = createRepositorySecurityGraph({ workspace: root, repositoryFiles,
      findings: findings.map(f => ({ rule: f.rule, severity: f.severity, file: f.file, line: f.line })) });
    parts.securityGraph = { status: graph.state, summary: graph.summary };
  }
  if (mode === 'waap-policy') {
    waapPolicy = specToWaap(root, spec);
    parts.waapPolicy = { status: 'generated', routeCount: waapPolicy.routes?.length || 0 };
  }
  findings = findings.slice(0, MAX_FINDINGS);
  const highest = findings.reduce((n, f) => Math.max(n, PRIORITY[f.severity] || 0), 0);
  const level = Object.keys(PRIORITY).find(key => PRIORITY[key] === highest) || 'info';
  return { schemaVersion: 1, engine: 'devshield-local-scan-adapter',
    mode, execution: 'offline-read-only', complete, parts,
    summary: { findings: findings.length, highestSeverity: level, capped: findings.length === MAX_FINDINGS },
    findings, ...(graph ? { graph } : {}), ...(waapPolicy ? { waapPolicy } : {}) };
}
export function scanSarif(report) {
  const rules = [...new Set(report.findings.map(f => f.rule))].map(id => ({ id }));
  return { version: '2.1.0', runs: [{ tool: { driver: { name: 'MABRIG DevShield Local Scan', rules } },
    results: report.findings.map(f => ({ ruleId: f.rule, level: (PRIORITY[f.severity] || 0) >= 3 ? 'error' : 'warning',
      message: { text: f.message }, locations: [{ physicalLocation: {
        artifactLocation: { uri: f.file }, region: { startLine: f.line } } }] })) }] };
}
