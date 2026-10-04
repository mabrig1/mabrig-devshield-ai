#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import {
  apiAgentTrustMarkdown,
  apiAgentTrustSarif,
  scanApiAgentTrust,
  shouldFailApiAgentTrust
} from '../src/api-agent-trust.mjs';

const args = process.argv.slice(2);
const options = new Map();
const flags = new Set();

for (let i = 0; i < args.length; i++) {
  const arg = args[i];
  if (arg === '--help' || arg === '-h') flags.add('help');
  else if (arg === '--enforce') options.set('mode', 'enforce');
  else if (arg.startsWith('--') && i + 1 < args.length) options.set(arg.slice(2), args[++i]);
  else if (arg === '--repository') continue;
  else {
    console.error('Unknown argument: ' + arg);
    process.exit(2);
  }
}

if (flags.has('help')) {
  console.log([
    'MABRIG DevShield API & Agent Trust Shield',
    '',
    'Usage:',
    '  node bin/api-trust.mjs [options]',
    '  npm run api-trust -- [options]',
    '',
    'Options:',
    '  --mode <mode>          off|advisory|enforce (default: advisory)',
    '  --enforce              Shortcut for --mode enforce',
    '  --fail-on <severity>   critical|high|medium|low|none (default: high)',
    '  --report-dir <path>    Report directory (default: .devshield)',
    '  --max-files <n>        Maximum candidate source files (default: 800)',
    '  --max-file-bytes <n>   Maximum bytes per source file (default: 1500000)',
    '  -h, --help             Show help',
    '',
    'The shield performs static heuristic checks only and never executes target application code.'
  ].join('\n'));
  process.exit(0);
}

function normalizeMode(value) {
  const mode = String(value || 'advisory').toLowerCase();
  return ['off','advisory','enforce'].includes(mode) ? mode : 'advisory';
}

function normalizeSeverity(value) {
  const severity = String(value || 'high').toLowerCase();
  return ['critical','high','medium','low','none'].includes(severity) ? severity : 'high';
}

function clampInt(value, min, max, fallback) {
  const n = Number.parseInt(value, 10);
  return Number.isFinite(n) ? Math.max(min, Math.min(max, n)) : fallback;
}

function writeOutput(key, value) {
  const file = process.env.GITHUB_OUTPUT;
  if (!file) return;
  fs.appendFileSync(file, key + '=' + String(value).replace(/\r?\n/g, ' ') + '\n');
}

function appendSummary(markdown) {
  const file = process.env.GITHUB_STEP_SUMMARY;
  if (!file) return;
  fs.appendFileSync(file, '\n' + markdown + '\n');
}

const workspace = process.env.GITHUB_WORKSPACE || process.cwd();
const mode = normalizeMode(options.get('mode') || process.env.INPUT_API_TRUST || 'advisory');
const failOn = normalizeSeverity(options.get('fail-on') || process.env.INPUT_API_TRUST_FAIL_ON || 'high');
const reportDirRel = options.get('report-dir') || process.env.INPUT_REPORT_DIR || '.devshield';
const maxFiles = clampInt(options.get('max-files') || process.env.INPUT_MAX_FILES || '800', 1, 5000, 800);
const maxFileBytes = clampInt(options.get('max-file-bytes') || process.env.INPUT_MAX_FILE_BYTES || '1500000', 10000, 5000000, 1500000);

if (path.isAbsolute(reportDirRel) || path.normalize(reportDirRel).startsWith('..')) {
  console.error('Report directory must be repository-relative.');
  process.exit(2);
}

if (mode === 'off') {
  writeOutput('api-trust-state', 'disabled');
  writeOutput('api-trust-findings', 0);
  writeOutput('api-trust-critical', 0);
  writeOutput('api-trust-high', 0);
  writeOutput('api-trust-report-file', '');
  writeOutput('api-trust-sarif-file', '');
  console.log('DevShield API & Agent Trust Shield disabled.');
  process.exit(0);
}

const report = scanApiAgentTrust({ workspace, maxFiles, maxFileBytes });
const reportDir = path.join(workspace, reportDirRel);
fs.mkdirSync(reportDir, { recursive: true });

const jsonRel = path.posix.join(reportDirRel.replace(/\\/g, '/'), 'devshield-api-agent-trust.json');
const markdownRel = path.posix.join(reportDirRel.replace(/\\/g, '/'), 'devshield-api-agent-trust.md');
const sarifRel = path.posix.join(reportDirRel.replace(/\\/g, '/'), 'devshield-api-agent-trust.sarif');

fs.writeFileSync(path.join(workspace, jsonRel), JSON.stringify({ ...report, mode, failOn }, null, 2) + '\n');
fs.writeFileSync(path.join(workspace, markdownRel), apiAgentTrustMarkdown(report, mode) + '\n');
fs.writeFileSync(path.join(workspace, sarifRel), JSON.stringify(apiAgentTrustSarif(report), null, 2) + '\n');

const failed = mode === 'enforce' && shouldFailApiAgentTrust(report, failOn);
const state = failed ? 'blocked' : report.findings.length ? 'findings' : 'clean';

writeOutput('api-trust-state', state);
writeOutput('api-trust-findings', report.findings.length);
writeOutput('api-trust-critical', report.counts.critical);
writeOutput('api-trust-high', report.counts.high);
writeOutput('api-trust-report-file', jsonRel);
writeOutput('api-trust-sarif-file', sarifRel);

appendSummary(apiAgentTrustMarkdown(report, mode));

console.log('DevShield API & Agent Trust Shield: ' + state);
console.log('Scanned files: ' + report.scannedFiles);
console.log('Findings: ' + report.findings.length + ' (critical ' + report.counts.critical + ', high ' + report.counts.high + ')');
console.log('Report: ' + jsonRel);
console.log('SARIF: ' + sarifRel);

if (failed) {
  console.error('API & Agent Trust Shield blocked because findings met the ' + failOn + ' threshold.');
  process.exitCode = 1;
}
