#!/usr/bin/env node
import process from 'node:process';

const args = process.argv.slice(2);
if (args.includes('--inventory')) {
  process.argv = [...process.argv.slice(0, 2), ...args.filter(arg => arg !== '--inventory')];
  await import('./inventory.mjs');
  process.exit(process.exitCode || 0);
}
const options = new Map();
const flags = new Set();

for (let i = 0; i < args.length; i++) {
  const arg = args[i];
  if (arg === '--help' || arg === '-h') flags.add('help');
  else if (arg === '--no-sarif') flags.add('no-sarif');
  else if (arg === '--strict') options.set('policy', 'strict');
  else if (arg === '--repository') options.set('scope', 'repository');
  else if (arg === '--changed-files') options.set('scope', 'changed-files');
  else if (arg === '--staged') options.set('scope', 'staged');
  else if (arg.startsWith('--') && i + 1 < args.length) {
    options.set(arg.slice(2), args[++i]);
  } else {
    console.error(`Unknown argument: ${arg}`);
    process.exit(2);
  }
}

if (flags.has('help')) {
  console.log(`MABRIG DevShield AI local scanner

Usage:
  node bin/devshield.mjs [options]
  npm run scan -- [options]

Default behavior scans staged Git changes and blocks at high severity.

Options:
  --staged                 Scan staged changes (default)
  --inventory              Offline npm lockfile evidence (use --inventory --help)
  --changed-files          Scan all lines in changed files
  --repository             Scan tracked repository files
  --scope <scope>          staged|changed-lines|changed-files|repository
  --fail-on <severity>     critical|high|medium|low|none (default: high)
  --policy <policy>        balanced|strict|secrets-only
  --strict                 Shortcut for --policy strict
  --config <path>          Policy file (default: .devshield.json)
  --exclude <globs>        Comma-separated path globs
  --baseline <path>        Baseline file
  --baseline-mode <mode>   new-only|report|off
  --dependency-agentic <mode> off|auto|on (auto disables working-tree correlation for local staged scans)
  --security-graph <mode>   off|auto|on (auto disables working-tree graphing for local staged scans)
  --control-plane <mode>    off|auto|on
  --security-graph-baseline-file <path> committed graph baseline for diffing
  --security-history <mode> off|auto|on
  --security-history-file <path> committed security history JSON
  --security-history-max-entries <n> retain 1..200 entries
  --report-dir <path>      Report directory (default: .devshield)
  Signing key: set DEVSHIELD_SECURITY_HISTORY_SIGNING_KEY in the environment; do not pass secrets on the command line.
  --no-sarif               Disable SARIF output
  -h, --help               Show this help

Examples:
  npm run scan
  npm run scan -- --strict --fail-on medium
  npm run scan -- --repository --fail-on high
`);
  process.exit(0);
}

const scope = options.get('scope') || 'staged';
const failOn = options.get('fail-on') || 'high';
const policy = options.get('policy') || '';
const config = options.get('config') || '.devshield.json';
const exclude = options.get('exclude') || '';
const baseline = options.get('baseline') || '';
const baselineMode = options.get('baseline-mode') || '';
const dependencyAgentic = options.get('dependency-agentic') || '';
const securityGraph = options.get('security-graph') || '';
const controlPlane = options.get('control-plane') || '';
const securityGraphBaselineFile = options.get('security-graph-baseline-file') || '';
const securityHistory = options.get('security-history') || '';
const securityHistoryFile = options.get('security-history-file') || '';
const securityHistoryMaxEntries = options.get('security-history-max-entries') || '';
const reportDir = options.get('report-dir') || '.devshield';

process.env.GITHUB_WORKSPACE = process.cwd();
process.env.INPUT_SCAN_SCOPE = scope;
process.env.INPUT_FAIL_ON = failOn;
process.env.INPUT_COMMENT = 'false';
process.env.INPUT_DEPENDENCY_REVIEW = 'false';
process.env.INPUT_CONFIG_FILE = config;
process.env.INPUT_REPORT_DIR = reportDir;
process.env.INPUT_SARIF = flags.has('no-sarif') ? 'false' : 'true';

if (policy) process.env.INPUT_POLICY = policy;
if (exclude) process.env.INPUT_EXCLUDE_PATHS = exclude;
if (baseline) process.env.INPUT_BASELINE_FILE = baseline;
if (baselineMode) process.env.INPUT_BASELINE_MODE = baselineMode;
if (dependencyAgentic) process.env.INPUT_DEPENDENCY_AGENTIC = dependencyAgentic;
if (securityGraph) process.env.INPUT_SECURITY_GRAPH = securityGraph;
if (controlPlane) process.env.INPUT_CONTROL_PLANE = controlPlane;
if (securityGraphBaselineFile) process.env.INPUT_SECURITY_GRAPH_BASELINE_FILE = securityGraphBaselineFile;
if (securityHistory) process.env.INPUT_SECURITY_HISTORY = securityHistory;
if (securityHistoryFile) process.env.INPUT_SECURITY_HISTORY_FILE = securityHistoryFile;
if (securityHistoryMaxEntries) process.env.INPUT_SECURITY_HISTORY_MAX_ENTRIES = securityHistoryMaxEntries;

await import('../src/index.mjs');
