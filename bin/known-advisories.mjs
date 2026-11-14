#!/usr/bin/env node
// Offline, read-only npm dependency advisory evidence. No registry queries or package execution.
import fs from 'node:fs';
import path from 'node:path';
import { createDependencyInventory } from '../src/dependency-inventory.mjs';
import { scanKnownNpmAdvisories, knownAdvisoriesSarif, knownAdvisoriesBlock } from '../src/known-npm-advisories.mjs';

const USAGE = [
  'Usage: node bin/known-advisories.mjs [--lockfile package-lock.json] [--report-dir .devshield] [--mode advisory|enforce] [--fail-on critical|high|medium|low|none]',
  'Offline matching against a curated November 2026 npm advisory snapshot. Not a live audit.',
  'Checks installed versions in npm v2/v3 lockfiles; never runs source, installs packages, or accesses the network.',
  'advisory: never gates findings; enforce: fail on matching severity or incomplete coverage.',
  'Exit: 0=advisory or no matches, 1=threshold matched, 2=incomplete/invalid.'
].join('\n');

function repoPath(relative) {
  if (!relative || typeof relative !== 'string' || path.isAbsolute(relative) ||
      relative.includes('\\') || relative.length > 500 ||
      /[\x00-\x1f\x7f]/.test(relative) ||
      relative.split('/').some(p => !p || p === '.' || p === '..')) {
    throw new Error('Use a safe repository-relative path.');
  }
  let current = process.cwd();
  for (const component of relative.split('/')) {
    current = path.join(current, component);
    try {
      if (fs.lstatSync(current).isSymbolicLink()) throw new Error('Symlinks are not supported.');
    } catch (err) { if (err.code !== 'ENOENT') throw err; }
  }
  return current;
}
function readLock(file) {
  const fd = fs.openSync(file, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
  try {
    const st = fs.fstatSync(fd);
    if (!st.isFile() || st.size > 20 * 1024 * 1024) throw new Error('Expected a regular lockfile of at most 20 MiB');
    const bytes = fs.readFileSync(fd);
    if (bytes.length > 20 * 1024 * 1024 || bytes.includes(0)) throw new Error('Lockfile too large or binary');
    return bytes.toString('utf8');
  } finally { fs.closeSync(fd); }
}
function save(file, content) {
  try {
    const st = fs.lstatSync(file);
    if (!st.isFile() || st.isSymbolicLink() || st.nlink !== 1) throw new Error('Unsafe report destination');
  } catch (err) { if (err.code !== 'ENOENT') throw err; }
  fs.writeFileSync(file, content, {
    flag: fs.constants.O_CREAT | fs.constants.O_TRUNC | fs.constants.O_WRONLY | (fs.constants.O_NOFOLLOW || 0),
    mode: 0o600
  });
}
function setOutput(key, value) {
  const file = process.env.GITHUB_OUTPUT;
  if (file) fs.appendFileSync(file, key + '=' + String(value).replace(/[\r\n]/g, ' ') + '\n');
}
const args = process.argv.slice(2);
if (args.includes('--help') || args.includes('-h')) {
  console.log(USAGE);
  process.exit(0);
}
try {
  const opts = { 'mode': 'advisory', 'report-dir': '.devshield', 'fail-on': 'critical' };
  for (let i = 0; i < args.length; i += 2) {
    const arg = args[i];
    if (!['--lockfile', '--report-dir', '--mode', '--fail-on'].includes(arg) ||
        !args[i + 1] || args[i + 1].startsWith('--')) throw new Error('Invalid option or missing value');
    opts[arg.slice(2)] = args[i + 1];
  }
  if (!['advisory', 'enforce'].includes(opts.mode) ||
      !['critical', 'high', 'medium', 'low', 'none'].includes(opts['fail-on'])) {
    throw new Error('Invalid mode or fail-on');
  }
  const relative = opts.lockfile || (fs.existsSync('npm-shrinkwrap.json') ? 'npm-shrinkwrap.json' : 'package-lock.json');
  const file = repoPath(relative);
  const dir = repoPath(opts['report-dir']);
  const jsonFile = repoPath(opts['report-dir'] + '/known-advisories.json');
  const sarifFile = repoPath(opts['report-dir'] + '/known-advisories.sarif');
  if (file === jsonFile || file === sarifFile) throw new Error('Report output would overwrite source lockfile');
  let report;
  if (!fs.existsSync(file)) {
    report = {
      schemaVersion: 1, status: 'not-present', mode: 'offline-curated-snapshot',
      note: 'No npm v2/v3 lockfile found. No installed package versions were evaluated.',
      summary: { advisoryMatches: 0, affectedInstallations: 0, totalInstallations: 0 },
      findings: []
    };
  } else {
    const inventory = createDependencyInventory(readLock(file), { sourceFile: relative });
    report = scanKnownNpmAdvisories(inventory);
  }
  fs.mkdirSync(dir, { recursive: true });
  save(jsonFile, JSON.stringify(report, null, 2) + '\n');
  save(sarifFile, JSON.stringify(knownAdvisoriesSarif(report), null, 2) + '\n');
  setOutput('known-advisories-state', report.status);
  setOutput('known-advisories-findings', report.summary.advisoryMatches || 0);
  setOutput('known-advisories-report-file', path.relative(process.cwd(), jsonFile).replace(/\\/g, '/'));
  setOutput('known-advisories-sarif-file', path.relative(process.cwd(), sarifFile).replace(/\\/g, '/'));
  console.log('DevShield known advisories: ' + report.status + '; version matches: ' +
    (report.summary.advisoryMatches || 0) + '; mode: ' + opts.mode + '.');
  if (opts.mode === 'enforce') {
    if (report.status !== 'reviewed') process.exitCode = 2;
    else if (knownAdvisoriesBlock(report, opts['fail-on'])) process.exitCode = 1;
  }
} catch (error) {
  // Never print raw lockfile content, package URLs, credentials or parser stack traces.
  console.error('DevShield known advisory check incomplete or invalid: ' +
    (error.code ? 'could not safely access the input or report path' : error.message));
  process.exitCode = 2;
}
