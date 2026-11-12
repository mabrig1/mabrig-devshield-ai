#!/usr/bin/env node
// On-demand and opt-in polling only: this is not a full antivirus or EDR.
import crypto from 'node:crypto';
import { scanEndpoint, endpointSarif } from '../src/endpoint-shield.mjs';

const usage = [
  'DevShield Endpoint Threat Guard — offline developer malware-preflight',
  'Usage: devshield-endpoint --path <file-or-directory> [--format json|sarif]',
  '       [--fail-on critical|high|medium|low|none] [--watch-seconds 5..300]',
  'Never executes project code, installs software, quarantines files, or connects to a cloud.',
  'Exit: 0=no threshold findings (with complete coverage), 1=findings at threshold, 2=incomplete/invalid.'
].join('\n');
const options = { format: 'json', 'fail-on': 'high' };
if (process.argv.slice(2).includes('--help')) { console.log(usage); process.exit(0); }
const args = process.argv.slice(2);
for (let i = 0; i < args.length; i += 2) {
  if (!['--path', '--format', '--fail-on', '--watch-seconds'].includes(args[i]) || !args[i + 1]) {
    console.error(usage); process.exit(2);
  }
  options[args[i].slice(2)] = args[i + 1];
}
if (!options.path || !['json', 'sarif'].includes(options.format) ||
    !['critical', 'high', 'medium', 'low', 'none'].includes(options['fail-on']) ||
    (options['watch-seconds'] && (!/^[0-9]{1,3}$/.test(options['watch-seconds']) ||
      Number(options['watch-seconds']) < 5 || Number(options['watch-seconds']) > 300))) {
  console.error('Invalid arguments. See --help.'); process.exit(2);
}
const rank = { none: 99, low: 1, medium: 2, high: 3, critical: 4 };
let previous = null;
function execute() {
  try {
    const report = scanEndpoint(options.path);
    const printable = options.format === 'sarif' ? endpointSarif(report) : report;
    const signature = crypto.createHash('sha256').update(JSON.stringify({
      hashes: report.hashes, findings: report.findings, errors: report.errors,
      filesInspected: report.filesInspected, bytesInspected: report.bytesInspected
    })).digest('hex');
    if (!options['watch-seconds'] || signature !== previous) {
      console.log(JSON.stringify(printable, null, options['watch-seconds'] ? 0 : 2));
    }
    previous = signature;
    const blocked = options['fail-on'] !== 'none' &&
      report.findings.some(f => rank[f.severity] >= rank[options['fail-on']]);
    if (!options['watch-seconds']) process.exitCode = report.complete ? blocked ? 1 : 0 : 2;
  } catch {
    console.error('Endpoint scan could not complete. Check target path, permissions and scan limits.');
    if (!options['watch-seconds']) process.exitCode = 2;
  }
}
execute();
if (options['watch-seconds']) {
  const interval = setInterval(execute, Number(options['watch-seconds']) * 1000);
  for (const name of ['SIGINT', 'SIGTERM']) {
    process.on(name, () => { clearInterval(interval); process.exitCode = 0; });
  }
}
