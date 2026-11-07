#!/usr/bin/env node
// Repository source is untrusted data: this command never builds, imports or runs it.
import process from 'node:process';
import { scanRepository, shouldBlockPreflight } from '../src/repository-preflight.mjs';

const args = process.argv.slice(2);
const usage = `Usage: devshield-preflight [directory] [--fail-on critical|high|medium|low|none]
Read-only, offline malware preflight. JSON report is printed to stdout.
Exit codes: 0 = completed without threshold findings, 1 = findings at threshold,
2 = scan incomplete, invalid input or invalid arguments.
Example: npm run preflight -- /path/to/untrusted-checkout --fail-on high`;
function die(message) {
  console.error(message);
  console.error(usage);
  process.exit(2);
}
let dir = '.';
let threshold = 'high';
let directorySpecified = false;
for (let i = 0; i < args.length; i++) {
  const arg = args[i];
  if (arg === '--help' || arg === '-h') { console.log(usage); process.exit(0); }
  if (arg === '--fail-on') {
    const next = args[++i];
    if (!['critical', 'high', 'medium', 'low', 'none'].includes(next)) die('Invalid --fail-on value');
    threshold = next;
  } else if (arg.startsWith('-') || directorySpecified) {
    die('Unexpected argument: ' + arg);
  } else {
    dir = arg;
    directorySpecified = true;
  }
}
try {
  const report = scanRepository(dir);
  console.log(JSON.stringify(report, null, 2));
  if (!report.complete) process.exitCode = 2;
  else if (shouldBlockPreflight(report, threshold)) process.exitCode = 1;
} catch (error) {
  // Only error class/message, never source snippets or executable output.
  console.error('Preflight could not complete: ' + error.message);
  process.exitCode = 2;
}
