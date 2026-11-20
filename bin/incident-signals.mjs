#!/usr/bin/env node
// Operator-supplied telemetry only: never requests a token, remote URL, or application source.
import { readFileSync, lstatSync, writeFileSync } from 'node:fs';
import { analyzeIncidentSignals } from '../src/incident-signals.mjs';

const usage = 'Usage: node bin/incident-signals.mjs --input local-aggregate.json [--output private-report.json]';
function parseArgs(args) {
  if (args.length === 1 && args[0] === '--help') return { help: true };
  const out = {};
  for (let i = 0; i < args.length; i += 2) {
    const key = args[i];
    if (!['--input', '--output'].includes(key) || i + 1 >= args.length ||
        !args[i + 1] || args[i + 1].startsWith('--') || out[key]) {
      throw new Error(usage);
    }
    out[key] = args[i + 1];
  }
  if (!out['--input']) throw new Error(usage);
  return out;
}
try {
  const options = parseArgs(process.argv.slice(2));
  if (options.help) {
    console.log(usage);
  } else {
    const inputPath = options['--input'];
    const stat = lstatSync(inputPath);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 1024 * 1024) {
      throw new Error('Input must be a non-symlink JSON file no larger than 1 MiB.');
    }
    const data = JSON.parse(readFileSync(inputPath, 'utf8'));
    const report = analyzeIncidentSignals(data);
    const output = JSON.stringify(report, null, 2) + '\n';
    if (options['--output']) {
      // Exclusive create prevents overwrites and symlink-following on existing paths.
      writeFileSync(options['--output'], output, { flag: 'wx', mode: 0o600 });
    } else {
      process.stdout.write(output);
    }
  }
} catch (error) {
  // Error messages must never print input contents, destinations, tokens or user identifiers.
  console.error('DevShield Incident Signals: unable to analyse input; check local JSON and permissions.');
  process.exitCode = 2;
}
