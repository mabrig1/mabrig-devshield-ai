#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import { importReachabilitySarif } from '../src/reachability-evidence.mjs';

const args = process.argv.slice(2);
if (args.length === 1 && args[0] === '--help') {
  console.log('Usage: node bin/reachability.mjs --sarif <CodeQL SARIF file> [--workspace <checkout>] [--out <JSON file>]');
  process.exit(0);
}
const opts = {};
for (let i = 0; i < args.length; i += 2) {
  if (!['--sarif', '--workspace', '--out'].includes(args[i]) || !args[i + 1]) {
    console.error('Invalid argument. Use --help.'); process.exit(2);
  }
  opts[args[i].slice(2)] = args[i + 1];
}
if (!opts.sarif) { console.error('--sarif is required'); process.exit(2); }
try {
  const input = path.resolve(opts.sarif);
  const stat = fs.lstatSync(input);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 8 * 1024 * 1024) throw new Error('SARIF file must be regular and at most 8 MiB');
  const report = importReachabilitySarif(JSON.parse(fs.readFileSync(input, 'utf8')), {
    workspace: path.resolve(opts.workspace || process.cwd())
  });
  const output = JSON.stringify(report, null, 2) + '\n';
  if (opts.out) fs.writeFileSync(path.resolve(opts.out), output, { flag: 'wx', mode: 0o600 });
  else process.stdout.write(output);
} catch (error) {
  console.error('Reachability evidence import failed: ' + error.message);
  process.exitCode = 2;
}
