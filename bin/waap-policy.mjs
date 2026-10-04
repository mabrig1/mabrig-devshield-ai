#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { openApiToWaapPolicy, readOpenApiJson } from '../src/waap-openapi.mjs';

const args = process.argv.slice(2);

if (!args.length || args.includes('--help') || args.includes('-h')) {
  console.log([
    'DevShield WAAP OpenAPI policy generator',
    '',
    'Usage:',
    '  node bin/waap-policy.mjs <openapi.json> [--out runtime-waf/policy.generated.json] [--base policy.json]',
    '',
    'Options:',
    '  --out <file>   Output JSON path. Defaults to stdout.',
    '  --base <file>  Optional existing WAAP/WAF policy whose global settings are preserved.',
    '  -h, --help     Show this help.',
    '',
    'Only OpenAPI 3.x JSON documents are supported. YAML is intentionally not parsed to keep the tool dependency-free.'
  ].join('\n'));
  process.exit(0);
}

const input = args[0];
let outFile = '';
let baseFile = '';

for (let i = 1; i < args.length; i++) {
  if (args[i] === '--out' && args[i + 1]) outFile = args[++i];
  else if (args[i] === '--base' && args[i + 1]) baseFile = args[++i];
  else {
    console.error('Unknown argument: ' + args[i]);
    process.exit(2);
  }
}

function safeRepoPath(value) {
  const normalized = path.normalize(value);
  if (path.isAbsolute(normalized) || normalized.startsWith('..')) {
    throw new Error('Output/base path must be repository-relative');
  }
  return normalized;
}

try {
  const spec = readOpenApiJson(input);
  let base = {};

  if (baseFile) {
    const safeBase = safeRepoPath(baseFile);
    base = JSON.parse(fs.readFileSync(safeBase, 'utf8'));
  }

  const policy = openApiToWaapPolicy(spec, base);
  const output = JSON.stringify(policy, null, 2) + '\n';

  if (outFile) {
    const safeOut = safeRepoPath(outFile);
    fs.mkdirSync(path.dirname(safeOut), { recursive: true });
    fs.writeFileSync(safeOut, output);
    console.log('WAAP policy written to ' + safeOut);
    console.log('Generated routes: ' + policy.routes.length);
  } else {
    process.stdout.write(output);
  }
} catch (error) {
  console.error('WAAP policy generation failed: ' + String(error?.message || error));
  process.exit(1);
}
