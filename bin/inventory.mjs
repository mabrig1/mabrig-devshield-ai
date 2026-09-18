#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import { createDependencyInventory, inventoryBlocks, inventoryMarkdown } from '../src/dependency-inventory.mjs';

// Only use relative paths inside the caller's workspace, without symlink traversal.
function workspacePath(relative) {
  if (!relative || path.isAbsolute(relative) || relative.includes('\\') || relative.split('/').includes('..') || /[\x00-\x1f\x7f]/.test(relative)) throw new Error('Use a relative path inside the workspace.');
  let current = process.cwd();
  for (const part of relative.split('/').filter(p => p && p !== '.')) {
    current = path.join(current, part);
    try { if (fs.lstatSync(current).isSymbolicLink()) throw new Error('Symlink paths are not supported.'); }
    catch (error) { if (error.code !== 'ENOENT') throw error; }
  }
  return current;
}

try {
  const options = { 'report-dir': '.devshield', 'fail-on': 'high' };
  const args = process.argv.slice(2);
  if (args.includes('--help') || args.includes('-h')) {
    console.log('DevShield offline npm dependency evidence\n\nUsage: node bin/inventory.mjs [--lockfile path] [--report-dir path] [--fail-on high|medium|low|critical|none]\n\nDefaults: npm-shrinkwrap.json before package-lock.json; .devshield reports; high severity gate.\nReads a working-tree npm v2/v3 lockfile without network access or installation.\nExit codes: 0 passed, 1 metadata gate blocked, 2 invalid input or report failure.');
  } else {
    for (let i = 0; i < args.length; i += 2) {
      const key = args[i].slice(2);
      if (!['--lockfile', '--report-dir', '--fail-on'].includes(args[i]) || !args[i + 1] || args[i + 1].startsWith('--')) throw new Error('Unknown argument or missing option value. Use --help.');
      options[key] = args[i + 1];
    }
    inventoryBlocks({ findings: [] }, options['fail-on']);
    const sourceFile = options.lockfile || (fs.existsSync('npm-shrinkwrap.json') ? 'npm-shrinkwrap.json' : 'package-lock.json');
    const input = workspacePath(sourceFile);
    const stat = fs.statSync(input);
    if (!stat.isFile() || stat.size > 20 * 1024 * 1024) throw new Error('Lockfile must be a regular file no larger than 20 MiB.');
    const report = createDependencyInventory(fs.readFileSync(input, 'utf8'), { sourceFile });
    const reportDir = workspacePath(options['report-dir']);
    const outputs = ['dependency-inventory.json', 'dependency-inventory.md'].map(name => workspacePath(path.join(options['report-dir'], name)));
    if (outputs.includes(input)) throw new Error('Report output would overwrite the input lockfile.');
    fs.mkdirSync(reportDir, { recursive: true });
    fs.writeFileSync(outputs[0], `${JSON.stringify(report, null, 2)}\n`, { flag: fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_TRUNC | fs.constants.O_NOFOLLOW, mode: 0o600 });
    fs.writeFileSync(outputs[1], inventoryMarkdown(report), { flag: fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_TRUNC | fs.constants.O_NOFOLLOW, mode: 0o600 });
    const blocked = inventoryBlocks(report, options['fail-on']);
    console.log(`DevShield dependency evidence: ${report.summary.packages} packages, ${report.summary.findings} metadata findings. Gate: ${blocked ? 'blocked' : 'passed'}.`);
    process.exitCode = blocked ? 1 : 0;
  }
} catch (error) {
  // Do not print raw JSON, URLs, or OS errors that could contain sensitive input.
  console.error(`DevShield inventory failed: ${error.code ? 'could not access the input or report path.' : error.message}`);
  process.exitCode = 2;
}
