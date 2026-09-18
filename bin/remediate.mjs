#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import {
  applyApprovedRemediation,
  createRemediationPlan,
  remediationMarkdown,
  writeRemediationPlan
} from '../src/remediation-engine.mjs';

const args = process.argv.slice(2);
const options = new Map();
const flags = new Set();

for (let i = 0; i < args.length; i++) {
  const arg = args[i];
  if (arg === '--help' || arg === '-h') flags.add('help');
  else if (arg === '--apply') flags.add('apply');
  else if (arg === '--dry-run') flags.add('dry-run');
  else if (arg.startsWith('--') && i + 1 < args.length) options.set(arg.slice(2), args[++i]);
  else {
    console.error(`Unknown argument: ${arg}`);
    process.exit(2);
  }
}

if (flags.has('help')) {
  console.log(`MABRIG DevShield AI approval-gated remediation

Usage:
  npm run remediate
  npm run remediate -- --apply --approve <missionId>
  npm run remediate -- --apply --approve <missionId> --dry-run

Options:
  --agentic-plan <path>     Agentic plan (default: .devshield/devshield-agentic-plan.json)
  --report-dir <path>       Report directory (default: .devshield)
  --apply                   Apply allowlisted exact edits locally
  --approve <missionId>     Required with --apply; must match the plan mission
  --dry-run                 Validate approved edits without writing files
  -h, --help                Show help

The GitHub Action never applies repository mutations. This local command rejects stale source lines and symlink paths.`);
  process.exit(0);
}

const workspace = process.cwd();
const agenticPlanPath = options.get('agentic-plan') || '.devshield/devshield-agentic-plan.json';
const reportDir = options.get('report-dir') || '.devshield';
const approval = options.get('approve') || '';

if (path.isAbsolute(agenticPlanPath) || agenticPlanPath.includes('..') || agenticPlanPath.includes('\\')) {
  console.error('Agentic plan must be a repository-relative path.');
  process.exit(2);
}

try {
  const agenticPlan = JSON.parse(fs.readFileSync(path.join(workspace, agenticPlanPath), 'utf8'));
  const plan = createRemediationPlan({ workspace, agenticPlan });
  const files = writeRemediationPlan({ workspace, reportDir, plan });
  console.log(remediationMarkdown(plan));
  console.log(`Remediation plan: ${files.jsonFile}`);

  if (flags.has('apply')) {
    if (!approval) throw new Error('Use --approve <missionId> to apply remediation.');
    const result = applyApprovedRemediation({
      workspace,
      plan,
      approval,
      dryRun: flags.has('dry-run')
    });
    console.log(`${result.dryRun ? 'Validated' : 'Applied'} ${result.applied.length} approved exact remediation edit(s).`);
    console.log('Run DevShield again to verify the remediated fingerprints are gone.');
  }
} catch (error) {
  console.error(`DevShield remediation failed: ${error.message}`);
  process.exit(2);
}
