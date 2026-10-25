#!/usr/bin/env node
import { ADVISORY_SNAPSHOT, assessRuntimeVersion } from '../src/runtime-advisories.mjs';

const args = process.argv.slice(2);
if (args.includes('--help') || args.includes('-h')) {
  console.log(`DevShield offline runtime advisory check
Usage: node bin/runtime-advisories.mjs [--node-version X.Y.Z] [--php-version X.Y.Z] [--fail-on high|critical|medium|none]
With no version arguments, checks this scanner's Node.js runtime only.
Explicit versions are operator-supplied evidence, not remotely verified deployment evidence.
JSON goes to stdout. No network requests, package installation, target execution or changes.
Exit 1: threshold met. Exit 2: invalid arguments. Exit 0 is not security certification.
Snapshot: ${ADVISORY_SNAPSHOT.id}`);
} else {
  const versions = new Map();
  let failOn = 'high';
  try {
    for (let i = 0; i < args.length; i++) {
      const arg = args[i];
      if (!['--node-version', '--php-version', '--fail-on'].includes(arg)) throw new Error('Unknown option; use --help.');
      const value = args[++i];
      if (!value || value.startsWith('--')) throw new Error('Missing option value; use --help.');
      if (arg === '--fail-on') {
        if (!['high', 'critical', 'medium', 'none'].includes(value)) throw new Error('Invalid failure threshold.');
        failOn = value;
      } else {
        if (!/^v?\d+\.\d+\.\d+$/.test(value) || value.length > 40) throw new Error('Supply an exact stable runtime version (X.Y.Z).');
        versions.set(arg === '--node-version' ? 'node' : 'php', value);
      }
    }
    const supplied = versions.size > 0;
    if (!supplied) versions.set('node', process.versions.node);
    const assessments = [...versions].map(([runtime, version]) => ({
      ...assessRuntimeVersion(runtime, version),
      evidenceSource: supplied ? 'operator-supplied-version' : 'local-scanner-process',
      deploymentVerified: false
    }));
    console.log(JSON.stringify({ schemaVersion: 1, snapshot: ADVISORY_SNAPSHOT.id, assessments }, null, 2));
    const rank = { medium: 2, high: 3, critical: 4 };
    if (failOn !== 'none' && assessments.some(x => rank[x.severity] >= rank[failOn])) process.exitCode = 1;
  } catch (err) {
    console.error(err.message);
    process.exitCode = 2;
  }
}
