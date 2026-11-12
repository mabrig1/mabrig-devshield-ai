#!/usr/bin/env node
// Non-destructive smoke test of the deployed public website.
// No arguments permit untrusted URLs, tokens, source code or API writes.
import { verifyPublicDevShield } from '../src/public-deployment-smoke.mjs';

if (process.argv.slice(2).includes('--help')) {
  console.log('Usage: node bin/check-public-devshield.mjs\nRead-only HTTPS GETs for DevShield homepage, /health, /app.js and /app.css.\nChecks the real production hostname, not a Wrangler dry-run. No API key needed.');
} else if (process.argv.length !== 2) {
  console.error('Unknown arguments. This command checks only the official DevShield hostname.');
  process.exitCode = 2;
} else {
  try {
    const result = await verifyPublicDevShield();
    console.log(JSON.stringify(result, null, 2));
  } catch (error) {
    console.error(error instanceof Error ? error.message : 'Public deployment smoke check failed');
    process.exitCode = 1;
  }
}
