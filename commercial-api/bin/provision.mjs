#!/usr/bin/env node
// Offline operator-only provisioning: no API key is sent to GitHub or the network.
import { createHash, randomBytes, randomUUID } from 'node:crypto';
const [tenantId, tenantName, limitRaw = '50'] = process.argv.slice(2);
const limit = Number(limitRaw);
if (!/^[a-zA-Z0-9_-]{2,64}$/.test(tenantId || '') ||
    typeof tenantName !== 'string' || !tenantName.trim() || tenantName.length > 120 ||
    !Number.isSafeInteger(limit) || limit < 1 || limit > 100000) {
  console.error('Usage: node bin/provision.mjs <tenant-id> <tenant-name> [daily-scan-limit]');
  process.exitCode = 2;
} else {
  const token = 'dsc_live_' + randomBytes(32).toString('base64url');
  const hash = createHash('sha256').update(token).digest('hex');
  const sql = value => "'" + String(value).replaceAll("'", "''") + "'";
  const statements = [
    `INSERT INTO tenants (id, name, daily_scan_limit) VALUES (${sql(tenantId)}, ${sql(tenantName)}, ${limit});`,
    `INSERT INTO api_keys (id, tenant_id, key_hash, label, scopes) VALUES (${sql(randomUUID())}, ${sql(tenantId)}, ${sql(hash)}, 'initial-installation', 'scans:read scans:write');`
  ];
  console.log('ONE-TIME API KEY (store securely; not recoverable):');
  console.log(token);
  console.log('\nRun the following SQL against your PRIVATE D1 database using wrangler d1 execute --command (or via an operator-only migration):');
  for (const line of statements) console.log(line);
  console.log('\nNever commit this output or post the API key in chat, tickets or CI logs.');
}
