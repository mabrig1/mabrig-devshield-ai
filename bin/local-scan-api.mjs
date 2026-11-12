#!/usr/bin/env node
// Starts only a loopback developer API, never a public HTTP listener.
import path from 'node:path';
import { createLocalScanServer } from '../src/local-scan-server.mjs';

const args = process.argv.slice(2);
if (args.includes('--help') || args.includes('-h')) {
  console.log('Usage: devshield-local-api --workspace <trusted-directory> [--port 0..65535]\nSet DEVSHIELD_LOCAL_API_TOKEN to a 32+ character random URL-safe secret.\nBinds to 127.0.0.1 only; never executes scanned source or transmits code.');
  process.exit(0);
}
let workspace = '', port = 0;
for (let i = 0; i < args.length; i += 2) {
  if (args[i] === '--workspace' && args[i + 1]) workspace = args[i + 1];
  else if (args[i] === '--port' && args[i + 1] && /^\d{1,5}$/.test(args[i + 1])) port = Number(args[i + 1]);
  else { console.error('Invalid or incomplete option'); process.exit(2); }
}
if (!workspace || port > 65535) {
  console.error('Trusted workspace and valid port required. See --help.');
  process.exit(2);
}
try {
  const server = createLocalScanServer({
    workspace: path.resolve(workspace),
    token: process.env.DEVSHIELD_LOCAL_API_TOKEN
  });
  server.listen(port, '127.0.0.1', () => {
    console.log('DevShield local scan API listening at http://127.0.0.1:' + server.address().port);
  });
  process.on('SIGINT', () => server.close());
  process.on('SIGTERM', () => server.close());
} catch {
  console.error('Local API configuration rejected; check workspace and DEVSHIELD_LOCAL_API_TOKEN.');
  process.exitCode = 2;
}
