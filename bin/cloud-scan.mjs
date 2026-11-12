#!/usr/bin/env node
// No network activity unless the operator explicitly passes --upload.
import { scanLocal, scanSarif, MODES } from '../src/local-scan-api.mjs';
import { buildCloudReport, uploadCloudReport } from '../src/cloud-scan-bridge.mjs';

const usage = [
  'DevShield local scan + optional privacy-safe cloud report ingestion',
  'Usage: devshield-cloud-scan --workspace <trusted-directory> --mode <scan-mode> [--format json|sarif]',
  '       [--upload --repository owner/repo --api-origin https://your-approved-api.example',
  '         [--idempotency-key stable-run-id]]',
  'Modes: ' + MODES.join(', '),
  'Local scan: zero network calls. Upload: only allowlisted structured finding metadata, never source or paths.',
  'Set DEVSHIELD_CLOUD_API_KEY in the environment for --upload; do not pass API keys as command-line arguments.'
].join('\n');
const options = { mode: 'preflight', format: 'json', upload: false };
const args = process.argv.slice(2);
if (args.includes('--help') || args.includes('-h')) { console.log(usage); process.exit(0); }
for (let i = 0; i < args.length; i++) {
  const opt = args[i];
  if (opt === '--upload') { options.upload = true; continue; }
  if (!['--workspace', '--mode', '--format', '--repository', '--api-origin', '--idempotency-key'].includes(opt) ||
      !args[i + 1] || args[i + 1].startsWith('--')) {
    console.error(usage);
    process.exit(2);
  }
  if (Object.hasOwn(options, opt.slice(2)) && !['mode', 'format'].includes(opt.slice(2))) {
    console.error('Duplicate option');
    process.exit(2);
  }
  options[opt.slice(2)] = args[++i];
}
if (!options.workspace || !MODES.includes(options.mode) || !['json', 'sarif'].includes(options.format) ||
    (!options.upload && (options.repository || options['api-origin'] || options['idempotency-key'])) ||
    (options.upload && (!options.repository || !options['api-origin'] || options.format !== 'json'))) {
  console.error(usage);
  process.exit(2);
}
try {
  const report = scanLocal({ workspace: options.workspace, mode: options.mode });
  if (!report.complete) {
    console.error('Local scan incomplete. Upload refused.');
    process.exitCode = 2;
  } else if (!options.upload) {
    console.log(JSON.stringify(options.format === 'sarif' ? scanSarif(report) : report, null, 2));
  } else {
    const prepared = buildCloudReport(report, {
      repository: options.repository,
      fingerprintKey: process.env.DEVSHIELD_CLOUD_API_KEY,
      idempotencyKey: options['idempotency-key'] || undefined
    });
    const result = await uploadCloudReport(prepared, {
      origin: options['api-origin'],
      apiKey: process.env.DEVSHIELD_CLOUD_API_KEY
    });
    console.log(JSON.stringify({ upload: result.status, id: result.id,
      scanType: options.mode, findings: prepared.payload.findings.length,
      metadataBytes: prepared.bytes, sourceUploaded: false, pathsUploaded: false,
      idempotencyKey: prepared.idempotencyKey }));
  }
} catch (error) {
  // Never log source content, API keys, request headers or remote response bodies.
  const code = String(error?.message || '');
  if (/^Cloud API rejected report \(HTTP [0-9]+\)$/.test(code)) {
    console.error(code);
  } else {
    console.error('Scan or upload rejected; check workspace, metadata completeness and cloud configuration.');
  }
  process.exitCode = 2;
}
