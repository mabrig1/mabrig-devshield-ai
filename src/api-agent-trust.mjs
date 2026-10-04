import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';

const RANK = { low: 1, medium: 2, high: 3, critical: 4 };
const EXTENSIONS = new Set(['.js','.mjs','.cjs','.ts','.tsx','.jsx','.json','.yaml','.yml','.html','.vue','.svelte','.py','.go','.rb','.php']);
const SKIP_DIRS = new Set(['.git','node_modules','.devshield','dist','build','coverage','.next','.nuxt','vendor']);

function lineOf(content, index) {
  return content.slice(0, Math.max(0, index)).split('\n').length;
}

function stableId(rule, file, line) {
  return crypto.createHash('sha256').update(rule + '\0' + file + '\0' + line).digest('hex').slice(0, 20);
}

function makeFinding(rule, severity, category, file, content, index, message, recommendation, confidence = 'high') {
  const line = lineOf(content, index);
  return { id: stableId(rule, file, line), rule, severity, category, confidence, path: file, line, message, recommendation };
}

function firstMatch(content, patterns) {
  let best = null;
  for (const pattern of patterns) {
    const match = pattern.exec(content);
    pattern.lastIndex = 0;
    if (match && (!best || match.index < best.index)) best = match;
  }
  return best;
}

function hasAny(content, patterns) {
  return patterns.some(pattern => {
    const ok = pattern.test(content);
    pattern.lastIndex = 0;
    return ok;
  });
}

function likelyFrontend(file, content) {
  const rel = file.replace(/\\/g, '/').toLowerCase();
  return /(^|\/)(public|client|frontend|src\/components|src\/pages|src\/app)(\/|$)/.test(rel)
    || /\b(window|document|localStorage|sessionStorage)\b/.test(content);
}

export function analyzeApiAgentTrustFile(file, content) {
  const findings = [];
  if (typeof content !== 'string' || !content) return findings;

  const wildcardCors = firstMatch(content, [
    /access-control-allow-origin["'\s:=,-]+\*/i,
    /origin\s*:\s*["']\*["']/i
  ]);
  const credentialedCors = hasAny(content, [
    /access-control-allow-credentials["'\s:=,-]+true/i,
    /credentials\s*:\s*true/i
  ]);
  if (wildcardCors && credentialedCors) {
    findings.push(makeFinding(
      'api-cors-wildcard-credentials','critical','api-boundary',file,content,wildcardCors.index,
      'Wildcard CORS is combined with credentialed requests.',
      'Use an explicit origin allowlist and never combine credentialed requests with a wildcard origin.'
    ));
  }

  const publicSecret = firstMatch(content, [
    /\b(?:NEXT_PUBLIC|VITE|REACT_APP|PUBLIC)_[A-Z0-9_]*(?:SECRET|PRIVATE_KEY|JWT|PAYSTACK_SECRET|STRIPE_SECRET|API_SECRET|ACCESS_TOKEN)[A-Z0-9_]*\b/g,
    /\b(?:window|globalThis)\.[A-Z0-9_]*(?:SECRET|PRIVATE_KEY|PAYSTACK_SECRET|STRIPE_SECRET|JWT_SECRET)[A-Z0-9_]*\b/gi
  ]);
  if (publicSecret) {
    findings.push(makeFinding(
      'api-client-secret-exposure','critical','secrets',file,content,publicSecret.index,
      'A secret-looking credential is exposed through a client or public variable namespace.',
      'Move the credential to a server-side secret store and proxy the privileged operation through an authenticated backend.'
    ));
  }

  const jwtNone = firstMatch(content, [
    /algorithms?\s*:\s*\[[^\]]*["']none["']/i,
    /algorithm\s*:\s*["']none["']/i
  ]);
  if (jwtNone) {
    findings.push(makeFinding(
      'api-jwt-none-algorithm','critical','authentication',file,content,jwtNone.index,
      'JWT verification appears to allow the none algorithm.',
      'Require a strong explicit signing algorithm and validate issuer, audience, expiry, and signature.'
    ));
  }

  const hardcodedJwt = firstMatch(content, [
    /\b(?:jwt|jsonwebtoken)\.(?:sign|verify)\s*\([^,]+,\s*["'][^"'\n]{4,}["']/i,
    /\bsignJwt\s*\([^,]+,\s*["'][^"'\n]{4,}["']/i
  ]);
  if (hardcodedJwt) {
    findings.push(makeFinding(
      'api-jwt-hardcoded-secret','critical','authentication',file,content,hardcodedJwt.index,
      'JWT signing or verification appears to use a hard-coded literal secret.',
      'Load signing material from a protected secret store and rotate any exposed value.'
    ));
  }

  const adminRoute = firstMatch(content, [
    /["']\/api\/admin(?:\/|["'])/i,
    /\b(?:app|router)\.(?:get|post|put|patch|delete)\s*\(\s*["'][^"']*admin/i
  ]);
  if (adminRoute && !hasAny(content, [
    /\brequireAuth\b/i,/\bauthenticate\b/i,/\bauthori[sz]e\b/i,/\brequireRole\b/i,
    /\bjwt\.(?:verify|decode)\b/i,/\bverifyJwt\b/i,/\buser\.role\b/i,/\bsession\b/i
  ])) {
    findings.push(makeFinding(
      'api-admin-route-no-auth-signal','high','authorization',file,content,adminRoute.index,
      'An admin API route is present without a file-level authentication or authorization signal.',
      'Protect admin routes with server-side authentication and explicit role or permission checks.',
      'medium'
    ));
  }

  const webhook = firstMatch(content, [
    /["'][^"']*webhook[^"']*["']/i,
    /\bwebhook\b/i
  ]);
  if (webhook && !hasAny(content, [
    /x-[a-z0-9-]*signature/i,/verifySignature/i,/verifyWebhook/i,/constructEvent/i,
    /createHmac/i,/timingSafeEqual/i,/webhook.*secret/i,/signature.*verify/i
  ])) {
    findings.push(makeFinding(
      'api-webhook-unverified','high','integrity',file,content,webhook.index,
      'A webhook handler is present without an observable signature-verification signal.',
      'Verify the provider signature over the raw request body before processing any webhook event.',
      'medium'
    ));
  }

  const userFetch = firstMatch(content, [
    /\bfetch\s*\(\s*(?:req|request)\.(?:body|query|params)/i,
    /\baxios\.(?:get|post|request)\s*\(\s*(?:req|request)\.(?:body|query|params)/i,
    /\b(?:fetch|request)\s*\(\s*(?:url|target|endpoint)\s*\)/i
  ]);
  if (userFetch && hasAny(content, [
    /\breq(?:uest)?\.(?:body|query|params)\b/i,
    /new URL\s*\([^)]*(?:body|query|params)/i
  ])) {
    findings.push(makeFinding(
      'api-user-controlled-outbound-request','high','ssrf',file,content,userFetch.index,
      'An outbound request may be built from user-controlled request data.',
      'Allowlist destinations, reject private and link-local addresses, pin validated DNS results, and disable redirects unless required.',
      'medium'
    ));
  }

  const disabledApproval = firstMatch(content, [
    /\b(?:require[_-]?approval|human[_-]?approval|approvalRequired)\s*[:=]\s*(?:false|["']never["'])/i,
    /\bautoApprove\s*[:=]\s*true/i
  ]);
  if (disabledApproval && hasAny(content, [
    /\b(agent|tool|function[_-]?call|computer[_-]?use|browser[_-]?use|execute|invoke)\b/i
  ])) {
    findings.push(makeFinding(
      'agent-human-approval-disabled','high','agentic-control',file,content,disabledApproval.index,
      'Agent or tool execution explicitly disables human approval.',
      'Require approval for high-impact tools, external side effects, privileged data access, deployments, payments, and destructive actions.'
    ));
  }

  const wildcardTools = firstMatch(content, [
    /\b(?:allowedTools|allowed_tools|toolAllowlist|tool_allowlist)\s*[:=]\s*\[\s*["']\*["']\s*\]/i,
    /\b(?:tools|permissions)\s*[:=]\s*["']\*["']/i
  ]);
  if (wildcardTools && hasAny(content, [/\b(agent|mcp|tool|assistant)\b/i])) {
    findings.push(makeFinding(
      'agent-unbounded-tool-authority','high','agentic-control',file,content,wildcardTools.index,
      'An agent or tool configuration grants wildcard tool authority.',
      'Use an explicit least-privilege tool allowlist and bind high-impact tools to human approval and scoped credentials.',
      'medium'
    ));
  }

  const promptShell = firstMatch(content, [
    /\b(?:exec|execSync|spawn|spawnSync)\s*\(\s*(?:response|result|output|completion|message|toolCall|tool_call|agentOutput|agent_output)\b/i,
    /\b(?:exec|execSync)\s*\(\s*[^)]*(?:choices\[|\.content\b|\.text\b)/i
  ]);
  if (promptShell) {
    findings.push(makeFinding(
      'agent-model-output-to-shell','critical','agentic-control',file,content,promptShell.index,
      'Model or tool output appears to flow directly into shell or process execution.',
      'Replace shell execution with typed allowlisted operations, validate arguments structurally, and require human approval for privileged side effects.'
    ));
  }

  const sensitiveRoute = firstMatch(content, [
    /["']\/api\/(?:orders?|payments?|checkout|purchase-orders|rfqs?)(?:\/|["'])/i
  ]);
  if (sensitiveRoute && hasAny(content, [/\bPOST\b/i,/\.(?:post|put|patch)\s*\(/i]) && !hasAny(content, [
    /Idempotency-Key/i,/idempotency[_-]?key/i,/\breference\b/i,/dedup/i
  ])) {
    findings.push(makeFinding(
      'api-sensitive-write-no-idempotency-signal','medium','transaction-safety',file,content,sensitiveRoute.index,
      'A transaction-sensitive write route is present without an observable idempotency or deduplication signal.',
      'Accept an idempotency key or provider reference and enforce uniqueness server-side before applying side effects.',
      'medium'
    ));
  }

  const paymentSecret = firstMatch(content, [
    /\b(?:sk_live_[A-Za-z0-9]+|sk_test_[A-Za-z0-9]+|FLWSECK-[A-Za-z0-9_-]+)\b/,
    /\bPAYSTACK_SECRET_KEY\b/
  ]);
  if (paymentSecret && likelyFrontend(file, content)) {
    findings.push(makeFinding(
      'api-payment-secret-in-client','critical','payments',file,content,paymentSecret.index,
      'A payment-provider secret appears in browser or client code.',
      'Move payment initialization and verification to the backend. Expose only public keys or one-time checkout URLs to the client.'
    ));
  }

  return findings;
}

export function collectCandidateFiles(workspace, options = {}) {
  const maxFiles = Math.max(1, Math.min(5000, Number(options.maxFiles || 800)));
  const maxFileBytes = Math.max(10000, Math.min(5000000, Number(options.maxFileBytes || 1500000)));
  const files = [];

  function walk(dir) {
    if (files.length >= maxFiles) return;
    let entries = [];
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }

    for (const entry of entries) {
      if (files.length >= maxFiles) break;
      if (entry.isSymbolicLink()) continue;
      const abs = path.join(dir, entry.name);

      if (entry.isDirectory()) {
        if (!SKIP_DIRS.has(entry.name)) walk(abs);
        continue;
      }

      if (!entry.isFile()) continue;
      const ext = path.extname(entry.name).toLowerCase();
      if (!EXTENSIONS.has(ext) && entry.name !== 'Dockerfile' && entry.name !== 'Procfile') continue;

      let stat;
      try { stat = fs.statSync(abs); } catch { continue; }
      if (stat.size > maxFileBytes) continue;

      files.push(path.relative(workspace, abs).replace(/\\/g, '/'));
    }
  }

  walk(workspace);
  return files;
}

export function scanApiAgentTrust(options = {}) {
  const workspace = options.workspace || process.cwd();
  const selected = Array.isArray(options.files)
    ? options.files
    : collectCandidateFiles(workspace, { maxFiles: options.maxFiles, maxFileBytes: options.maxFileBytes });

  const findings = [];

  for (const rel of selected) {
    const normalized = String(rel).replace(/\\/g, '/');
    if (!normalized || normalized.includes('\0') || normalized.split('/').includes('..')) continue;

    const abs = path.join(workspace, normalized);
    let content;
    try {
      const stat = fs.lstatSync(abs);
      if (!stat.isFile() || stat.isSymbolicLink()) continue;
      content = fs.readFileSync(abs, 'utf8');
    } catch {
      continue;
    }

    findings.push(...analyzeApiAgentTrustFile(normalized, content));
  }

  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const item of findings) counts[item.severity] = (counts[item.severity] || 0) + 1;

  let highestSeverity = 'none';
  for (const item of findings) {
    if (highestSeverity === 'none' || RANK[item.severity] > RANK[highestSeverity]) highestSeverity = item.severity;
  }

  return {
    schemaVersion: 1,
    engine: 'api-agent-trust-shield',
    generatedAt: new Date().toISOString(),
    scannedFiles: selected.length,
    findings,
    counts,
    highestSeverity
  };
}

export function apiAgentTrustMarkdown(report, mode = 'advisory') {
  const lines = [
    '# DevShield API & Agent Trust Shield',
    '',
    'Mode: **' + mode + '**',
    'Scanned files: **' + report.scannedFiles + '**',
    'Findings: **' + report.findings.length + '** (critical ' + report.counts.critical + ', high ' + report.counts.high + ', medium ' + report.counts.medium + ', low ' + report.counts.low + ')',
    ''
  ];

  if (!report.findings.length) {
    lines.push('No API or agent trust signals were observed by this static heuristic pass.', '');
  } else {
    lines.push('## Findings', '');
    for (const item of report.findings) {
      lines.push(
        '- **' + item.severity.toUpperCase() + '** [' + item.rule + '] — ' + item.path + ':' + item.line,
        '  - ' + item.message,
        '  - Recommendation: ' + item.recommendation,
        '  - Confidence: ' + item.confidence
      );
    }
    lines.push('');
  }

  lines.push(
    '## Scope',
    '',
    'This shield identifies static security signals and trust-boundary gaps. It does not prove exploitability, compromise, or regulatory non-compliance.',
    ''
  );

  return lines.join('\n');
}

export function apiAgentTrustSarif(report) {
  const ruleMap = new Map();

  for (const item of report.findings) {
    if (!ruleMap.has(item.rule)) {
      ruleMap.set(item.rule, {
        id: item.rule,
        name: item.rule,
        shortDescription: { text: item.message },
        help: { text: item.recommendation }
      });
    }
  }

  const level = severity => severity === 'critical' || severity === 'high'
    ? 'error'
    : severity === 'medium'
      ? 'warning'
      : 'note';

  return {
    version: '2.1.0',
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    runs: [{
      tool: {
        driver: {
          name: 'MABRIG DevShield API & Agent Trust Shield',
          version: '3.0.0',
          rules: [...ruleMap.values()]
        }
      },
      results: report.findings.map(item => ({
        ruleId: item.rule,
        level: level(item.severity),
        message: { text: item.message },
        locations: [{
          physicalLocation: {
            artifactLocation: { uri: item.path },
            region: { startLine: item.line }
          }
        }],
        fingerprints: { 'devshield/api-agent-trust': item.id }
      }))
    }]
  };
}

export function shouldFailApiAgentTrust(report, failOn = 'high') {
  if (failOn === 'none') return false;
  const threshold = RANK[failOn] || RANK.high;
  return report.findings.some(item => RANK[item.severity] >= threshold);
}
