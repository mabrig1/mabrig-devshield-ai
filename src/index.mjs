import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';

const severityRank = { low: 1, medium: 2, high: 3, critical: 4 };
const weights = { low: 2, medium: 7, high: 15, critical: 30 };
const input = (name, fallback = '') => process.env[name] ?? fallback;
const event = readJson(process.env.GITHUB_EVENT_PATH);
const workspace = process.env.GITHUB_WORKSPACE || process.cwd();
const maxFiles = clampInt(input('INPUT_MAX_FILES', '80'), 1, 300);
const failOn = input('INPUT_FAIL_ON', 'critical').toLowerCase();
const shouldComment = input('INPUT_COMMENT', 'true').toLowerCase() === 'true';
const token = input('INPUT_GITHUB_TOKEN') || process.env.GITHUB_TOKEN || '';
const openRouterKey = input('INPUT_OPENROUTER_API_KEY');
const model = input('INPUT_MODEL', 'openrouter/auto');
const outputFile = process.env.GITHUB_OUTPUT;
const summaryFile = process.env.GITHUB_STEP_SUMMARY;

function readJson(file) {
  if (!file) return {};
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return {}; }
}

function clampInt(value, min, max) {
  const n = Number.parseInt(value, 10);
  return Number.isFinite(n) ? Math.max(min, Math.min(max, n)) : min;
}

function git(args) {
  return execFileSync('git', args, { cwd: workspace, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();
}

function getDiffRange() {
  const base = event?.pull_request?.base?.sha;
  const head = event?.pull_request?.head?.sha;
  if (base && head) return [`${base}...${head}`];
  const before = event?.before;
  const after = event?.after;
  if (before && after && !/^0+$/.test(before)) return [`${before}...${after}`];
  return ['HEAD^', 'HEAD'];
}

function getChangedFiles() {
  const ranges = getDiffRange();
  let text = '';
  try {
    text = ranges.length === 1 ? git(['diff', '--name-only', ranges[0]]) : git(['diff', '--name-only', ...ranges]);
  } catch {
    try { text = git(['ls-files']); } catch { return []; }
  }
  return text.split(/\r?\n/).map(s => s.trim()).filter(Boolean).filter(isSafeRelativePath).slice(0, maxFiles);
}

function isSafeRelativePath(rel) {
  if (rel.includes('\0')) return false;
  const normalized = path.normalize(rel);
  return !normalized.startsWith('..') && !path.isAbsolute(normalized);
}

function isTextCandidate(file) {
  const base = path.basename(file);
  if (/^(package-lock\.json|pnpm-lock\.yaml|yarn\.lock|bun\.lockb)$/i.test(base)) return false;
  if (/\.(png|jpe?g|gif|webp|ico|pdf|zip|gz|tar|7z|woff2?|ttf|eot|mp3|mp4|mov|avi|lock)$/i.test(file)) return false;
  if (/(^|\/)(node_modules|dist|build|coverage|vendor)\//.test(file)) return false;
  return true;
}

const rules = [
  { id: 'private-key', severity: 'critical', re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/, message: 'Private key material appears to be committed.' },
  { id: 'github-token', severity: 'critical', re: /\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,})\b/, message: 'Possible GitHub token detected.' },
  { id: 'openai-key', severity: 'critical', re: /\bsk-(?:proj-|or-v1-)?[A-Za-z0-9_-]{20,}\b/, message: 'Possible AI provider API key detected.' },
  { id: 'aws-access-key', severity: 'critical', re: /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/, message: 'Possible AWS access key detected.' },
  { id: 'stripe-live-key', severity: 'critical', re: /\b(?:sk_live|rk_live)_[A-Za-z0-9]{16,}\b/, message: 'Possible Stripe live secret detected.' },
  { id: 'dangerous-eval', severity: 'high', re: /\beval\s*\(/, message: 'Dynamic eval() can enable code injection. Review necessity and input origin.' },
  { id: 'shell-exec', severity: 'medium', re: /\b(?:exec|execSync)\s*\(/, message: 'Shell execution found. Confirm arguments cannot contain untrusted input.' },
  { id: 'disabled-tls', severity: 'high', re: /rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*["']?0/, message: 'TLS certificate verification appears disabled.' },
  { id: 'wildcard-cors', severity: 'medium', re: /Access-Control-Allow-Origin["'\s,:=]+\*|origin\s*:\s*["']\*["']/, message: 'Wildcard CORS detected. Verify that public cross-origin access is intended.' },
  { id: 'sql-string-build', severity: 'high', re: /(?:SELECT|INSERT|UPDATE|DELETE)[^\n]{0,80}(?:\$\{|\+\s*req\.|\+\s*request\.|\+\s*params\.)/i, message: 'Possible SQL query construction with request data. Prefer parameterized queries.' },
  { id: 'debug-mode', severity: 'low', re: /\bDEBUG\s*=\s*(?:true|1)\b|debug\s*:\s*true/, message: 'Debug mode appears enabled; ensure it is not enabled in production.' },
];

function scanFile(rel) {
  const abs = path.join(workspace, rel);
  if (!fs.existsSync(abs) || !fs.statSync(abs).isFile() || !isTextCandidate(rel)) return [];
  let content;
  try { content = fs.readFileSync(abs, 'utf8'); } catch { return []; }
  if (content.length > 1_500_000) content = content.slice(0, 1_500_000);
  const findings = [];
  const lines = content.split(/\r?\n/);

  if (/^\.env(?:\.|$)/.test(path.basename(rel)) && !/\.example$/i.test(rel)) {
    findings.push({ rule: 'tracked-env', severity: 'critical', file: rel, line: 1, message: 'A real .env-style file is tracked. Move secrets to GitHub Actions secrets and keep only an example file.' });
  }

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    for (const rule of rules) {
      rule.re.lastIndex = 0;
      if (rule.re.test(line)) findings.push({ rule: rule.id, severity: rule.severity, file: rel, line: i + 1, message: rule.message });
    }
    if (/NEXT_PUBLIC_[A-Z0-9_]*(?:SECRET|PRIVATE|TOKEN|API_KEY)[A-Z0-9_]*\s*=/.test(line)) {
      findings.push({ rule: 'public-secret-env', severity: 'critical', file: rel, line: i + 1, message: 'A secret-looking value uses NEXT_PUBLIC_, which exposes it to browser bundles.' });
    }
    if (/uses:\s*[^\s]+@(?:main|master|latest)\b/i.test(line)) {
      findings.push({ rule: 'unpinned-action', severity: 'medium', file: rel, line: i + 1, message: 'GitHub Action is pinned to a moving branch/tag. Prefer a trusted version or commit SHA for stronger supply-chain control.' });
    }
  }

  if (path.basename(rel) === 'package.json') {
    try {
      const pkg = JSON.parse(content);
      for (const group of ['dependencies', 'devDependencies', 'optionalDependencies']) {
        for (const [dep, version] of Object.entries(pkg[group] || {})) {
          if (version === '*' || version === 'latest') findings.push({ rule: 'floating-dependency', severity: 'medium', file: rel, line: 1, message: `${dep} uses a floating version (${version}). Pin a bounded version range.` });
        }
      }
    } catch {}
  }
  return findings;
}

function redactedDiff() {
  const ranges = getDiffRange();
  let diff = '';
  try { diff = ranges.length === 1 ? git(['diff', '--unified=2', ranges[0]]) : git(['diff', '--unified=2', ...ranges]); } catch { return ''; }
  diff = diff.slice(0, 60_000);
  return diff
    .replace(/\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,})\b/g, '[REDACTED_GITHUB_TOKEN]')
    .replace(/\bsk-(?:proj-|or-v1-)?[A-Za-z0-9_-]{20,}\b/g, '[REDACTED_API_KEY]')
    .replace(/\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g, '[REDACTED_AWS_KEY]')
    .replace(/-----BEGIN[\s\S]{0,3000}?PRIVATE KEY-----[\s\S]{0,6000}?-----END[\s\S]{0,80}?PRIVATE KEY-----/g, '[REDACTED_PRIVATE_KEY]');
}

async function aiReview(diff, findings) {
  if (!openRouterKey || !diff) return '';
  const prompt = `You are MABRIG DevShield AI, a cautious senior code reviewer. Review this pull request diff for exploitable security bugs, authorization mistakes, data loss risks, broken error handling, and production regressions. Do not repeat deterministic findings unless you add useful context. Never claim certainty when the diff is insufficient. Return concise Markdown with: Risk verdict, Key findings (max 5), and Recommended fixes.\n\nDeterministic findings:\n${JSON.stringify(findings.slice(0, 30))}\n\nREDACTED DIFF:\n${diff}`;
  try {
    const res = await fetch('https://openrouter.ai/api/v1/chat/completions', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${openRouterKey}`,
        'Content-Type': 'application/json',
        'HTTP-Referer': 'https://github.com',
        'X-Title': 'MABRIG DevShield AI'
      },
      body: JSON.stringify({ model, messages: [{ role: 'user', content: prompt }], temperature: 0.1, max_tokens: 1200 })
    });
    if (!res.ok) return `> AI review unavailable (${res.status}). Deterministic checks still completed.`;
    const data = await res.json();
    return data?.choices?.[0]?.message?.content?.trim() || '';
  } catch (err) {
    return `> AI review unavailable (${String(err.message || err)}). Deterministic checks still completed.`;
  }
}

function riskFrom(findings) {
  const score = Math.min(100, findings.reduce((sum, f) => sum + (weights[f.severity] || 0), 0));
  const highest = findings.reduce((m, f) => Math.max(m, severityRank[f.severity] || 0), 0);
  const level = highest >= 4 ? 'critical' : highest === 3 ? 'high' : highest === 2 ? 'medium' : 'low';
  return { score, level };
}

function escapeCommand(s) { return String(s).replace(/%/g, '%25').replace(/\r/g, '%0D').replace(/\n/g, '%0A'); }
function emitAnnotations(findings) {
  for (const f of findings.slice(0, 50)) {
    const cmd = f.severity === 'critical' || f.severity === 'high' ? 'error' : f.severity === 'medium' ? 'warning' : 'notice';
    console.log(`::${cmd} file=${escapeCommand(f.file)},line=${f.line},title=${escapeCommand(`DevShield ${f.rule}`)}::${escapeCommand(f.message)}`);
  }
}

function buildMarkdown(files, findings, risk, ai) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  findings.forEach(f => counts[f.severity]++);
  const rows = findings.slice(0, 30).map(f => `| ${f.severity.toUpperCase()} | \`${f.rule}\` | \`${f.file}:${f.line}\` | ${f.message.replace(/\|/g, '\\|')} |`).join('\n');
  return `## 🛡️ MABRIG DevShield AI\n\n**Risk:** ${risk.level.toUpperCase()} · **Score:** ${risk.score}/100 · **Files scanned:** ${files.length}\n\nCritical **${counts.critical}** · High **${counts.high}** · Medium **${counts.medium}** · Low **${counts.low}**\n\n${findings.length ? `| Severity | Rule | Location | Finding |\n|---|---|---|---|\n${rows}` : '✅ No deterministic security findings were detected in the scanned files.'}\n\n${findings.length > 30 ? `_${findings.length - 30} additional findings omitted from this comment._\n\n` : ''}${ai ? `### AI-assisted review\n\n${ai}\n\n` : ''}---\n*MABRIG DevShield AI · security-first review before merge*`;
}

async function postPrComment(markdown) {
  const repo = event?.repository?.full_name;
  const number = event?.pull_request?.number;
  if (!shouldComment || !token || !repo || !number) return;
  const [owner, name] = repo.split('/');
  const headers = { Authorization: `Bearer ${token}`, Accept: 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28', 'Content-Type': 'application/json' };
  try {
    const list = await fetch(`https://api.github.com/repos/${owner}/${name}/issues/${number}/comments?per_page=100`, { headers });
    if (!list.ok) return;
    const comments = await list.json();
    const existing = comments.find(c => typeof c.body === 'string' && c.body.includes('## 🛡️ MABRIG DevShield AI') && c.user?.type === 'Bot');
    const url = existing ? existing.url : `https://api.github.com/repos/${owner}/${name}/issues/${number}/comments`;
    await fetch(url, { method: existing ? 'PATCH' : 'POST', headers, body: JSON.stringify({ body: markdown }) });
  } catch {}
}

function setOutput(name, value) {
  if (outputFile) fs.appendFileSync(outputFile, `${name}=${String(value).replace(/\n/g, ' ')}\n`);
}

const files = getChangedFiles().filter(isTextCandidate);
const findings = files.flatMap(scanFile);
const risk = riskFrom(findings);
emitAnnotations(findings);
const ai = await aiReview(redactedDiff(), findings);
const markdown = buildMarkdown(files, findings, risk, ai);
if (summaryFile) fs.appendFileSync(summaryFile, `${markdown}\n`);
await postPrComment(markdown);
setOutput('findings-count', findings.length);
setOutput('risk-score', risk.score);
setOutput('risk-level', risk.level);
console.log(`MABRIG DevShield AI: ${findings.length} findings, risk ${risk.level} (${risk.score}/100).`);

if (failOn !== 'none') {
  const threshold = severityRank[failOn] || severityRank.critical;
  const highest = findings.reduce((m, f) => Math.max(m, severityRank[f.severity] || 0), 0);
  if (highest >= threshold) {
    console.error(`DevShield policy failed: highest severity meets fail-on=${failOn}.`);
    process.exitCode = 1;
  }
}
