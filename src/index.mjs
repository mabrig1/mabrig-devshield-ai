import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { REDACTORS, rules } from './rules.mjs';

const VERSION = '1.1.0';
const COMMENT_MARKER = '<!-- mabrig-devshield-ai -->';
const severityRank = { low: 1, medium: 2, high: 3, critical: 4 };
const weights = { low: 2, medium: 7, high: 15, critical: 30 };
const input = (name, fallback = '') => process.env[name] ?? fallback;
const nonEmptyInput = (name, fallback = '') => {
  const value = process.env[name];
  return value == null || String(value).trim() === '' ? fallback : value;
};
const event = readJson(process.env.GITHUB_EVENT_PATH);
const workspace = process.env.GITHUB_WORKSPACE || process.cwd();

function readJson(file) {
  if (!file) return {};
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return {}; }
}

function clampInt(value, min, max, fallback = min) {
  const n = Number.parseInt(value, 10);
  return Number.isFinite(n) ? Math.max(min, Math.min(max, n)) : fallback;
}

function parseBool(value, fallback = false) {
  if (value == null || value === '') return fallback;
  return String(value).toLowerCase() === 'true';
}

function safeRelative(rel) {
  if (!rel || rel.includes('\0')) return false;
  const normalized = path.normalize(rel);
  return !path.isAbsolute(normalized) && !normalized.startsWith('..') && !normalized.split(path.sep).includes('..');
}

function git(args) {
  return execFileSync('git', args, { cwd: workspace, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], maxBuffer: 20 * 1024 * 1024 }).trimEnd();
}

function getDiffRange() {
  const base = event?.pull_request?.base?.sha;
  const head = event?.pull_request?.head?.sha;
  if (base && head) return `${base}...${head}`;
  const before = event?.before;
  const after = event?.after;
  if (before && after && !/^0+$/.test(before)) return `${before}...${after}`;
  try {
    git(['rev-parse', 'HEAD^']);
    return 'HEAD^...HEAD';
  } catch {
    return '';
  }
}

function globToRegExp(pattern) {
  const source = String(pattern || '').trim().replace(/\\/g, '/');
  let out = '^';
  for (let i = 0; i < source.length; i++) {
    const ch = source[i];
    if (ch === '*') {
      if (source[i + 1] === '*') { out += '.*'; i++; }
      else out += '[^/]*';
    } else if (ch === '?') {
      out += '[^/]';
    } else {
      out += ch.replace(/[\\^$.*+?()[\]{}|]/g, '\\$&');
    }
  }
  return new RegExp(`${out}$`);
}

function sanitizeConfig(raw) {
  const cfg = raw && typeof raw === 'object' ? raw : {};
  return {
    policy: typeof cfg.policy === 'string' ? cfg.policy : undefined,
    scanScope: typeof cfg.scanScope === 'string' ? cfg.scanScope : undefined,
    excludePaths: Array.isArray(cfg.excludePaths) ? cfg.excludePaths.filter(x => typeof x === 'string') : [],
    ignoreRules: Array.isArray(cfg.ignoreRules) ? cfg.ignoreRules.filter(x => typeof x === 'string') : [],
    ignoreCategories: Array.isArray(cfg.ignoreCategories) ? cfg.ignoreCategories.filter(x => typeof x === 'string') : [],
    severityOverrides: cfg.severityOverrides && typeof cfg.severityOverrides === 'object' ? cfg.severityOverrides : {},
    maxFileBytes: Number.isFinite(Number(cfg.maxFileBytes)) ? Number(cfg.maxFileBytes) : undefined,
    inlineSuppressions: typeof cfg.inlineSuppressions === 'boolean' ? cfg.inlineSuppressions : undefined
  };
}

function loadConfig() {
  const rel = input('INPUT_CONFIG_FILE', '.devshield.json').trim();
  if (!rel || !safeRelative(rel)) return { config: sanitizeConfig({}), path: '' };
  const abs = path.join(workspace, rel);
  if (!fs.existsSync(abs)) return { config: sanitizeConfig({}), path: rel };
  try {
    return { config: sanitizeConfig(JSON.parse(fs.readFileSync(abs, 'utf8'))), path: rel };
  } catch (err) {
    console.log(`::warning title=DevShield config::Could not parse ${rel}: ${escapeCommand(err.message || String(err))}`);
    return { config: sanitizeConfig({}), path: rel };
  }
}

const loadedConfig = loadConfig();
const config = loadedConfig.config;
const maxFiles = clampInt(input('INPUT_MAX_FILES', '120'), 1, 500, 120);
const maxFileBytes = clampInt(
  nonEmptyInput('INPUT_MAX_FILE_BYTES', String(config.maxFileBytes ?? 1_500_000)),
  10_000,
  5_000_000,
  1_500_000
);
const policy = normalizePolicy(nonEmptyInput('INPUT_POLICY', config.policy || 'balanced'));
const scanScope = normalizeScanScope(nonEmptyInput('INPUT_SCAN_SCOPE', config.scanScope || 'changed-lines'));
const inlineSuppressions = parseBool(nonEmptyInput('INPUT_INLINE_SUPPRESSIONS', String(config.inlineSuppressions ?? true)), true);
const excludePaths = [
  ...config.excludePaths,
  ...input('INPUT_EXCLUDE_PATHS', '').split(',').map(s => s.trim()).filter(Boolean)
].map(s => s.replace(/\\/g, '/'));
const excludeMatchers = excludePaths.map(globToRegExp);
const ignoreRules = new Set(config.ignoreRules);
const ignoreCategories = new Set(config.ignoreCategories);
const severityOverrides = config.severityOverrides || {};
const failOn = input('INPUT_FAIL_ON', 'critical').toLowerCase();
const shouldComment = parseBool(input('INPUT_COMMENT', 'true'), true);
const token = input('INPUT_GITHUB_TOKEN') || process.env.GITHUB_TOKEN || '';
const openRouterKey = input('INPUT_OPENROUTER_API_KEY');
const model = input('INPUT_MODEL', 'openrouter/auto');
const writeSarif = parseBool(input('INPUT_SARIF', 'true'), true);
const reportDir = safeReportDir(input('INPUT_REPORT_DIR', '.devshield'));
const outputFile = process.env.GITHUB_OUTPUT;
const summaryFile = process.env.GITHUB_STEP_SUMMARY;

function normalizePolicy(value) {
  const v = String(value || '').toLowerCase();
  return ['balanced', 'strict', 'secrets-only'].includes(v) ? v : 'balanced';
}

function normalizeScanScope(value) {
  const v = String(value || '').toLowerCase();
  return ['changed-lines', 'changed-files', 'repository'].includes(v) ? v : 'changed-lines';
}

function safeReportDir(value) {
  const rel = String(value || '').trim() || '.devshield';
  return safeRelative(rel) ? rel : '.devshield';
}

function isExcluded(rel) {
  const normalized = rel.replace(/\\/g, '/');
  return excludeMatchers.some(re => re.test(normalized));
}

function isDocumentationFile(file) {
  return /\.(?:md|mdx|rst|txt|adoc)$/i.test(file);
}

function isTextCandidate(file) {
  const normalized = file.replace(/\\/g, '/');
  const base = path.basename(normalized);
  if (/^(package-lock\.json|pnpm-lock\.yaml|yarn\.lock|bun\.lockb)$/i.test(base)) return false;
  if (/\.(png|jpe?g|gif|webp|ico|pdf|zip|gz|tar|7z|woff2?|ttf|eot|mp3|wav|mp4|mov|avi|mkv|lock)$/i.test(normalized)) return false;
  if (/(^|\/)(node_modules|dist|build|coverage|vendor|\.git)\//.test(normalized)) return false;
  return true;
}

function listChangedFiles() {
  const range = getDiffRange();
  let text = '';
  try {
    text = range ? git(['diff', '--name-only', '--diff-filter=ACMRTUXB', range]) : git(['ls-files']);
  } catch {
    try { text = git(['ls-files']); } catch { return []; }
  }
  return text.split(/\r?\n/)
    .map(s => s.trim())
    .filter(Boolean)
    .filter(safeRelative)
    .filter(rel => !isExcluded(rel))
    .filter(isTextCandidate)
    .slice(0, maxFiles);
