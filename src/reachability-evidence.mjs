import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

// Import *actual analyzer-reported* SARIF code flows. This module is not a taint solver.
// Only validated locations inside the checkout are retained; no source text is exported.
function safeLocation(raw, workspace) {
  const physical = raw?.location?.physicalLocation;
  const uri = physical?.artifactLocation?.uri;
  const line = physical?.region?.startLine;
  if (typeof uri !== 'string' || !Number.isSafeInteger(line) || line < 1 || line > 10000000) return null;
  if (uri.includes('\\') || uri.startsWith('/') || /^[a-z][a-z0-9+.-]*:/i.test(uri) || /[\x00-\x1f\x7f]/.test(uri)) return null;
  let decoded;
  try { decoded = decodeURIComponent(uri).replace(/^\.\//, ''); } catch { return null; }
  if (!decoded || decoded.includes('\\') || decoded.startsWith('/') || /[\x00-\x1f\x7f]/.test(decoded)) return null;
  const parts = decoded.split('/');
  if (parts.some(p => !p || p === '.' || p === '..') || decoded.length > 500) return null;
  const absolute = path.resolve(workspace, decoded);
  try {
    const rootReal = fs.realpathSync(workspace);
    const fileReal = fs.realpathSync(absolute);
    if (!fileReal.startsWith(rootReal + path.sep)) return null;
    const stat = fs.statSync(fileReal);
    if (!stat.isFile() || stat.size > 1_500_000) return null;
    // Checking line bounds prevents fabricated/outdated SARIF positions from being treated as evidence.
    const source = fs.readFileSync(fileReal, 'utf8');
    if (source.includes('\0') || line > source.split('\n').length) return null;
  } catch { return null; }
  return { file: decoded, line };
}

function severityFor(rule) {
  const score = Number(rule?.properties?.['security-severity']);
  if (!Number.isFinite(score) || score < 0 || score > 10) return 'unrated';
  if (score >= 9) return 'critical';
  if (score >= 7) return 'high';
  if (score >= 4) return 'medium';
  return 'low';
}

export function importReachabilitySarif(sarif, { workspace, maxFindings = 500 } = {}) {
  if (!workspace) throw new Error('workspace is required');
  if (!sarif || sarif.version !== '2.1.0' || !Array.isArray(sarif.runs)) throw new Error('SARIF 2.1.0 runs required');
  const findings = [];
  let ignored = 0;
  const seen = new Set();
  for (const run of sarif.runs.slice(0, 20)) {
    if (run?.tool?.driver?.name !== 'CodeQL') { ignored++; continue; }
    const rules = new Map((run.tool.driver.rules || []).filter(r => typeof r?.id === 'string').map(r => [r.id, r]));
    for (const result of (run.results || []).slice(0, 5000)) {
      if (findings.length >= maxFindings) break;
      if (typeof result?.ruleId !== 'string' || !/^[\w./-]{1,160}$/.test(result.ruleId)) { ignored++; continue; }
      const paths = (result.codeFlows || []).flatMap(flow => (flow.threadFlows || []).slice(0, 2));
      let emitted = false;
      for (const thread of paths.slice(0, 4)) {
        const raw = thread?.locations;
        if (!Array.isArray(raw) || raw.length < 2 || raw.length > 256) continue;
        const steps = raw.map(step => safeLocation(step, workspace));
        if (steps.some(step => !step)) continue;
        const source = steps[0];
        const sink = steps[steps.length - 1];
        if (source.file === sink.file && source.line === sink.line) continue;
        const fingerprint = crypto.createHash('sha256')
          .update([result.ruleId, source.file, source.line, sink.file, sink.line].join('\0'))
          .digest('hex').slice(0, 32);
        if (seen.has(fingerprint)) continue;
        seen.add(fingerprint);
        findings.push({
          fingerprint, rule: result.ruleId, severity: severityFor(rules.get(result.ruleId)),
          source, sink, path: steps.slice(0, 64), pathSteps: steps.length,
          evidence: 'engine-reported-code-flow', analyzer: 'CodeQL',
          // Heuristic *path evidence completeness*, NOT likelihood of exploitability.
          evidenceConfidenceScore: Math.min(90, 60 + Math.min(steps.length, 6) * 5),
          preconditions: [
            'The source is attacker-influenceable in the deployed application.',
            'The sink is executable on the relevant request or job path.',
            'No effective sanitizer, permission check, or other guard prevents exploitation.'
          ],
          remediation: 'Inspect the linked source-to-sink steps and add validation, safe APIs, authorization or sanitization at the relevant trust boundary.'
        });
        emitted = true;
        break; // First deterministic path per alert.
      }
      if (!emitted) ignored++;
    }
  }
  findings.sort((a, b) => a.fingerprint.localeCompare(b.fingerprint));
  return {
    schemaVersion: 1, state: 'external-analysis', analyzer: 'CodeQL',
    claim: 'CodeQL-reported dataflow path, not a proven reachable exploit',
    findings, summary: { findings: findings.length, skippedOrUnverified: ignored }
  };
}
