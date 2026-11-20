// Offline, dependency-free analysis of operator-supplied aggregate incident signals.
// No network, no personal identifiers, no source code, no automated remediation.
const KINDS = Object.freeze(['email', 'outbound', 'account', 'process', 'redirect']);
const ORDER = Object.freeze({ critical: 0, high: 1, medium: 2 });
const RULES = Object.freeze({
  'email-volume-spike': ['high', 'Outgoing email volume greatly exceeds its documented baseline', 'Verify provider logs, sending endpoints, and credential use; enforce rate limits.'],
  'email-unexpected-sender': ['high', 'An unrecognised sending identity was reported', 'Review sender domains and API keys; rotate credentials if exposure is confirmed.'],
  'outbound-unapproved-transfer': ['high', 'Large outbound transfer to an unapproved destination', 'Verify outbound integration ownership and investigate potential data exports.'],
  'outbound-unapproved-connection': ['medium', 'Outbound connection to an unapproved destination', 'Validate the destination against approved integrations and egress policy.'],
  'account-unrecognized-activity': ['high', 'User-reported unknown account or payment activity', 'Review authentication/session history and payment provider events before responding.'],
  'process-unapproved-high-cpu': ['high', 'Unapproved process with high CPU use', 'Review executable path, owner, parent process, and deployment history; preserve evidence.'],
  'process-unapproved': ['medium', 'Unapproved process observed', 'Inspect process ownership, origin, startup configuration, and related connections.'],
  'redirect-host-mismatch': ['high', 'Observed redirect host differs from approved destination', 'Check DNS, routing, front-end scripts, and hosting changes across devices.']
});
const isRecord = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const has = (value, key) => Object.prototype.hasOwnProperty.call(value, key);
const number = value => typeof value === 'number' && Number.isFinite(value) && value >= 0;
const boolean = value => typeof value === 'boolean';
function host(value) {
  if (typeof value !== 'string' || value.length > 253 ||
      !/^[a-z0-9.-]+$/i.test(value) || value.includes('..') ||
      value.startsWith('.') || value.endsWith('.')) return null;
  return value.toLowerCase();
}
function eventRule(event) {
  switch (event.kind) {
    case 'email':
      if (event.unexpectedSender === true) return 'email-unexpected-sender';
      if (number(event.dailySent) && number(event.baselineDailySent) &&
          event.baselineDailySent >= 20 && event.dailySent >= 100 &&
          event.dailySent >= event.baselineDailySent * 5) return 'email-volume-spike';
      return null;
    case 'outbound':
      if (event.approved === false && number(event.bytesOut)) {
        return event.bytesOut >= 1048576 ? 'outbound-unapproved-transfer' : 'outbound-unapproved-connection';
      }
      return null;
    case 'account':
      return event.userReportedUnknownChange === true ||
        event.unrecognizedSession === true || event.unknownTransaction === true
        ? 'account-unrecognized-activity' : null;
    case 'process':
      if (event.approved === false && number(event.cpuPercent)) {
        return event.cpuPercent >= 60 ? 'process-unapproved-high-cpu' : 'process-unapproved';
      }
      return null;
    case 'redirect':
      return null; // Redirects need their policy context; processed below.
    default: return null;
  }
}
function hasAssessableEvidence(event) {
  switch (event.kind) {
    case 'email': return boolean(event.unexpectedSender) ||
      (number(event.dailySent) && number(event.baselineDailySent) && event.baselineDailySent >= 20);
    case 'outbound': return boolean(event.approved) && number(event.bytesOut);
    case 'account': return boolean(event.userReportedUnknownChange) ||
      boolean(event.unrecognizedSession) || boolean(event.unknownTransaction);
    case 'process': return boolean(event.approved) && number(event.cpuPercent);
    case 'redirect': return Boolean(host(event.expectedHost) && host(event.observedHost));
    default: return false;
  }
}
export function analyzeIncidentSignals(input) {
  if (!isRecord(input) || input.version !== 1 || !Array.isArray(input.events) ||
      input.events.length > 5000) {
    throw new Error('Expected version 1 JSON object with an events array (maximum 5000).');
  }
  if (input.approvedRedirectHosts !== undefined &&
      (!Array.isArray(input.approvedRedirectHosts) || input.approvedRedirectHosts.length > 100 ||
       input.approvedRedirectHosts.some(value => !host(value)))) {
    throw new Error('approvedRedirectHosts must contain at most 100 valid hostnames.');
  }
  const redirects = new Set((input.approvedRedirectHosts || []).map(host));
  const covered = new Set(), assessed = new Set(), tally = new Map();
  for (const event of input.events) {
    if (!isRecord(event) || !KINDS.includes(event.kind)) {
      throw new Error('Each event must be an object with a supported kind.');
    }
    covered.add(event.kind);
    if (hasAssessableEvidence(event)) assessed.add(event.kind);
    let id = eventRule(event);
    if (event.kind === 'redirect') {
      const expected = host(event.expectedHost);
      const observed = host(event.observedHost);
      if (expected && observed && expected !== observed && !redirects.has(observed)) {
        id = 'redirect-host-mismatch';
      }
    }
    if (id) tally.set(id, (tally.get(id) || 0) + 1);
  }
  const findings = [...tally.entries()].map(([rule, count]) => ({
    rule, severity: RULES[rule][0], count, summary: RULES[rule][1],
    nextAction: RULES[rule][2], confidence: 'indicator-only'
  })).sort((a, b) => ORDER[a.severity] - ORDER[b.severity] || a.rule.localeCompare(b.rule));
  const unassessed = KINDS.filter(kind => !assessed.has(kind));
  return {
    schemaVersion: 1,
    mode: 'read-only',
    assessment: findings.length ? 'requires-review' :
      unassessed.length ? 'insufficient-evidence' : 'no-alerts-in-supplied-data',
    totalEvents: input.events.length,
    coveredKinds: KINDS.filter(kind => covered.has(kind)),
    unassessedKinds: unassessed,
    findings,
    caveat: 'Indicators are not proof of compromise. Missing or untrusted telemetry cannot establish safety.'
  };
}
