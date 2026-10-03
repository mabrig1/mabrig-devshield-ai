function issue(id, severity, message, cwe, remediation, line = 1, extra = {}) {
  return { id, severity, category: 'web-security', message, cwe, remediation, line, ...extra };
}

function sourceLine(content, re) {
  const lines = String(content || '').split(/\r?\n/);
  const index = lines.findIndex(line => re.test(line));
  return index >= 0 ? index + 1 : 1;
}

const HIGH_VALUE_PATH = /(?:^|\/)(?:api\/)?(?:auth|login|signin|sign-in|signup|sign-up|register|password|forgot|reset|admin|checkout|payment|payments|billing|contact|forms?)(?:\/|\.|$)/i;
const SOURCE_FILE = /\.(?:[cm]?[jt]sx?)$/i;

function hasPostHandler(content) {
  return /\bexport\s+(?:async\s+)?function\s+POST\b|\b(?:app|router|server|fastify)\s*\.\s*post\s*\(/i.test(content);
}

function hasAbuseGuard(content) {
  return /\brate\s*[-_]?\s*limit(?:er|ing)?\b|\brateLimit\b|\blimiter\b|@upstash\/ratelimit|express-rate-limit|rate-limiter-flexible|\bslowDown\b|turnstile|recaptcha|hcaptcha|cf-turnstile|bot.?management|too many requests|\b429\b/i.test(content);
}

function hasInMemoryCounter(content) {
  return /\bnew\s+Map\s*\(|\bnew\s+Set\s*\(|\b(?:requests|attempts|hits|rateLimits?|counters?)\s*=\s*\{\s*\}/i.test(content);
}

export function scanEdgeAbuseShield(rel, content) {
  const normalized = String(rel || '').replace(/\\/g, '/');
  const text = String(content || '');
  const findings = [];

  if (SOURCE_FILE.test(normalized) && HIGH_VALUE_PATH.test(normalized) && hasPostHandler(text)) {
    if (!hasAbuseGuard(text)) {
      findings.push(issue(
        'high-value-route-no-abuse-guard',
        'medium',
        'A high-value POST route has no in-file rate-limit or bot-challenge signal. Edge/WAF controls may exist outside the repository and should be verified.',
        'CWE-770',
        'Add or verify layered abuse controls: per-identity/IP rate limiting, bot/challenge protection for suspicious traffic, and edge/WAF rules for the route. Keep application-side limits even when an edge provider is present.',
        sourceLine(text, /\bPOST\b|\.post\s*\(/i),
        { confidence: 'medium' }
      ));
    }

    if (hasAbuseGuard(text) && hasInMemoryCounter(text)) {
      findings.push(issue(
        'serverless-in-memory-rate-limit',
        'medium',
        'A high-value route appears to keep rate-limit state in process memory, which can reset or fragment across serverless/cluster instances.',
        'CWE-770',
        'Use a shared atomic store or provider-native rate limiter for distributed enforcement; keep local counters only as a secondary optimization.',
        sourceLine(text, /new\s+(?:Map|Set)\s*\(|(?:requests|attempts|hits|rateLimits?|counters?)\s*=\s*\{/i),
        { confidence: 'high' }
      ));
    }
  }

  const usesLimiter = hasAbuseGuard(text);
  const xffLine = sourceLine(text, /x-forwarded-for/i);
  if (SOURCE_FILE.test(normalized) && usesLimiter && /x-forwarded-for/i.test(text)) {
    const trustsProxy = /\btrust\s+proxy\b|\btrustedProx(?:y|ies)\b|\bproxyTrust\b|\btrustedHop\b/i.test(text);
    if (!trustsProxy) {
      findings.push(issue(
        'spoofable-forwarded-ip-rate-limit',
        'high',
        'Rate-limit logic references X-Forwarded-For without an observable trusted-proxy boundary in this file, so a client-controlled value may influence the limiter key.',
        'CWE-441',
        'Derive client identity only from a trusted reverse-proxy boundary. Configure trusted proxy hops explicitly, normalize the provider-authenticated client IP, and reject/ignore untrusted forwarded headers.',
        xffLine,
        { confidence: 'medium' }
      ));
    }
  }

  if (SOURCE_FILE.test(normalized) && /['"]use client['"]/.test(text) &&
      /process\.env\.(?:TURNSTILE|RECAPTCHA|HCAPTCHA)_[A-Z0-9_]*(?:SECRET|PRIVATE|TOKEN)/i.test(text)) {
    findings.push(issue(
      'client-bot-secret-reference',
      'critical',
      'Client-side code references a bot-challenge secret/private/token environment variable.',
      'CWE-200',
      'Keep bot-verification secrets server-only. Expose only the public site key to the browser and perform challenge verification on the server.',
      sourceLine(text, /process\.env\.(?:TURNSTILE|RECAPTCHA|HCAPTCHA)_/i),
      { confidence: 'high' }
    ));
  }

  return findings;
}
