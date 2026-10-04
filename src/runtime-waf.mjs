import crypto from 'node:crypto';
import { normalizeWaapPolicy, normalizeWaapRoute, pathMatchesRoute } from './waap.mjs';

export const DEFAULT_WAF_POLICY = Object.freeze({
  mode: 'observe',
  blockScore: 70,
  inspectBodyBytes: 65536,
  maxBodyBytes: 1048576,
  allowedOrigins: [],
  trustedBots: [],
  blockedCountries: [],
  rateLimit: {
    enabled: true,
    requests: 120,
    windowSeconds: 60,
    key: 'ip'
  },
  routes: []
});

const RULES = [
  {
    id: 'path-traversal',
    category: 'path',
    weight: 60,
    test: value => /(?:\.\.[/\\]|%2e%2e(?:%2f|%5c)|%252e%252e)/i.test(value),
    message: 'Path traversal pattern detected'
  },
  {
    id: 'sql-injection',
    category: 'injection',
    weight: 60,
    test: value => /(?:\bunion\s+(?:all\s+)?select\b|\bor\s+1\s*=\s*1\b|\bsleep\s*\(\s*\d+\s*\)|\bbenchmark\s*\(|;\s*(?:drop|alter|truncate)\s+(?:table|database)\b)/i.test(value),
    message: 'SQL injection-shaped pattern detected'
  },
  {
    id: 'xss',
    category: 'injection',
    weight: 55,
    test: value => /(?:<\s*script\b|javascript\s*:|on(?:error|load|click|mouseover)\s*=|<\s*svg\b[^>]*\bonload\s*=)/i.test(value),
    message: 'Cross-site scripting-shaped pattern detected'
  },
  {
    id: 'command-injection',
    category: 'injection',
    weight: 70,
    test: value => /(?:\$\([^)]{1,160}\)|(?:^|[\s;&|])(?:curl|wget|nc|bash|sh|powershell)\s+[^&|;\n]{1,200}(?:[;&|]|$))/i.test(value),
    message: 'Command injection-shaped pattern detected'
  },
  {
    id: 'template-injection',
    category: 'injection',
    weight: 35,
    test: value => /(?:\{\{\s*[^}]{1,120}\s*\}\}|\$\{\s*[^}]{1,120}\s*\})/.test(value),
    message: 'Server-side template injection-shaped pattern detected'
  },
  {
    id: 'null-byte',
    category: 'protocol',
    weight: 70,
    test: value => /(?:%00|\u0000)/i.test(value),
    message: 'Null-byte pattern detected'
  }
];

const SCANNER_UA = /\b(?:sqlmap|nikto|nmap|masscan|acunetix|nessus|dirbuster|gobuster|wpscan|zgrab)\b/i;

function cleanMode(value) {
  return ['observe', 'block'].includes(String(value || '').toLowerCase())
    ? String(value).toLowerCase()
    : 'observe';
}

function clampNumber(value, min, max, fallback) {
  const n = Number(value);
  return Number.isFinite(n) ? Math.max(min, Math.min(max, n)) : fallback;
}

function normalizeRoute(route) {
  return {
    id: String(route?.id || crypto.randomUUID()),
    pathPrefix: String(route?.pathPrefix || '/'),
    methods: Array.isArray(route?.methods) ? route.methods.map(v => String(v).toUpperCase()) : [],
    requireAuth: Boolean(route?.requireAuth),
    maxBodyBytes: route?.maxBodyBytes == null ? null : clampNumber(route.maxBodyBytes, 0, 10000000, null),
    rateLimit: route?.rateLimit && typeof route.rateLimit === 'object'
      ? {
          enabled: route.rateLimit.enabled !== false,
          requests: clampNumber(route.rateLimit.requests, 1, 100000, 60),
          windowSeconds: clampNumber(route.rateLimit.windowSeconds, 1, 86400, 60),
          key: ['ip', 'ip-path'].includes(route.rateLimit.key) ? route.rateLimit.key : 'ip'
        }
      : null,
    webhook: route?.webhook && typeof route.webhook === 'object'
      ? {
          header: String(route.webhook.header || 'x-devshield-signature').toLowerCase(),
          algorithm: ['SHA-256', 'SHA-512'].includes(route.webhook.algorithm) ? route.webhook.algorithm : 'SHA-256',
          secretEnv: String(route.webhook.secretEnv || ''),
          encoding: route.webhook.encoding === 'base64' ? 'base64' : 'hex'
        }
      : null,
    ...normalizeWaapRoute(route)
  };
}

export function normalizeWafPolicy(input = {}) {
  const policy = input && typeof input === 'object' ? input : {};
  const rate = policy.rateLimit && typeof policy.rateLimit === 'object' ? policy.rateLimit : DEFAULT_WAF_POLICY.rateLimit;

  return {
    mode: cleanMode(policy.mode),
    blockScore: clampNumber(policy.blockScore, 1, 100, DEFAULT_WAF_POLICY.blockScore),
    inspectBodyBytes: clampNumber(policy.inspectBodyBytes, 0, 262144, DEFAULT_WAF_POLICY.inspectBodyBytes),
    maxBodyBytes: clampNumber(policy.maxBodyBytes, 0, 10000000, DEFAULT_WAF_POLICY.maxBodyBytes),
    allowedOrigins: Array.isArray(policy.allowedOrigins)
      ? policy.allowedOrigins.map(v => String(v).trim()).filter(Boolean)
      : [],
    trustedBots: Array.isArray(policy.trustedBots)
      ? policy.trustedBots.map(v => String(v).trim().toLowerCase()).filter(Boolean)
      : [],
    blockedCountries: Array.isArray(policy.blockedCountries)
      ? policy.blockedCountries.map(v => String(v).trim().toUpperCase()).filter(Boolean)
      : [],
    rateLimit: {
      enabled: rate.enabled !== false,
      requests: clampNumber(rate.requests, 1, 100000, DEFAULT_WAF_POLICY.rateLimit.requests),
      windowSeconds: clampNumber(rate.windowSeconds, 1, 86400, DEFAULT_WAF_POLICY.rateLimit.windowSeconds),
      key: ['ip', 'ip-path'].includes(rate.key) ? rate.key : DEFAULT_WAF_POLICY.rateLimit.key
    },
    waap: normalizeWaapPolicy(policy.waap || {}),
    routes: Array.isArray(policy.routes) ? policy.routes.map(normalizeRoute) : []
  };
}

export function policyFromEnvironment(env = {}) {
  let parsed = {};
  if (env.WAF_POLICY_JSON) {
    try {
      parsed = JSON.parse(String(env.WAF_POLICY_JSON));
    } catch {
      parsed = {};
    }
  }

  const policy = normalizeWafPolicy(parsed);
  if (env.WAF_MODE) policy.mode = cleanMode(env.WAF_MODE);
  if (env.WAF_BLOCK_SCORE) policy.blockScore = clampNumber(env.WAF_BLOCK_SCORE, 1, 100, policy.blockScore);
  if (env.WAF_ALLOWED_ORIGINS) {
    policy.allowedOrigins = String(env.WAF_ALLOWED_ORIGINS).split(',').map(v => v.trim()).filter(Boolean);
  }
  if (env.WAAP_POLICY_JSON) {
    try {
      policy.waap = normalizeWaapPolicy(JSON.parse(String(env.WAAP_POLICY_JSON)));
    } catch {}
  }
  return policy;
}

export function routePolicyFor(url, method, policy) {
  const pathname = new URL(url).pathname;
  const candidates = policy.routes
    .filter(route => pathMatchesRoute(pathname, route))
    .sort((a, b) => {
      const left = String(a.pathTemplate || a.pathPrefix || '/').length;
      const right = String(b.pathTemplate || b.pathPrefix || '/').length;
      return right - left;
    });

  const route = candidates[0] || null;
  if (!route) return null;
  if (route.methods.length && !route.methods.includes(String(method).toUpperCase())) return route;
  return route;
}

function bearerAlgNone(authorization) {
  const value = String(authorization || '');
  if (!value.toLowerCase().startsWith('bearer ')) return false;
  const token = value.slice(7).trim();
  const [header] = token.split('.');
  if (!header) return false;

  try {
    const normalized = header.replace(/-/g, '+').replace(/_/g, '/');
    const padded = normalized + '='.repeat((4 - normalized.length % 4) % 4);
    const json = typeof atob === 'function'
      ? atob(padded)
      : Buffer.from(padded, 'base64').toString('utf8');
    return String(JSON.parse(json).alg || '').toLowerCase() === 'none';
  } catch {
    return false;
  }
}

function requestOriginAllowed(origin, allowedOrigins) {
  if (!origin || !allowedOrigins.length) return true;
  return allowedOrigins.includes(origin);
}

function countryFromRequest(request) {
  return String(request.cf?.country || request.headers.get('cf-ipcountry') || '').toUpperCase();
}

function clientIp(request) {
  return String(
    request.headers.get('cf-connecting-ip')
      || request.headers.get('x-forwarded-for')
      || 'unknown'
  ).split(',')[0].trim();
}

function requestId(request) {
  return request.headers.get('cf-ray') || crypto.randomUUID();
}

function contentLength(request) {
  const value = request.headers.get('content-length');
  if (!value) return null;
  const n = Number(value);
  return Number.isFinite(n) && n >= 0 ? n : null;
}

export function inspectRequestMetadata(request, policy, route = null) {
  const reasons = [];
  let score = 0;
  const method = request.method.toUpperCase();
  const url = new URL(request.url);
  const userAgent = request.headers.get('user-agent') || '';
  const origin = request.headers.get('origin') || '';
  const authorization = request.headers.get('authorization') || '';

  if (SCANNER_UA.test(userAgent) && !policy.trustedBots.some(bot => userAgent.toLowerCase().includes(bot))) {
    reasons.push({ rule: 'scanner-user-agent', category: 'bot', weight: 45, message: 'Known scanner user-agent detected' });
    score += 45;
  }

  if (!requestOriginAllowed(origin, policy.allowedOrigins)) {
    reasons.push({ rule: 'origin-not-allowed', category: 'origin', weight: 80, message: 'Browser origin is not allowlisted' });
    score += 80;
  }

  const country = countryFromRequest(request);
  if (country && policy.blockedCountries.includes(country)) {
    reasons.push({ rule: 'country-block', category: 'geo', weight: 100, message: 'Request country is blocked by policy' });
    score += 100;
  }

  if (bearerAlgNone(authorization)) {
    reasons.push({ rule: 'jwt-none-algorithm', category: 'auth', weight: 100, message: 'Bearer token declares JWT alg none' });
    score += 100;
  }

  if (route) {
    if (route.methods.length && !route.methods.includes(method)) {
      reasons.push({ rule: 'method-not-allowed', category: 'route', weight: 100, message: 'HTTP method is not allowed for this route' });
      score += 100;
    }

    if (route.requireAuth && !authorization) {
      reasons.push({ rule: 'missing-auth', category: 'auth', weight: 100, message: 'Authorization is required for this route' });
      score += 100;
    }
  }

  const maxBody = route?.maxBodyBytes ?? policy.maxBodyBytes;
  const length = contentLength(request);
  if (length != null && maxBody > 0 && length > maxBody) {
    reasons.push({ rule: 'body-too-large', category: 'protocol', weight: 100, message: 'Request body exceeds the configured maximum' });
    score += 100;
  }

  if (request.headers.has('x-http-method-override')) {
    reasons.push({ rule: 'method-override', category: 'protocol', weight: 20, message: 'HTTP method override header observed' });
    score += 20;
  }

  const metadataText = [url.pathname, url.search, userAgent].join('\n');
  for (const rule of RULES) {
    if (rule.test(metadataText)) {
      reasons.push({ rule: rule.id, category: rule.category, weight: rule.weight, message: rule.message });
      score += rule.weight;
    }
  }

  return {
    score: Math.min(100, score),
    reasons,
    requestId: requestId(request),
    method,
    path: url.pathname,
    ip: clientIp(request),
    country,
    userAgent: userAgent.slice(0, 240)
  };
}

export function inspectBodyText(text) {
  const reasons = [];
  let score = 0;
  const value = String(text || '');

  for (const rule of RULES) {
    if (rule.test(value)) {
      reasons.push({ rule: rule.id, category: rule.category, weight: rule.weight, message: rule.message });
      score += rule.weight;
    }
  }

  return { score: Math.min(100, score), reasons };
}

export function combineInspection(metadata, body) {
  const reasons = [...(metadata?.reasons || []), ...(body?.reasons || [])];
  const seen = new Set();
  const deduped = [];

  for (const reason of reasons) {
    const key = reason.rule + ':' + reason.message;
    if (seen.has(key)) continue;
    seen.add(key);
    deduped.push(reason);
  }

  const score = Math.min(
    100,
    deduped.reduce((sum, item) => sum + Number(item.weight || 0), 0)
  );

  return { ...metadata, score, reasons: deduped };
}

export function decideWafAction(inspection, policy) {
  const blocked = inspection.score >= policy.blockScore;
  if (policy.mode === 'block' && blocked) return 'block';
  return blocked ? 'observe-high-risk' : 'allow';
}

export function rateLimitDescriptor(request, policy, route = null) {
  const config = route?.rateLimit || policy.rateLimit;
  if (!config?.enabled) return null;

  const url = new URL(request.url);
  const ip = clientIp(request);
  const suffix = config.key === 'ip-path' ? ':' + url.pathname : '';
  return {
    key: 'devshield:waf:rate:' + ip + suffix,
    requests: config.requests,
    windowSeconds: config.windowSeconds
  };
}

export function safeLogEvent(inspection, action, extra = {}) {
  return {
    ts: new Date().toISOString(),
    component: 'devshield-runtime-waf',
    action,
    requestId: inspection.requestId,
    method: inspection.method,
    path: inspection.path,
    country: inspection.country || null,
    score: inspection.score,
    rules: inspection.reasons.map(item => item.rule),
    ...extra
  };
}

export async function verifyWebhookSignature(rawBody, signature, secret, options = {}) {
  if (!secret || !signature) return false;

  const algorithm = options.algorithm === 'SHA-512' ? 'SHA-512' : 'SHA-256';
  const encoding = options.encoding === 'base64' ? 'base64' : 'hex';
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(String(secret)),
    { name: 'HMAC', hash: algorithm },
    false,
    ['sign']
  );

  const bytes = new Uint8Array(
    await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(String(rawBody)))
  );

  const expected = encoding === 'base64'
    ? bytesToBase64(bytes)
    : [...bytes].map(b => b.toString(16).padStart(2, '0')).join('');

  return constantTimeEqual(expected, String(signature).trim());
}

function bytesToBase64(bytes) {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  if (typeof btoa === 'function') return btoa(binary);
  return Buffer.from(binary, 'binary').toString('base64');
}

function constantTimeEqual(a, b) {
  const left = new TextEncoder().encode(String(a));
  const right = new TextEncoder().encode(String(b));
  if (left.length !== right.length) return false;

  let diff = 0;
  for (let i = 0; i < left.length; i++) diff |= left[i] ^ right[i];
  return diff === 0;
}
