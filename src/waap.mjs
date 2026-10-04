import crypto from 'node:crypto';

function clampNumber(value, min, max, fallback) {
  const n = Number(value);
  return Number.isFinite(n) ? Math.max(min, Math.min(max, n)) : fallback;
}

function stringArray(value) {
  return Array.isArray(value) ? value.map(v => String(v)).filter(Boolean) : [];
}

function normalizeFieldRule(rule = {}) {
  return {
    type: ['string','number','integer','boolean','array','object'].includes(rule.type) ? rule.type : null,
    required: Boolean(rule.required),
    maxLength: rule.maxLength == null ? null : clampNumber(rule.maxLength, 0, 1000000, null),
    min: rule.min == null ? null : Number(rule.min),
    max: rule.max == null ? null : Number(rule.max),
    enum: Array.isArray(rule.enum) ? rule.enum : null
  };
}

function normalizeRequestSchema(schema) {
  if (!schema || typeof schema !== 'object') return null;
  const fields = {};
  for (const [name, rule] of Object.entries(schema.fields || {})) {
    fields[String(name)] = normalizeFieldRule(rule);
  }
  return {
    requiredFields: stringArray(schema.requiredFields),
    allowedFields: stringArray(schema.allowedFields),
    rejectUnknownFields: schema.rejectUnknownFields === true,
    maxFields: clampNumber(schema.maxFields, 1, 10000, 100),
    fields
  };
}

function normalizeGraphql(config) {
  if (!config || typeof config !== 'object') return null;
  return {
    enabled: config.enabled !== false,
    allowIntrospection: config.allowIntrospection === true,
    maxDepth: clampNumber(config.maxDepth, 1, 100, 10),
    maxAliases: clampNumber(config.maxAliases, 0, 10000, 20),
    maxQueryBytes: clampNumber(config.maxQueryBytes, 256, 1000000, 65536)
  };
}

function normalizeResponseInspection(config) {
  if (!config || typeof config !== 'object') return null;
  return {
    enabled: config.enabled !== false,
    inspectJson: config.inspectJson !== false,
    maxBytes: clampNumber(config.maxBytes, 256, 1000000, 131072),
    blockOnSecrets: config.blockOnSecrets === true,
    redactHeaders: stringArray(config.redactHeaders).map(v => v.toLowerCase())
  };
}

export function normalizeWaapPolicy(input = {}) {
  const policy = input && typeof input === 'object' ? input : {};
  return {
    apiDiscovery: {
      enabled: policy.apiDiscovery?.enabled !== false,
      apiPrefixes: stringArray(policy.apiDiscovery?.apiPrefixes).length
        ? stringArray(policy.apiDiscovery.apiPrefixes)
        : ['/api/','/graphql'],
      unknownAction: ['observe','block'].includes(policy.apiDiscovery?.unknownAction)
        ? policy.apiDiscovery.unknownAction
        : 'observe',
      excludePrefixes: stringArray(policy.apiDiscovery?.excludePrefixes)
    },
    parameterPollution: {
      enabled: policy.parameterPollution?.enabled !== false,
      action: ['observe','block'].includes(policy.parameterPollution?.action)
        ? policy.parameterPollution.action
        : 'observe',
      allowDuplicateKeys: stringArray(policy.parameterPollution?.allowDuplicateKeys)
    },
    apiVersions: {
      allowed: stringArray(policy.apiVersions?.allowed),
      header: String(policy.apiVersions?.header || 'x-api-version').toLowerCase(),
      action: ['observe','block'].includes(policy.apiVersions?.action)
        ? policy.apiVersions.action
        : 'observe'
    },
    graphql: normalizeGraphql(policy.graphql),
    responseInspection: normalizeResponseInspection(policy.responseInspection)
  };
}

export function normalizeWaapRoute(route = {}) {
  return {
    pathTemplate: route.pathTemplate ? String(route.pathTemplate) : null,
    requestContentTypes: stringArray(route.requestContentTypes).map(v => v.toLowerCase()),
    requestSchema: normalizeRequestSchema(route.requestSchema),
    graphql: normalizeGraphql(route.graphql),
    responseInspection: normalizeResponseInspection(route.responseInspection),
    authAbuse: route.authAbuse && typeof route.authAbuse === 'object'
      ? {
          enabled: route.authAbuse.enabled !== false,
          failures: clampNumber(route.authAbuse.failures, 1, 1000, 10),
          windowSeconds: clampNumber(route.authAbuse.windowSeconds, 10, 86400, 300),
          statuses: Array.isArray(route.authAbuse.statuses)
            ? route.authAbuse.statuses.map(Number).filter(v => Number.isInteger(v) && v >= 400 && v <= 499)
            : [401, 403]
        }
      : null,
    apiVersionRequired: route.apiVersionRequired === true,
    requiredHeaders: stringArray(route.requiredHeaders).map(v => v.toLowerCase())
  };
}

export function pathMatchesRoute(pathname, route) {
  if (route?.pathTemplate) {
    const actual = String(pathname || '').split('/').filter(Boolean);
    const expected = String(route.pathTemplate).split('/').filter(Boolean);
    if (actual.length !== expected.length) return false;

    for (let i = 0; i < expected.length; i++) {
      const segment = expected[i];
      if (segment.startsWith('{') && segment.endsWith('}')) continue;
      if (segment !== actual[i]) return false;
    }
    return true;
  }

  const prefix = String(route?.pathPrefix || '/');
  return String(pathname || '').startsWith(prefix);
}

export function apiRouteKnown(url, routes = []) {
  const pathname = new URL(url).pathname;
  return routes.some(route => pathMatchesRoute(pathname, route));
}

function isApiPath(url, waap) {
  const pathname = new URL(url).pathname;
  if (waap.apiDiscovery.excludePrefixes.some(prefix => pathname.startsWith(prefix))) return false;
  return waap.apiDiscovery.apiPrefixes.some(prefix => pathname.startsWith(prefix));
}

export function inspectApiDiscovery(request, policy, waap) {
  const reasons = [];
  if (!waap.apiDiscovery.enabled) return { reasons, block: false };

  const isApi = isApiPath(request.url, waap);
  if (!isApi) return { reasons, block: false };

  const known = apiRouteKnown(request.url, policy.routes || []);
  if (!known) {
    reasons.push({
      rule: 'waap-shadow-api',
      category: 'api-discovery',
      weight: waap.apiDiscovery.unknownAction === 'block' ? 100 : 25,
      message: 'API-like endpoint is not represented in the WAAP route inventory'
    });
    return { reasons, block: waap.apiDiscovery.unknownAction === 'block' };
  }

  return { reasons, block: false };
}

export function inspectParameterPollution(request, waap) {
  const reasons = [];
  if (!waap.parameterPollution.enabled) return { reasons, block: false };

  const url = new URL(request.url);
  const seen = new Map();

  for (const [key] of url.searchParams.entries()) {
    const count = (seen.get(key) || 0) + 1;
    seen.set(key, count);
  }

  const duplicates = [...seen.entries()]
    .filter(([key, count]) => count > 1 && !waap.parameterPollution.allowDuplicateKeys.includes(key))
    .map(([key]) => key);

  if (!duplicates.length) return { reasons, block: false };

  reasons.push({
    rule: 'waap-parameter-pollution',
    category: 'api-abuse',
    weight: waap.parameterPollution.action === 'block' ? 100 : 35,
    message: 'Duplicate query parameters detected: ' + duplicates.slice(0, 10).join(', ')
  });

  return { reasons, block: waap.parameterPollution.action === 'block' };
}

export function inspectApiVersion(request, route, waap) {
  const reasons = [];
  const value = String(request.headers.get(waap.apiVersions.header) || '').trim();

  if (route?.apiVersionRequired && !value) {
    reasons.push({
      rule: 'waap-api-version-missing',
      category: 'api-contract',
      weight: waap.apiVersions.action === 'block' ? 100 : 30,
      message: 'Required API version header is missing'
    });
    return { reasons, block: waap.apiVersions.action === 'block' };
  }

  if (value && waap.apiVersions.allowed.length && !waap.apiVersions.allowed.includes(value)) {
    reasons.push({
      rule: 'waap-api-version-not-allowed',
      category: 'api-contract',
      weight: waap.apiVersions.action === 'block' ? 100 : 45,
      message: 'API version is not allowlisted'
    });
    return { reasons, block: waap.apiVersions.action === 'block' };
  }

  return { reasons, block: false };
}

export function inspectRequiredHeaders(request, route) {
  const reasons = [];
  if (!route?.requiredHeaders?.length) return { reasons, block: false };

  const missing = route.requiredHeaders.filter(name => !request.headers.has(name));
  if (!missing.length) return { reasons, block: false };

  reasons.push({
    rule: 'waap-required-header-missing',
    category: 'api-contract',
    weight: 100,
    message: 'Required API header is missing'
  });

  return { reasons, block: true };
}

export function inspectContentType(request, route) {
  const reasons = [];
  if (!route?.requestContentTypes?.length) return { reasons, block: false };
  if (['GET','HEAD','OPTIONS'].includes(request.method.toUpperCase())) return { reasons, block: false };

  const raw = String(request.headers.get('content-type') || '').toLowerCase();
  const value = raw.split(';')[0].trim();
  if (route.requestContentTypes.includes(value)) return { reasons, block: false };

  reasons.push({
    rule: 'waap-content-type-not-allowed',
    category: 'api-contract',
    weight: 100,
    message: 'Request Content-Type is not allowed for this route'
  });
  return { reasons, block: true };
}

function valueType(value) {
  if (Array.isArray(value)) return 'array';
  if (value === null) return 'null';
  if (Number.isInteger(value)) return 'integer';
  return typeof value;
}

export function validateJsonContract(value, schema) {
  const errors = [];
  if (!schema) return errors;
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return [{ code: 'body-object-required', field: null }];
  }

  const keys = Object.keys(value);
  if (keys.length > schema.maxFields) errors.push({ code: 'too-many-fields', field: null });

  const required = new Set([
    ...schema.requiredFields,
    ...Object.entries(schema.fields).filter(([,rule]) => rule.required).map(([name]) => name)
  ]);

  for (const field of required) {
    if (!(field in value)) errors.push({ code: 'required-field-missing', field });
  }

  if (schema.rejectUnknownFields && schema.allowedFields.length) {
    for (const field of keys) {
      if (!schema.allowedFields.includes(field)) errors.push({ code: 'unknown-field', field });
    }
  }

  for (const [field, rule] of Object.entries(schema.fields)) {
    if (!(field in value)) continue;
    const current = value[field];
    const actual = valueType(current);

    if (rule.type && actual !== rule.type && !(rule.type === 'number' && actual === 'integer')) {
      errors.push({ code: 'type-mismatch', field });
      continue;
    }

    if (typeof current === 'string' && rule.maxLength != null && current.length > rule.maxLength) {
      errors.push({ code: 'string-too-long', field });
    }

    if (typeof current === 'number') {
      if (Number.isFinite(rule.min) && current < rule.min) errors.push({ code: 'number-below-min', field });
      if (Number.isFinite(rule.max) && current > rule.max) errors.push({ code: 'number-above-max', field });
    }

    if (rule.enum && !rule.enum.includes(current)) errors.push({ code: 'enum-not-allowed', field });
  }

  return errors.slice(0, 50);
}

export function inspectJsonRequest(text, route) {
  const reasons = [];
  if (!route?.requestSchema) return { reasons, block: false, errors: [] };

  let parsed;
  try {
    parsed = JSON.parse(String(text || ''));
  } catch {
    reasons.push({
      rule: 'waap-json-invalid',
      category: 'api-contract',
      weight: 100,
      message: 'JSON request body is invalid'
    });
    return { reasons, block: true, errors: [{ code: 'invalid-json', field: null }] };
  }

  const errors = validateJsonContract(parsed, route.requestSchema);
  if (!errors.length) return { reasons, block: false, errors: [] };

  reasons.push({
    rule: 'waap-json-contract-violation',
    category: 'api-contract',
    weight: 100,
    message: 'JSON request violates the configured API contract'
  });

  return { reasons, block: true, errors };
}

function stripGraphqlStringsAndComments(query) {
  return String(query || '')
    .replace(/"""[\s\S]*?"""/g, '""')
    .replace(/"(?:\\.|[^"\\])*"/g, '""')
    .replace(/#[^\n\r]*/g, '');
}

export function analyzeGraphql(query, config) {
  const reasons = [];
  if (!config?.enabled) return { reasons, block: false, depth: 0, aliases: 0 };

  const value = String(query || '');
  if (new TextEncoder().encode(value).byteLength > config.maxQueryBytes) {
    reasons.push({
      rule: 'waap-graphql-query-too-large',
      category: 'graphql',
      weight: 100,
      message: 'GraphQL query exceeds configured byte limit'
    });
  }

  const cleaned = stripGraphqlStringsAndComments(value);

  if (!config.allowIntrospection && /\b__(?:schema|type)\b/.test(cleaned)) {
    reasons.push({
      rule: 'waap-graphql-introspection',
      category: 'graphql',
      weight: 100,
      message: 'GraphQL introspection is disabled by policy'
    });
  }

  let depth = 0;
  let maxDepth = 0;
  for (const ch of cleaned) {
    if (ch === '{') {
      depth += 1;
      maxDepth = Math.max(maxDepth, depth);
    } else if (ch === '}') {
      depth = Math.max(0, depth - 1);
    }
  }

  if (maxDepth > config.maxDepth) {
    reasons.push({
      rule: 'waap-graphql-depth',
      category: 'graphql',
      weight: 100,
      message: 'GraphQL query depth exceeds configured maximum'
    });
  }

  const aliasMatches = cleaned.match(/\b[A-Za-z_][A-Za-z0-9_]*\s*:\s*[A-Za-z_][A-Za-z0-9_]*/g) || [];
  const aliases = aliasMatches.length;

  if (aliases > config.maxAliases) {
    reasons.push({
      rule: 'waap-graphql-aliases',
      category: 'graphql',
      weight: 100,
      message: 'GraphQL alias count exceeds configured maximum'
    });
  }

  return {
    reasons,
    block: reasons.some(item => item.weight >= 100),
    depth: maxDepth,
    aliases
  };
}

export function graphqlQueryFromRequest(text, contentType) {
  const rawType = String(contentType || '').toLowerCase();
  if (rawType.startsWith('application/graphql')) return String(text || '');

  if (rawType.startsWith('application/json')) {
    try {
      const parsed = JSON.parse(String(text || ''));
      return typeof parsed.query === 'string' ? parsed.query : '';
    } catch {
      return '';
    }
  }

  return '';
}

const SECRET_PATTERNS = [
  { id: 'private-key', re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/ },
  { id: 'aws-secret-key', re: /\b[A-Za-z0-9/+=]{40}\b/ },
  { id: 'github-token', re: /\b(?:ghp|github_pat)_[A-Za-z0-9_]{20,}\b/ },
  { id: 'stripe-secret', re: /\bsk_(?:live|test)_[A-Za-z0-9]{12,}\b/ },
  { id: 'paystack-secret', re: /\bsk_(?:live|test)_[A-Za-z0-9]{12,}\b/ },
  { id: 'jwt-like', re: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/ }
];

export function inspectResponseText(text, config) {
  const findings = [];
  if (!config?.enabled) return findings;

  const value = String(text || '');
  for (const pattern of SECRET_PATTERNS) {
    if (pattern.re.test(value)) {
      pattern.re.lastIndex = 0;
      findings.push({
        rule: 'waap-response-secret-' + pattern.id,
        category: 'data-leakage',
        message: 'Response contains a secret-like value'
      });
    }
    pattern.re.lastIndex = 0;
  }
  return findings;
}

export function safeEndpointFingerprint(request) {
  const url = new URL(request.url);
  const basis = request.method.toUpperCase() + '\0' + url.pathname;
  return crypto.createHash('sha256').update(basis).digest('hex').slice(0, 16);
}

export function endpointObservation(request, route, inspection) {
  const url = new URL(request.url);
  return {
    fingerprint: safeEndpointFingerprint(request),
    method: request.method.toUpperCase(),
    path: url.pathname,
    routeId: route?.id || null,
    known: Boolean(route),
    score: Number(inspection?.score || 0),
    ts: new Date().toISOString()
  };
}
