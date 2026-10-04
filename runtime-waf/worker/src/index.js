import {
  combineInspection,
  decideWafAction,
  inspectBodyText,
  inspectRequestMetadata,
  policyFromEnvironment,
  rateLimitDescriptor,
  routePolicyFor,
  safeLogEvent,
  verifyWebhookSignature
} from '../../../src/runtime-waf.mjs';
import {
  analyzeGraphql,
  endpointObservation,
  graphqlQueryFromRequest,
  inspectApiDiscovery,
  inspectApiVersion,
  inspectContentType,
  inspectJsonRequest,
  inspectParameterPollution,
  inspectRequiredHeaders,
  inspectResponseText
} from '../../../src/waap.mjs';

const memoryRate = new Map();
const memoryAuth = new Map();

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'no-store',
      'x-content-type-options': 'nosniff',
      ...headers
    }
  });
}

function appendReason(inspection, reason) {
  return combineInspection(inspection, {
    score: reason.weight,
    reasons: [reason]
  });
}

function appendReasons(inspection, check) {
  let next = inspection;
  for (const reason of check?.reasons || []) next = appendReason(next, reason);
  return next;
}

function shouldInspectBody(request, policy, route) {
  if (request.method === 'GET' || request.method === 'HEAD') return false;
  const contentType = String(request.headers.get('content-type') || '').toLowerCase();
  if (!contentType) return false;

  if (route?.requestSchema || route?.graphql || policy.waap?.graphql) return true;

  return [
    'application/json',
    'application/x-www-form-urlencoded',
    'text/',
    'application/xml',
    'application/graphql'
  ].some(prefix => contentType.startsWith(prefix));
}

async function readBodyLimited(request, limit) {
  if (!request.body || limit <= 0) return { text: '', bytes: 0, truncated: false };

  const clone = request.clone();
  const reader = clone.body.getReader();
  const chunks = [];
  let total = 0;
  let truncated = false;

  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      total += value.byteLength;

      if (total > limit) {
        const keep = value.byteLength - (total - limit);
        if (keep > 0) chunks.push(value.slice(0, keep));
        truncated = true;
        await reader.cancel();
        break;
      }

      chunks.push(value);
    }
  } finally {
    try { reader.releaseLock(); } catch {}
  }

  const size = chunks.reduce((sum, chunk) => sum + chunk.byteLength, 0);
  const merged = new Uint8Array(size);
  let offset = 0;

  for (const chunk of chunks) {
    merged.set(chunk, offset);
    offset += chunk.byteLength;
  }

  return {
    text: new TextDecoder().decode(merged),
    bytes: total,
    truncated
  };
}

async function enforceRateLimit(request, descriptor, env) {
  if (!descriptor) return { limited: false, count: 0 };

  const now = Date.now();
  const bucketMs = descriptor.windowSeconds * 1000;

  if (env.RATE_KV) {
    let current = null;

    try {
      const raw = await env.RATE_KV.get(descriptor.key);
      current = raw ? JSON.parse(raw) : null;
    } catch {}

    if (!current || now >= Number(current.reset || 0)) {
      current = { count: 0, reset: now + bucketMs };
    }

    current.count += 1;

    try {
      await env.RATE_KV.put(descriptor.key, JSON.stringify(current), {
        expirationTtl: Math.max(60, descriptor.windowSeconds + 5)
      });
    } catch {}

    return {
      limited: current.count > descriptor.requests,
      count: current.count,
      reset: current.reset
    };
  }

  let current = memoryRate.get(descriptor.key);
  if (!current || now >= current.reset) current = { count: 0, reset: now + bucketMs };
  current.count += 1;
  memoryRate.set(descriptor.key, current);

  if (memoryRate.size > 5000) {
    for (const [key, value] of memoryRate) {
      if (now >= value.reset) memoryRate.delete(key);
    }
  }

  return {
    limited: current.count > descriptor.requests,
    count: current.count,
    reset: current.reset
  };
}

async function sha256(value) {
  const bytes = new Uint8Array(
    await crypto.subtle.digest('SHA-256', new TextEncoder().encode(String(value)))
  );
  return [...bytes].map(byte => byte.toString(16).padStart(2, '0')).join('');
}

function clientIp(request) {
  return String(
    request.headers.get('cf-connecting-ip')
      || request.headers.get('x-forwarded-for')
      || 'unknown'
  ).split(',')[0].trim();
}

async function authAbuseKey(request, route) {
  const ipHash = (await sha256(clientIp(request))).slice(0, 24);
  return 'devshield:waap:auth:' + (route?.id || 'route') + ':' + ipHash;
}

async function authAbuseState(request, route, env) {
  if (!route?.authAbuse?.enabled) return { limited: false, count: 0, key: null };

  const key = await authAbuseKey(request, route);
  const now = Date.now();
  const ttlMs = route.authAbuse.windowSeconds * 1000;

  if (env.WAAP_KV) {
    let current = null;
    try {
      const raw = await env.WAAP_KV.get(key);
      current = raw ? JSON.parse(raw) : null;
    } catch {}

    if (!current || now >= Number(current.reset || 0)) current = { count: 0, reset: now + ttlMs };

    return {
      key,
      count: Number(current.count || 0),
      reset: Number(current.reset || now + ttlMs),
      limited: Number(current.count || 0) >= route.authAbuse.failures
    };
  }

  let current = memoryAuth.get(key);
  if (!current || now >= current.reset) current = { count: 0, reset: now + ttlMs };
  memoryAuth.set(key, current);

  return {
    key,
    count: current.count,
    reset: current.reset,
    limited: current.count >= route.authAbuse.failures
  };
}

async function recordAuthResult(request, route, env, status) {
  if (!route?.authAbuse?.enabled) return;

  const key = await authAbuseKey(request, route);
  const failed = route.authAbuse.statuses.includes(Number(status));
  const now = Date.now();
  const reset = now + route.authAbuse.windowSeconds * 1000;

  if (env.WAAP_KV) {
    if (!failed) {
      try { await env.WAAP_KV.delete(key); } catch {}
      return;
    }

    let current = null;
    try {
      const raw = await env.WAAP_KV.get(key);
      current = raw ? JSON.parse(raw) : null;
    } catch {}

    if (!current || now >= Number(current.reset || 0)) current = { count: 0, reset };
    current.count += 1;

    try {
      await env.WAAP_KV.put(key, JSON.stringify(current), {
        expirationTtl: Math.max(60, route.authAbuse.windowSeconds + 5)
      });
    } catch {}
    return;
  }

  if (!failed) {
    memoryAuth.delete(key);
    return;
  }

  let current = memoryAuth.get(key);
  if (!current || now >= current.reset) current = { count: 0, reset };
  current.count += 1;
  memoryAuth.set(key, current);
}

async function recordEndpoint(request, route, inspection, env) {
  const observation = endpointObservation(request, route, inspection);

  if (!env.WAAP_KV) {
    console.log(JSON.stringify({
      component: 'devshield-waap-inventory',
      ...observation
    }));
    return;
  }

  const key = 'devshield:waap:endpoint:' + observation.fingerprint;

  try {
    const raw = await env.WAAP_KV.get(key);
    const previous = raw ? JSON.parse(raw) : null;
    const next = {
      ...observation,
      firstSeen: previous?.firstSeen || observation.ts,
      lastSeen: observation.ts,
      count: Number(previous?.count || 0) + 1
    };

    await env.WAAP_KV.put(key, JSON.stringify(next));
  } catch {}
}

async function constantTimeEqualSecret(left, right) {
  const a = new TextEncoder().encode(String(left || ''));
  const b = new TextEncoder().encode(String(right || ''));
  if (a.length !== b.length) return false;

  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

async function waapInventory(request, env) {
  if (!env.WAAP_ADMIN_TOKEN || !env.WAAP_KV) {
    return json({ error: 'WAAP inventory is not configured' }, 404);
  }

  const supplied = request.headers.get('x-devshield-admin-token') || '';
  if (!(await constantTimeEqualSecret(supplied, env.WAAP_ADMIN_TOKEN))) {
    return json({ error: 'Forbidden' }, 403);
  }

  const listed = await env.WAAP_KV.list({ prefix: 'devshield:waap:endpoint:', limit: 1000 });
  const endpoints = [];

  for (const item of listed.keys || []) {
    try {
      const raw = await env.WAAP_KV.get(item.name);
      if (raw) endpoints.push(JSON.parse(raw));
    } catch {}
  }

  endpoints.sort((a, b) => String(b.lastSeen || '').localeCompare(String(a.lastSeen || '')));

  return json({
    component: 'DevShield WAAP API Inventory',
    count: endpoints.length,
    endpoints
  });
}

function upstreamUrl(request, env) {
  if (!env.UPSTREAM_ORIGIN) throw new Error('UPSTREAM_ORIGIN is required');

  const upstream = new URL(String(env.UPSTREAM_ORIGIN));
  if (!['https:', 'http:'].includes(upstream.protocol)) throw new Error('UPSTREAM_ORIGIN must use http or https');

  const incoming = new URL(request.url);
  incoming.protocol = upstream.protocol;
  incoming.hostname = upstream.hostname;
  incoming.port = upstream.port;

  if (upstream.pathname && upstream.pathname !== '/') {
    incoming.pathname = upstream.pathname.replace(/\/+$/, '') + '/' + incoming.pathname.replace(/^\/+/, '');
  }

  const original = new URL(request.url);
  if (incoming.hostname === original.hostname && incoming.port === original.port) {
    throw new Error('UPSTREAM_ORIGIN must not point back to the WAAP hostname');
  }

  return incoming;
}

async function proxyRequest(request, env, inspection, action) {
  const target = upstreamUrl(request, env);
  const headers = new Headers(request.headers);

  headers.delete('host');
  headers.delete('x-devshield-waf');
  headers.delete('x-devshield-waap');
  headers.delete('x-devshield-request-id');
  headers.delete('x-devshield-origin-token');

  headers.set('x-devshield-waf', action === 'observe-high-risk' ? 'observe' : 'pass');
  headers.set('x-devshield-waap', action === 'observe-high-risk' ? 'observe' : 'pass');
  headers.set('x-devshield-request-id', inspection.requestId);

  if (env.ORIGIN_SHARED_SECRET) {
    headers.set('x-devshield-origin-token', String(env.ORIGIN_SHARED_SECRET));
  }

  const init = {
    method: request.method,
    headers,
    redirect: 'manual'
  };

  if (!['GET', 'HEAD'].includes(request.method.toUpperCase())) init.body = request.body;

  const response = await fetch(target.toString(), init);
  const responseHeaders = new Headers(response.headers);

  responseHeaders.delete('server');
  responseHeaders.delete('x-powered-by');
  responseHeaders.set('x-content-type-options', 'nosniff');
  responseHeaders.set('x-devshield-waf', action === 'observe-high-risk' ? 'observe' : 'pass');
  responseHeaders.set('x-devshield-waap', action === 'observe-high-risk' ? 'observe' : 'pass');
  responseHeaders.set('x-devshield-request-id', inspection.requestId);

  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers: responseHeaders
  });
}

async function inspectProtectedResponse(response, request, env, policy, route, inspection) {
  const config = route?.responseInspection || policy.waap?.responseInspection;
  if (!config?.enabled) return { response, findings: [] };

  const headers = new Headers(response.headers);
  for (const name of config.redactHeaders || []) headers.delete(name);

  const contentType = String(headers.get('content-type') || '').toLowerCase();
  const length = Number(headers.get('content-length') || 0);

  if (!config.inspectJson || !contentType.includes('application/json')) {
    return {
      response: new Response(response.body, {
        status: response.status,
        statusText: response.statusText,
        headers
      }),
      findings: []
    };
  }

  if (length && length > config.maxBytes) {
    return {
      response: new Response(response.body, {
        status: response.status,
        statusText: response.statusText,
        headers
      }),
      findings: []
    };
  }

  let text = '';
  try {
    text = await response.clone().text();
  } catch {
    return {
      response: new Response(response.body, {
        status: response.status,
        statusText: response.statusText,
        headers
      }),
      findings: []
    };
  }

  if (new TextEncoder().encode(text).byteLength > config.maxBytes) {
    return {
      response: new Response(response.body, {
        status: response.status,
        statusText: response.statusText,
        headers
      }),
      findings: []
    };
  }

  const findings = inspectResponseText(text, config);

  if (findings.length) {
    console.log(JSON.stringify({
      component: 'devshield-waap-response',
      action: config.blockOnSecrets && policy.mode === 'block' ? 'block' : 'observe',
      requestId: inspection.requestId,
      method: request.method,
      path: new URL(request.url).pathname,
      rules: findings.map(item => item.rule)
    }));
  }

  if (findings.length && config.blockOnSecrets && policy.mode === 'block') {
    return {
      response: json(
        { error: 'Response blocked by data protection policy', requestId: inspection.requestId },
        502,
        {
          'x-devshield-waap': 'block',
          'x-devshield-request-id': inspection.requestId
        }
      ),
      findings
    };
  }

  return {
    response: new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers
    }),
    findings
  };
}

function logDecision(inspection, action, extra = {}) {
  console.log(JSON.stringify(safeLogEvent(inspection, action, {
    layer: 'waap',
    ...extra
  })));
}

export default {
  async fetch(request, env) {
    const policy = policyFromEnvironment(env);
    const url = new URL(request.url);

    if (url.pathname === '/_devshield/waf/health' || url.pathname === '/_devshield/waap/health') {
      return json({
        ok: true,
        component: 'DevShield WAAP',
        version: '3.2.0',
        mode: policy.mode,
        layers: ['waf', 'api-protection']
      });
    }

    if (url.pathname === '/_devshield/waap/inventory' && request.method === 'GET') {
      return waapInventory(request, env);
    }

    const route = routePolicyFor(request.url, request.method, policy);
    let inspection = inspectRequestMetadata(request, policy, route);

    const discovery = inspectApiDiscovery(request, policy, policy.waap);
    inspection = appendReasons(inspection, discovery);

    const pollution = inspectParameterPollution(request, policy.waap);
    inspection = appendReasons(inspection, pollution);

    const apiVersion = inspectApiVersion(request, route, policy.waap);
    inspection = appendReasons(inspection, apiVersion);

    const requiredHeaders = inspectRequiredHeaders(request, route);
    inspection = appendReasons(inspection, requiredHeaders);

    const contentTypeCheck = inspectContentType(request, route);
    inspection = appendReasons(inspection, contentTypeCheck);

    const rate = await enforceRateLimit(request, rateLimitDescriptor(request, policy, route), env);
    if (rate.limited) {
      inspection = appendReason(inspection, {
        rule: 'rate-limit',
        category: 'abuse',
        weight: 100,
        message: 'Rate limit exceeded'
      });
    }

    const authState = await authAbuseState(request, route, env);
    if (authState.limited) {
      inspection = appendReason(inspection, {
        rule: 'waap-auth-abuse',
        category: 'auth-abuse',
        weight: 100,
        message: 'Repeated authentication failures exceeded route policy'
      });
    }

    const routeMaxBody = route?.maxBodyBytes ?? policy.maxBodyBytes;
    let bodyResult = null;
    const needsWebhookBody = Boolean(route?.webhook);
    const needsBody = shouldInspectBody(request, policy, route) || needsWebhookBody;

    if (needsBody) {
      const graphqlConfig = route?.graphql || policy.waap?.graphql;
      const graphqlLimit = graphqlConfig?.maxQueryBytes || 0;
      const schemaLimit = route?.requestSchema ? policy.inspectBodyBytes : 0;

      const readLimit = Math.max(
        policy.inspectBodyBytes,
        graphqlLimit,
        schemaLimit,
        needsWebhookBody ? routeMaxBody : 0
      );

      bodyResult = await readBodyLimited(request, readLimit);

      if (routeMaxBody > 0 && (bodyResult.bytes > routeMaxBody || bodyResult.truncated && readLimit >= routeMaxBody)) {
        inspection = appendReason(inspection, {
          rule: 'body-too-large',
          category: 'protocol',
          weight: 100,
          message: 'Request body exceeds the configured maximum'
        });
      }

      if (shouldInspectBody(request, policy, route) && bodyResult.text) {
        inspection = combineInspection(
          inspection,
          inspectBodyText(bodyResult.text.slice(0, policy.inspectBodyBytes))
        );
      }

      const contentType = String(request.headers.get('content-type') || '').toLowerCase();

      if (route?.requestSchema && contentType.startsWith('application/json')) {
        const contract = inspectJsonRequest(bodyResult.text, route);
        inspection = appendReasons(inspection, contract);
      }

      const activeGraphql = route?.graphql || policy.waap?.graphql;
      if (activeGraphql?.enabled) {
        const query = graphqlQueryFromRequest(bodyResult.text, contentType);
        if (query) {
          const graphqlCheck = analyzeGraphql(query, activeGraphql);
          inspection = appendReasons(inspection, graphqlCheck);
        }
      }
    }

    const activeGraphql = route?.graphql || policy.waap?.graphql;
    if (activeGraphql?.enabled && ['GET','HEAD'].includes(request.method.toUpperCase())) {
      const query = url.searchParams.get('query') || '';
      if (query) inspection = appendReasons(inspection, analyzeGraphql(query, activeGraphql));
    }

    if (route?.webhook) {
      const signature = request.headers.get(route.webhook.header) || '';
      const secret = route.webhook.secretEnv ? env[route.webhook.secretEnv] : '';

      if (!secret) {
        inspection = appendReason(inspection, {
          rule: 'webhook-secret-missing',
          category: 'integrity',
          weight: 100,
          message: 'Webhook route is configured but its secret is unavailable'
        });
      } else {
        const valid = await verifyWebhookSignature(
          bodyResult?.text || '',
          signature,
          secret,
          {
            algorithm: route.webhook.algorithm,
            encoding: route.webhook.encoding
          }
        );

        if (!valid) {
          inspection = appendReason(inspection, {
            rule: 'webhook-signature-invalid',
            category: 'integrity',
            weight: 100,
            message: 'Webhook signature verification failed'
          });
        }
      }
    }

    await recordEndpoint(request, route, inspection, env);

    const action = decideWafAction(inspection, policy);

    if (policy.mode === 'block' && (rate.limited || authState.limited)) {
      const status = rate.limited ? 429 : 403;
      logDecision(inspection, rate.limited ? 'rate-limit' : 'auth-abuse', {
        rateCount: rate.count || null,
        authFailureCount: authState.count || null
      });

      return json(
        {
          error: rate.limited ? 'Too many requests' : 'Request blocked',
          requestId: inspection.requestId
        },
        status,
        {
          'retry-after': String(Math.max(
            1,
            Math.ceil(((rate.limited ? rate.reset : authState.reset) - Date.now()) / 1000)
          )),
          'x-devshield-waf': 'block',
          'x-devshield-waap': 'block',
          'x-devshield-request-id': inspection.requestId
        }
      );
    }

    if (action === 'block') {
      logDecision(inspection, 'block');
      return json(
        { error: 'Request blocked', requestId: inspection.requestId },
        403,
        {
          'x-devshield-waf': 'block',
          'x-devshield-waap': 'block',
          'x-devshield-request-id': inspection.requestId
        }
      );
    }

    if (action === 'observe-high-risk') {
      logDecision(inspection, 'observe', { highRisk: true });
    } else if (inspection.reasons.length) {
      logDecision(inspection, 'observe', { highRisk: false });
    }

    try {
      const upstream = await proxyRequest(request, env, inspection, action);
      await recordAuthResult(request, route, env, upstream.status);

      const protectedResponse = await inspectProtectedResponse(
        upstream,
        request,
        env,
        policy,
        route,
        inspection
      );

      return protectedResponse.response;
    } catch (error) {
      console.error(JSON.stringify({
        component: 'devshield-waap',
        action: 'proxy-error',
        requestId: inspection.requestId,
        path: inspection.path,
        message: String(error?.message || error)
      }));

      return json(
        { error: 'Upstream unavailable', requestId: inspection.requestId },
        502,
        {
          'x-devshield-waf': 'error',
          'x-devshield-waap': 'error',
          'x-devshield-request-id': inspection.requestId
        }
      );
    }
  }
};
