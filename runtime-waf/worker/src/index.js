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

const memoryRate = new Map();

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

function shouldInspectBody(request, policy, route) {
  if (request.method === 'GET' || request.method === 'HEAD') return false;
  const contentType = String(request.headers.get('content-type') || '').toLowerCase();
  if (!contentType) return false;
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

  if (incoming.hostname === new URL(request.url).hostname && incoming.port === new URL(request.url).port) {
    throw new Error('UPSTREAM_ORIGIN must not point back to the WAF hostname');
  }

  return incoming;
}

async function proxyRequest(request, env, inspection, action) {
  const target = upstreamUrl(request, env);
  const headers = new Headers(request.headers);
  headers.delete('host');
  headers.delete('x-devshield-waf');
  headers.delete('x-devshield-request-id');
  headers.delete('x-devshield-origin-token');
  headers.set('x-devshield-waf', action === 'observe-high-risk' ? 'observe' : 'pass');
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
  responseHeaders.set('x-devshield-waf', action === 'observe-high-risk' ? 'observe' : 'pass');
  responseHeaders.set('x-devshield-request-id', inspection.requestId);

  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers: responseHeaders
  });
}

function logDecision(inspection, action, extra = {}) {
  console.log(JSON.stringify(safeLogEvent(inspection, action, extra)));
}

export default {
  async fetch(request, env) {
    const policy = policyFromEnvironment(env);
    const url = new URL(request.url);

    if (url.pathname === '/_devshield/waf/health') {
      return json({
        ok: true,
        component: 'DevShield Runtime WAF',
        version: '3.1.0',
        mode: policy.mode
      });
    }

    const route = routePolicyFor(request.url, request.method, policy);
    let inspection = inspectRequestMetadata(request, policy, route);

    const rate = await enforceRateLimit(request, rateLimitDescriptor(request, policy, route), env);
    if (rate.limited) {
      inspection = appendReason(inspection, {
        rule: 'rate-limit',
        category: 'abuse',
        weight: 100,
        message: 'Rate limit exceeded'
      });
    }

    const routeMaxBody = route?.maxBodyBytes ?? policy.maxBodyBytes;
    let bodyResult = null;
    const needsWebhookBody = Boolean(route?.webhook);

    if (shouldInspectBody(request, policy, route) || needsWebhookBody) {
      const readLimit = Math.max(
        policy.inspectBodyBytes,
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
        inspection = combineInspection(inspection, inspectBodyText(bodyResult.text.slice(0, policy.inspectBodyBytes)));
      }
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

    const action = decideWafAction(inspection, policy);

    if (policy.mode === 'block' && rate.limited) {
      logDecision(inspection, 'rate-limit', { rateCount: rate.count });
      return json(
        { error: 'Too many requests', requestId: inspection.requestId },
        429,
        {
          'retry-after': String(Math.max(1, Math.ceil((rate.reset - Date.now()) / 1000))),
          'x-devshield-waf': 'block',
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
      return await proxyRequest(request, env, inspection, action);
    } catch (error) {
      console.error(JSON.stringify({
        component: 'devshield-runtime-waf',
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
          'x-devshield-request-id': inspection.requestId
        }
      );
    }
  }
};
