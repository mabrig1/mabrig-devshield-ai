// Safe deployment *candidate* for the existing named Worker.
// No remote scanning, AI, email, secrets or customer-data API is activated here.
const headers = {
  'content-type': 'application/json; charset=utf-8',
  'cache-control': 'no-store',
  'x-content-type-options': 'nosniff',
  'referrer-policy': 'no-referrer'
};

function respond(body, status = 200, method = 'GET') {
  return new Response(method === 'HEAD' ? null : JSON.stringify(body), { status, headers });
}

export default {
  async fetch(request) {
    const url = new URL(request.url);
    const method = request.method;
    if (method !== 'GET' && method !== 'HEAD') {
      return respond({ error: 'method_not_allowed' }, 405, method);
    }
    if (url.pathname === '/health') {
      return respond({
        component: 'MABRIG DevShield Worker',
        status: 'gateway-candidate-only',
        cloudScanning: false,
        billing: false,
        secretRequired: false
      }, 200, method);
    }
    if (url.pathname === '/') {
      return respond({
        service: 'MABRIG DevShield AI',
        message: 'Deployment candidate: local CLI and GitHub Action remain the active security tools.',
        apiStatus: 'not-configured',
        documentation: 'https://github.com/mabrig1/mabrig-devshield-ai'
      }, 200, method);
    }
    if (url.pathname.startsWith('/api/') || url.pathname.startsWith('/v1/')) {
      return respond({ error: 'api_not_configured' }, 503, method);
    }
    return respond({ error: 'not_found' }, 404, method);
  }
};
