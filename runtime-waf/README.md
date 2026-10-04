# DevShield Runtime WAF

DevShield Runtime WAF is the deployable enforcement layer introduced in v3.1. DevShield v3.2 extends this same edge Worker into a WAAP layer for API discovery, request contracts, GraphQL controls, authentication-abuse protection, and response data protection.

It is separate from Runtime Guard:

- Runtime Guard probes a deployed application and measures protection signals.
- Runtime WAF sits in front of the application and can observe or block malicious requests.

## Architecture

Internet -> DevShield WAAP / Runtime WAF -> protected origin application

The Worker proxies approved traffic to a fixed `UPSTREAM_ORIGIN`. It never accepts an arbitrary upstream URL from the client.

## Safe deployment default

The default mode is:

```
observe
```

Observe mode scores and logs suspicious traffic but still forwards it.

After reviewing the logs and tuning the policy, switch to:

```
block
```

Do not start a production deployment in block mode unless you have validated normal application traffic first.

## WAAP extension

For the v3.2 Web Application & API Protection controls, see [WAAP.md](WAAP.md). The WAAP layer uses the same Worker and the same observe/block safety model; there is no separate proxy hop.

## Included protections

The current policy engine supports:

- SQL injection-shaped patterns
- XSS-shaped patterns
- path traversal
- command injection-shaped patterns
- template injection-shaped patterns
- null-byte patterns
- scanner/bot user-agent signals
- explicit origin allowlists
- country blocks
- JWT `alg=none` detection
- per-route allowed methods
- per-route authentication requirements
- global and per-route request-body limits
- global and per-route rate limiting
- HMAC webhook verification
- safe structured security logs
- origin-authentication secret headers
- fixed-origin proxying

## Privacy

Security logs intentionally exclude:

- request bodies
- Authorization headers
- origin shared secrets
- client IP addresses
- full user-agent values

Logs contain only request metadata needed for triage, including request ID, route, action, score, country and matched rule IDs.

## Configure the Worker

Copy:

```
runtime-waf/wrangler.toml.example
```

to:

```
runtime-waf/wrangler.toml
```

Set:

```toml
UPSTREAM_ORIGIN = "https://origin.example.com"
WAF_MODE = "observe"
WAF_BLOCK_SCORE = "70"
```

The upstream should be the real application origin, not the public WAF hostname.

## Route policy

You can provide the full JSON policy through the Worker variable:

```
WAF_POLICY_JSON
```

Use `policy.example.json` as the starting point.

The longest matching `pathPrefix` wins.

Example:

```json
{
  "mode": "observe",
  "blockScore": 70,
  "allowedOrigins": ["https://example.com"],
  "routes": [
    {
      "id": "admin",
      "pathPrefix": "/api/admin",
      "methods": ["GET", "POST", "PATCH", "DELETE"],
      "requireAuth": true
    }
  ]
}
```

## Webhook verification

A route can require a HMAC signature:

```json
{
  "id": "paystack-webhook",
  "pathPrefix": "/api/payments/webhook",
  "methods": ["POST"],
  "webhook": {
    "header": "x-paystack-signature",
    "algorithm": "SHA-512",
    "secretEnv": "PAYSTACK_SECRET_KEY",
    "encoding": "hex"
  }
}
```

Store the actual secret as a Worker secret:

```bash
npx wrangler secret put PAYSTACK_SECRET_KEY
```

The secret is never included in the policy file or logs.

## Origin bypass protection

A WAF is not effective if attackers can connect directly to the origin and skip the edge layer.

Set:

```bash
npx wrangler secret put ORIGIN_SHARED_SECRET
```

The Worker will add:

```
X-DevShield-Origin-Token: <secret>
```

to upstream requests.

The protected application should reject direct traffic when this header is absent or incorrect.

For even stronger protection, combine this with network-level origin restrictions where your hosting provider supports them.

## Rate limiting

Without a KV binding, the Worker uses an isolate-local in-memory counter. That is useful as a lightweight signal but is not globally authoritative.

For better persistence, create a Workers KV namespace and bind it as:

```
RATE_KV
```

The included implementation then uses KV-backed time windows.

For high-volume or strongly consistent enforcement, use Cloudflare's native Rate Limiting/WAF rules alongside DevShield.

## Health endpoint

The Worker exposes:

```
GET /_devshield/waf/health
```

Example:

```json
{
  "ok": true,
  "component": "DevShield Runtime WAF",
  "version": "3.1.0",
  "mode": "observe"
}
```

It does not expose policy details or secrets.

## Deployment

```bash
cd runtime-waf
npm install
cp wrangler.toml.example wrangler.toml
npx wrangler login
npm run deploy
```

Then attach the desired public hostname to the Worker in Cloudflare.

Recommended topology:

```
app.example.com       -> DevShield Runtime WAF Worker
origin.example.com    -> application origin
```

Protect `origin.example.com` with the origin shared secret or provider-level restrictions.

## Migration sequence

1. Deploy in `observe`.
2. Exercise normal browser, mobile, API, webhook and admin flows.
3. Review Worker logs for false positives.
4. Add route-specific limits and allowlists.
5. Run DevShield Runtime Guard against the WAF hostname.
6. Confirm controlled probes receive the expected block responses.
7. Switch to `block`.
8. Keep Runtime Guard in CI to detect future protection regressions.

## Challenge mode

This version intentionally does not pretend to implement a Cloudflare Managed Challenge from Worker JavaScript.

For interactive challenges, combine DevShield decisions with Cloudflare WAF/Ruleset controls. The embedded Worker itself supports deterministic observe/block enforcement.

## Limitations

Runtime WAF is an application-layer control. It does not replace:

- Cloudflare managed WAF rules
- DDoS protection
- provider-level network ACLs
- secure application authorization
- safe database queries
- secret management
- secure webhook code
- dependency security

It provides an additional programmable enforcement layer and audit boundary.
