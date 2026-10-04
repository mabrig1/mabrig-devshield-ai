# DevShield WAAP — Web Application & API Protection

DevShield v3.2 extends the Runtime WAF into a WAAP layer for protecting browser applications and APIs at the edge.

The deployment model remains:

```
Internet -> DevShield WAAP -> protected origin
```

The WAF layer handles attack-shaped web traffic. The WAAP layer adds API-aware controls.

## WAAP protections

DevShield WAAP adds:

- API endpoint inventory and shadow/unknown API detection
- OpenAPI-derived route contracts
- method-aware path-template matching such as `/api/orders/{id}`
- required header enforcement
- Content-Type enforcement
- API version allowlists
- duplicate query parameter / parameter-pollution detection
- JSON request contract enforcement
- unknown-field rejection to reduce mass-assignment exposure
- field type, length, enum and numeric range validation
- GraphQL introspection controls
- GraphQL depth limits
- GraphQL alias/fan-out limits
- GraphQL query-size limits
- repeated authentication-failure protection
- request/body resource controls
- HMAC webhook protection
- response secret-leak inspection
- response header hardening
- persistent API inventory through Workers KV
- privacy-safe API observations

## Safe default

The global enforcement mode is still:

```
observe
```

This means a rule can be configured as a block-worthy WAAP condition while DevShield continues to report it without denying traffic.

After validating production traffic, explicitly switch:

```
WAF_MODE=block
```

The same mode controls WAF and WAAP enforcement so there is one clear edge decision boundary.

## API discovery

Example:

```json
{
  "waap": {
    "apiDiscovery": {
      "enabled": true,
      "apiPrefixes": ["/api/", "/graphql"],
      "unknownAction": "observe",
      "excludePrefixes": ["/api/health"]
    }
  }
}
```

A request under an API prefix that is not represented in the configured route inventory is recorded as:

```
waap-shadow-api
```

After your route inventory is complete, change:

```json
"unknownAction": "block"
```

and then enable global `block` mode.

## Persistent API inventory

Bind a Workers KV namespace as:

```
WAAP_KV
```

DevShield records privacy-minimized endpoint observations containing:

- method
- pathname
- stable endpoint fingerprint
- matched route ID
- known/unknown state
- risk score
- first/last seen
- observation count

It does **not** store:

- query values
- request bodies
- Authorization values
- cookies
- client IP addresses

Set a secret:

```bash
npx wrangler secret put WAAP_ADMIN_TOKEN
```

Then retrieve the inventory:

```bash
curl https://your-waap.example.com/_devshield/waap/inventory \
  -H "X-DevShield-Admin-Token: YOUR_TOKEN"
```

The inventory endpoint is unavailable unless both `WAAP_KV` and `WAAP_ADMIN_TOKEN` are configured.

## OpenAPI → WAAP policy

DevShield can convert an OpenAPI 3.x JSON document into method-specific WAAP route contracts.

```bash
npm run waap:policy -- openapi.json --out runtime-waf/policy.generated.json
```

Preserve global settings from an existing policy:

```bash
npm run waap:policy -- openapi.json \
  --base runtime-waf/policy.example.json \
  --out runtime-waf/policy.generated.json
```

The generator maps:

- OpenAPI path templates
- HTTP methods
- operation security requirements
- required headers
- JSON request content types
- required fields
- primitive property types
- enum values
- string length limits
- numeric minimum/maximum
- `additionalProperties: false` to unknown-field rejection

Supported extensions:

```
x-devshield-max-body-bytes
x-devshield-rate-limit
x-devshield-auth-abuse
x-devshield-response-inspection
```

Only OpenAPI 3.x JSON is supported. The generator intentionally does not add a YAML parser dependency.

## JSON request contracts

Example:

```json
{
  "id": "create-order",
  "pathPrefix": "/api/orders",
  "methods": ["POST"],
  "requireAuth": true,
  "requestContentTypes": ["application/json"],
  "requestSchema": {
    "allowedFields": ["items", "deliveryLocation"],
    "rejectUnknownFields": true,
    "maxFields": 2,
    "fields": {
      "items": {
        "type": "array",
        "required": true
      },
      "deliveryLocation": {
        "type": "string",
        "required": true,
        "maxLength": 180
      }
    }
  }
}
```

This can stop malformed or unexpected request shapes before application code processes them.

It does not replace application validation. Business rules still belong in the application.

## Parameter pollution

Duplicate query parameters can produce inconsistent behavior across proxies/frameworks.

```json
{
  "waap": {
    "parameterPollution": {
      "enabled": true,
      "action": "observe",
      "allowDuplicateKeys": ["tag"]
    }
  }
}
```

Only parameter names are reported. Values are not logged.

## API version protection

```json
{
  "waap": {
    "apiVersions": {
      "allowed": ["2026-10"],
      "header": "x-api-version",
      "action": "observe"
    }
  },
  "routes": [
    {
      "id": "orders",
      "pathPrefix": "/api/orders",
      "apiVersionRequired": true
    }
  ]
}
```

This can help retire old or unintended API versions at the edge.

## Authentication abuse protection

Login and token routes can maintain a separate failure budget.

```json
{
  "id": "login",
  "pathPrefix": "/api/auth/login",
  "methods": ["POST"],
  "authAbuse": {
    "enabled": true,
    "failures": 8,
    "windowSeconds": 600,
    "statuses": [401, 403]
  }
}
```

With `WAAP_KV`, counters persist across Worker isolates. IP addresses are hashed before they are used in auth-abuse keys.

Successful authentication responses clear the local failure counter for that route/client.

## GraphQL protection

Global example:

```json
{
  "waap": {
    "graphql": {
      "enabled": true,
      "allowIntrospection": false,
      "maxDepth": 10,
      "maxAliases": 20,
      "maxQueryBytes": 65536
    }
  }
}
```

A route can override the global policy.

DevShield checks:

- `__schema` / `__type` introspection
- brace nesting depth
- alias fan-out
- query byte size

This is intentionally deterministic and lightweight. It is not a complete GraphQL cost model.

## Response data protection

WAAP can inspect small JSON responses for high-confidence secret-like formats.

```json
{
  "waap": {
    "responseInspection": {
      "enabled": true,
      "inspectJson": true,
      "maxBytes": 131072,
      "blockOnSecrets": false,
      "redactHeaders": ["x-debug-token"]
    }
  }
}
```

In observe mode, findings are logged without response bodies or secret values.

When both:

```
blockOnSecrets=true
WAF_MODE=block
```

are active, the suspicious upstream response is replaced with a generic blocked response.

Response inspection deliberately skips large responses.

## Required headers

For routes that need idempotency, tenant, request-ID or client-version headers:

```json
{
  "requiredHeaders": [
    "idempotency-key",
    "x-request-id"
  ]
}
```

The edge only checks presence. Semantic verification still belongs in the application.

## Path templates

OpenAPI-style templates are matched segment-by-segment:

```
/api/orders/{id}
```

matches:

```
/api/orders/123
/api/orders/abc
```

but not:

```
/api/orders/123/items
```

When multiple operations share the same path, DevShield selects the contract matching the incoming HTTP method.

## Layered deployment

Recommended production stack:

```
Cloudflare DDoS / Managed WAF
        |
DevShield WAAP Worker
        |
Application authentication + authorization
        |
Database / queues / payment services
```

DevShield WAAP is additive. It is not a substitute for authorization checks, prepared database queries, secure secrets, or provider-level DDoS controls.

## Recommended rollout

1. Deploy DevShield WAAP in `observe`.
2. Import your OpenAPI route inventory.
3. Enable `WAAP_KV`.
4. Review shadow API observations.
5. Tune JSON/GraphQL/auth-abuse rules.
6. Run legitimate application flows.
7. Run DevShield Runtime Guard against the public WAAP hostname.
8. Change high-confidence API rules from observe to block.
9. Change global mode to `block`.
10. Protect the origin with `ORIGIN_SHARED_SECRET` or network ACLs.

## Health endpoint

```
GET /_devshield/waap/health
```

returns the active DevShield layer/version without exposing policy or secrets.
