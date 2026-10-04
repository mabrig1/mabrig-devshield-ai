# API & Agent Trust Shield

DevShield v3 adds an independent static trust-boundary scanner for modern API backends and agentic applications.

## Why it exists

Traditional secret and injection checks are not enough for applications that combine:

- public APIs,
- browser clients,
- payment providers,
- webhooks,
- JWT authentication,
- AI agents,
- tool execution,
- remote fetches,
- privileged admin routes.

The API & Agent Trust Shield looks for dangerous architecture signals before they become production incidents.

## Checks

The v3 engine currently detects:

- credentialed wildcard CORS,
- public/client-side secret namespaces,
- JWT `none` algorithm acceptance,
- hard-coded JWT signing or verification secrets,
- admin routes without an observable authentication/authorization signal,
- webhook handlers without an observable signature-verification signal,
- user-controlled outbound request patterns that can create SSRF risk,
- explicitly disabled human approval around agent/tool execution,
- wildcard agent/tool authority,
- model/tool output flowing into shell execution,
- transaction-sensitive write routes with no observable idempotency signal,
- payment-provider secrets in likely client/browser code.

These are static signals, not claims that an application is exploitable.

## CLI

Advisory scan:

```bash
npm run api-trust
```

Or through the main CLI:

```bash
npm run scan -- --api-trust
```

Enforce high-or-above findings:

```bash
npm run api-trust -- --enforce --fail-on high
```

Reports are written to:

```
.devshield/devshield-api-agent-trust.json
.devshield/devshield-api-agent-trust.md
.devshield/devshield-api-agent-trust.sarif
```

## GitHub Action

```yaml
- uses: mabrig1/mabrig-devshield-ai@v3
  with:
    github-token: ${{ github.token }}
    api-trust: advisory
    api-trust-fail-on: high
```

Modes:

- `off` — do not run the shield.
- `advisory` — emit evidence but never fail this shield's step.
- `enforce` — fail when a finding reaches the configured `api-trust-fail-on` threshold.

The default is advisory so existing repositories can observe findings before deciding to enforce them.

## Agentic safety boundary

The shield intentionally treats agent authority separately from ordinary application security. It flags explicit patterns such as disabled approval, wildcard tool access, and model output sent to shell execution.

A secure implementation should prefer:

1. typed tool contracts,
2. least-privilege tool allowlists,
3. scoped credentials,
4. explicit human approval for high-impact side effects,
5. durable audit logs,
6. idempotency and replay resistance for external actions,
7. server-side authorization independent of model instructions.

## API security boundary

For public APIs, DevShield expects sensitive trust decisions to remain server-side:

- do not expose secret keys in browser bundles,
- authenticate and authorize administrative routes,
- calculate sensitive prices/commissions server-side,
- verify payment/webhook signatures,
- validate and constrain outbound network destinations,
- use idempotency for transaction-sensitive writes,
- use explicit origin allowlists for credentialed browser requests.

## Limitations

Static analysis cannot prove:

- that middleware is invoked at runtime,
- that a webhook provider signature is semantically correct,
- that authorization policy is complete,
- that a model can or cannot be prompt-injected,
- that an SSRF path is reachable,
- that a payment provider is configured correctly.

Findings should be reviewed alongside runtime tests, threat modeling, and deployment configuration.
