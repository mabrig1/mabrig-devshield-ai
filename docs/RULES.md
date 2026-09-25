# DevShield Rule & Policy Guide

MABRIG DevShield AI v2.8 uses a dependency-free deterministic rule engine before any optional AI review.

## Rule categories

| Category | Examples |
|---|---|
| Secrets | private keys, provider tokens, credential URLs, tracked `.env`, package registry credentials |
| Injection | `eval`, shell interpolation, SQL construction, unsafe process execution |
| Deserialization | Python pickle and unsafe YAML loading |
| XSS | DOM HTML assignment and React `dangerouslySetInnerHTML` |
| Authentication | disabled JWT signature verification |
| Configuration | disabled TLS, wildcard CORS, debug mode, unsafe permissions |
| Cryptography | strict-mode MD5/SHA-1 hardening |
| Supply chain | mutable GitHub Action refs, long-lived npm publish credentials, remote scripts, floating dependencies |
| AI security | insecure remote MCP transport, disabled approvals, wildcard tool surfaces |
| CI security | `write-all`, risky `pull_request_target`, expression-to-shell injection, pwn-request checkout |
| IaC | world-open networks, wildcard IAM permissions, public Terraform ACLs |
| Containers | privileged mode, host networking, root users, privilege escalation |

## Noise-control model

DevShield uses three layers of noise control:

1. **Changed-lines scanning by default.** Existing issues on untouched lines do not become new PR failures.
2. **Balanced vs strict rules.** Lower-confidence hardening rules are strict-only.
3. **Narrow suppressions.** Non-critical findings may use `devshield:ignore`; critical findings require an explicit repository-level exception or path exclusion.

## Configuration

```json
{
  "policy": "balanced",
  "scanScope": "changed-lines",
  "excludePaths": ["fixtures/**"],
  "ignoreRules": [],
  "ignoreCategories": [],
  "severityOverrides": {
    "shell-exec": "high"
  },
  "maxFileBytes": 1500000,
  "inlineSuppressions": true
}
```

### `ignoreRules`

Use this only for a rule the repository intentionally does not want enforced. Prefer a path exclusion for fixtures.

### `ignoreCategories`

Useful for specialized pipelines, but broad category suppression should be reviewed like a security-policy change.

### `severityOverrides`

Allowed values are `low`, `medium`, `high`, and `critical`. Invalid values fall back to the built-in severity.

## Inline suppressions

```js
// devshield:ignore shell-exec
exec("known-static-command");
```

Critical findings remain active even when an inline `devshield:ignore` marker is present.

## SARIF

The SARIF report includes:

- rule IDs
- severity and category
- CWE metadata where applicable
- file/line locations
- remediation text
- stable finding fingerprints

This makes DevShield results usable by GitHub Code Scanning and other SARIF-aware systems.

## Rule contribution standard

A new deterministic rule should:

1. detect a security-relevant condition with a clear threat model;
2. have a stable rule ID;
3. define severity, category, CWE, message, and remediation;
4. include a file restriction when the pattern is format-specific;
5. be `strictOnly` if it is useful but reasonably likely to be noisy;
6. have a smoke/evaluation case before promotion to the balanced policy.


## v2.5 emerging-threat rules

DevShield v2.5 adds deterministic coverage for current developer and agent-security risks:

- **Full-SHA Action pinning:** non-SHA third-party `uses:` references are now balanced-policy medium findings. Local `./`, same-repository `$/`, Docker actions, and full commit SHAs are excluded.
- **Retired Node 20 Action runtime:** custom `action.yml`/`action.yaml` metadata using `runs.using: node20` is a high finding; hosted runners now require Node 24 for JavaScript Actions.
- **npm publishing credentials:** a workflow combining `npm publish` with a repository-secret `NODE_AUTH_TOKEN` is reported as a migration risk toward trusted publishing (OIDC) or staged publishing.
- **Low-trust Actions cache writes:** `pull_request_target` workflows that explicitly set `cache-mode: write` or `write-only` are high findings because the override can re-open cache-poisoning paths.
- **Remote MCP transport:** plain-HTTP MCP server URLs are high severity.
- **MCP approvals/tool scope:** globally disabled approval and wildcard tool-surface patterns are strict-mode findings. They are not treated as proof of exploitation.
- **Modern provider secrets:** GitLab token families and Supabase personal access tokens are detected and redacted.

The AI/MCP checks are intentionally configuration-focused. Static source scanning cannot prove that a prompt-injection attack will succeed, so DevShield reports unsafe trust-boundary configurations rather than claiming exploitability.


## v2.6 trust-boundary rules

DevShield v2.6 adds structured checks around the places where modern developer and AI tooling crosses trust boundaries:

- **Structured MCP config audit:** common MCP JSON configs are parsed so `url`, `command`, `args`, and `env` can be evaluated together.
- **MCP embedded credentials:** secret-looking literal values in MCP server environment blocks are critical findings.
- **MCP package execution:** `npx`-launched MCP servers without an exact package version or immutable source revision are medium supply-chain findings.
- **Unsafe PR checkout opt-out:** `allow-unsafe-pr-checkout: true` is a high CI-security finding.
- **Contributor fork checkout:** `pull_request_target` plus `github.event.pull_request.head.repo.full_name` is critical because the privileged workflow is pointed directly at contributor-controlled repository content.
- **npm provenance downgrade:** an npm publishing workflow that explicitly disables provenance is a medium supply-chain finding.

These checks are evidence about configuration and authority. They do not assert exploitability or compromise.


## v2.7 MCP authorization and protocol rules

DevShield v2.7 aligns static MCP configuration review with the 2026-07-28 protocol security direction:

- **OAuth transport:** remote issuer, authorization, token, registration, and JWKS URLs using plain HTTP are high findings.
- **OAuth client secrets:** literal client secrets committed inside MCP configuration are critical findings.
- **Authorization headers:** literal bearer credentials committed in MCP server headers are critical findings.
- **Dynamic Client Registration:** explicitly enabling DCR is a medium compatibility finding because MCP 2026-07-28 formally deprecates DCR in favor of Client ID Metadata Documents (CIMD).
- **Legacy HTTP+SSE:** explicit SSE transport or an MCP endpoint ending in `/sse` is a medium compatibility finding under the new protocol-era deprecation policy.
- **Broad OAuth scopes:** wildcard/admin/full-access scope names are strict-mode medium findings and should be reviewed for least privilege.

DevShield does not infer whether an OAuth client correctly validates the RFC 9207 `iss` response at runtime from static configuration alone. That runtime property requires protocol-level verification rather than source-pattern matching.


## v2.8 Runtime Guard DNS pinning

Runtime Guard now treats DNS resolution as part of the security boundary instead of only pre-validating the URL:

- the hostname is resolved immediately before every normal probe request;
- any private/non-routable answer blocks the request unless private targets were explicitly enabled;
- Node's HTTP(S) custom `lookup` is used to force the socket to the validated address;
- the original hostname is retained for the HTTP Host header and TLS SNI/certificate validation;
- connection reuse is disabled so a prior socket cannot bypass a later DNS check;
- the response socket address is compared with the validated address;
- redirects remain disabled.

Custom injected `fetchFn` integrations are intentionally not labeled DNS-pinned because DevShield cannot control how an arbitrary external fetch implementation resolves names.
