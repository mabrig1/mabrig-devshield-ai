# DevShield Rule & Policy Guide

MABRIG DevShield AI v1.1 uses a dependency-free deterministic rule engine before any optional AI review.

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
| Supply chain | mutable GitHub Action refs, remote scripts, floating dependencies |
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
