# Changelog

All notable changes to **MABRIG DevShield AI** are documented here.

## [1.1.0] - 2026-09-12

### Added
- Diff-aware `changed-lines` scanning as the default PR review mode.
- `changed-files` and full `repository` scan scopes.
- 50+ deterministic checks spanning secrets, injection, deserialization, XSS, authentication, configuration, cryptography, GitHub Actions, supply chain, IaC, and containers.
- Repository policy-as-code through `.devshield.json`.
- `balanced`, `strict`, and `secrets-only` policies.
- Rule/category ignores and per-rule severity overrides.
- Inline `devshield:ignore` suppressions for non-critical findings.
- SARIF 2.1.0 output with CWE/category metadata and stable fingerprints.
- Structured JSON report for CI pipelines and commercial ingestion.
- Additional outputs: scanned files, ignored findings, report path, and SARIF path.
- Safer AI handoff with expanded secret redaction, excluded-path filtering, and explicit prompt-injection resistance.

### Changed
- Risk scoring now caps repeated rule/file hits so one noisy pattern does not dominate the score.
- Critical findings cannot be hidden with inline suppressions.
- PR comments include scan scope, active policy, category counts, suppression count, and report locations.
- Maximum default files scanned increased from 80 to 120.
- Package version advanced to 1.1.0.

### Validation
- Smoke coverage now validates diff-aware scanning, suppressions, policy configuration, JSON/SARIF generation, critical findings, and merge-gate behavior.

## [1.0.0] - 2026-08-31

### Added
- Deterministic pull request security scanner.
- Secret detection for private keys, GitHub tokens, AI-provider keys, AWS access keys, Stripe live keys, and tracked `.env` files.
- Risk checks for dynamic `eval`, shell execution, disabled TLS verification, wildcard CORS, request-built SQL, debug mode, floating dependencies, and moving GitHub Action refs.
- Pull request annotations, job summaries, risk score, risk level, and findings count outputs.
- Optional OpenRouter AI-assisted second-pass review with diff redaction.
- Configurable `fail-on`, `max-files`, `comment`, and `exclude-paths` inputs.
- GitHub-hosted smoke test and self-scan workflow.
- Marketplace listing copy, pricing plan, security policy, contribution guide, code of conduct, workflow example, and launch checklist.
- Stable `v1` compatibility ref for customer workflows.

### Changed
- CI upgraded to current GitHub Actions releases using `actions/checkout@v7` and `actions/setup-node@v7`.
- Self-scan supports fixture/generated-path exclusions so intentional security test strings do not fail the product's own release validation.

### Validation
- Pull request launch CI passed.
- Post-merge `main` CI passed.
