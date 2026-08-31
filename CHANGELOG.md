# Changelog

All notable changes to **MABRIG DevShield AI** are documented here.

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

