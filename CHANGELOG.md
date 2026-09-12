# Changelog

All notable changes to **MABRIG DevShield AI** are documented here.

## [1.3.0] - 2026-09-12

### Added
- Local dependency-free DevShield CLI.
- `npm run scan` developer workflow.
- `staged` scan scope for pre-commit/pre-push prevention.
- Example Git pre-commit hook.

### Security
- Staged scans read the Git index snapshot with `git show :path` rather than the mutable working-tree copy, preventing staged-content/working-tree divergence from bypassing local review.

### Validation
- Smoke coverage verifies risky staged code is blocked even if the working tree is changed to a safe version after staging.
- Safe staged changes pass the local CLI gate.

## [1.2.0] - 2026-09-12

### Added
- Native GitHub dependency-review integration for pull requests.
- Vulnerable dependency findings with package, ecosystem, version, license, GHSA, advisory URL, and advisory summary metadata.
- Dependency license deny policy.
- Configurable minimum dependency vulnerability severity.
- Graceful fallback when GitHub dependency review is unavailable.
- Finding baselines through `.devshield-baseline.json`.
- `new` versus `existing` finding state.
- `new-only`, `report`, and `off` baseline modes.
- Generated baseline candidate report for adopting DevShield on legacy repositories.
- New outputs for new findings, existing findings, dependency findings, dependency-review status, and baseline candidate path.

### Changed
- Merge gating and risk scoring can operate only on findings not present in the committed baseline.
- Existing baseline findings remain visible in JSON and SARIF reports.
- Deduplication now uses stable fingerprints, allowing multiple dependency advisories in the same manifest to remain distinct.
- Machine-readable report schema advanced to version 2.
- PR summaries now expose dependency-review and baseline status.

### Validation
- Smoke coverage now includes baseline adoption behavior and dependency-review fixtures in addition to the v1.1 security regression suite.

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
