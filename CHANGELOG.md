# Changelog

All notable changes to **MABRIG DevShield AI** are documented here.

## Unreleased

- Policy-aware regression gate with explicit `off`, non-blocking `report`, and opt-in `enforce` modes.
- Configurable new-risk severity threshold from critical through low, plus `none`.
- Independent ignore/warn/block policy for expanded graph exposure.
- Ignore/warn policy for unchanged inherited debt.
- Blast-radius threshold with ignore, warn, block, or require-owner-approval actions.
- Narrow GitHub review verification for individual CODEOWNERS owners; team ownership is never inferred automatically.
- Regression policy JSON/Markdown artifacts and Action outputs.
- Privacy-safe Cloud policy telemetry excludes reviewer identities and ownership mappings.
- Existing deterministic `fail-on` gate remains independent and authoritative.

## [2.1.0] - 2026-09-19

### Added
- Tamper-evident Security Graph History with SHA-256 hash chaining.
- Optional HMAC-SHA256 entry signing through a secret input/environment key; signing keys are never written to reports or Cloud telemetry.
- Longitudinal classification for new risk, expanded exposure, reduced exposure, resolved risk, and unchanged inherited debt.
- Bounded risk-exposure snapshots for finding/advisory graph nodes.
- History integrity/signature validation before a committed history is trusted.
- Reviewed security-history candidate generation with configurable retention from 1 to 200 entries.
- Compact history/regression summary added to optional AI context and privacy-safe Cloud metadata.
- New Action/CLI controls and outputs for v2.1 security history.

## [2.0.0] - 2026-09-19

### Added
- Security Control Plane coordinating Repository Security Graph evidence into review workflows.
- Stable graph snapshot diffing with added/removed nodes, edges, paths, new finding nodes, and no-longer-observed finding nodes.
- Bounded changed-file blast-radius analysis with direct/contextual confidence preservation.
- Evidence-weighted review-priority propagation with deterministic decay; explicitly not CVSS or exploit probability.
- Best-effort CODEOWNERS ownership hints for impacted graph files.
- Remediation observation checks reporting `still-observed` or `not-observed-after-scan`.
- Reviewed graph baseline candidate generation for future graph-diff comparisons.
- Privacy-safe Cloud export adds only aggregate control-plane/diff metadata, not graph contents or ownership mappings.
- New Action/CLI controls and outputs for the v2.0 control plane.

## [1.9.0] - 2026-09-19

### Added
- Repository Security Graph with typed package, file, finding, and advisory nodes.
- Direct evidence edges for package imports, relative module imports, file findings, and package advisories.
- Contextual workflow-install edges that remain explicitly weaker than direct evidence.
- Bounded multi-hop path discovery with weakest-edge confidence propagation.
- Stable graph, node, edge, and path IDs for downstream audit/diffing.
- JSON, Markdown, and Graphviz DOT graph artifacts plus Action outputs for graph state, nodes, edges, and paths.
- Graph output stores no source snippets or secret values.
- Local staged scans disable working-tree graphing in `auto` mode to avoid mixed snapshots.

## [1.8.0] - 2026-09-19

### Added
- Agentic dependency intelligence mission correlating lockfile evidence, GitHub dependency-review findings, direct source references, lifecycle-script metadata, CI workflows, and deployment context.
- Evidence confidence labels distinguish evidence-linked, contextual, heuristic, and heuristic-elevated paths.
- Stable dependency mission reports and Action outputs for state, prioritized packages, candidate paths, and direct references.
- Root dependency relationship evidence (runtime, development, optional, peer) added to the offline inventory.
- Local staged scans disable working-tree dependency correlation in `auto` mode to avoid mixing snapshots.
- Optional AI review receives a compact dependency-mission summary while deterministic gates remain authoritative.
- Action/runtime version reporting aligned to v1.8.0.

## [1.7.0] - 2026-09-18

### Added
- Offline npm v2/v3 dependency evidence through `npm run inventory` or `npm run scan -- --inventory`.
- JSON and Markdown reports with package identities, license uncertainty, integrity metadata, source transport findings, lockfile hashes, and stable finding fingerprints.
- Explicit coverage limits: no vulnerability lookup, signature verification, package download, or artifact integrity validation.
- Regression tests for safe and unsafe metadata, credential omission, workspace links, gate behavior, malformed input, symlink refusal, and CLI routing.
- Contribution-specific AI assistance disclosure.

## [1.6.0] - 2026-09-18

### Added
- Approval-gated remediation proposal engine with exact source-line candidates for a deliberately small hardening allowlist.
- Local `devshield-remediate` CLI with mission-ID approval, dry-run validation, source-hash stale checks, path/symlink protection, and no automatic commit.
- New `remediation-mode` Action/config setting and remediation plan outputs.
- GitHub Action remains proposal-only and never mutates repository source.

## [1.5.0] - 2026-09-18

### Added
- Agentic security engine with observe → prioritize → attack-path → remediate → verify stages.
- Deterministic priority queue, file clusters, heuristic candidate attack paths, remediation tasks, and verification evidence.
- New `agentic-mode` Action/config setting plus JSON/Markdown agentic plan reports and Action outputs.
- Guardrails prohibit automatic repository mutation, merge-gate bypass, credential rotation, or execution of untrusted source instructions.

## [1.4.0] - 2026-09-13

### Added
- Opt-in DevShield Cloud export bridge for managed dashboards, analytics, usage metering, and paid entitlements.
- New `cloud-api-url`, `cloud-token`, and `cloud-required` Action inputs.
- New `cloud-export-status` output.
- Versioned Cloud ingestion payload with repository/revision metadata, scan summary, finding fingerprints, rule metadata, and dependency advisory metadata.

### Privacy and security
- Cloud export is disabled by default.
- Only HTTPS ingestion endpoints are accepted.
- Cloud credentials are sent only in the Authorization header and are never included in the payload.
- Source code, source snippets, and diff text are not included in the Cloud payload.
- Paid deployments can set `cloud-required: true` to fail closed when managed export is unavailable.

### Validation
- Smoke coverage captures the exact Cloud payload and verifies that source markers, Cloud tokens, and diff content are absent.
- Existing deterministic, dependency, baseline, CLI, and merge-gate regression coverage remains active.

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
