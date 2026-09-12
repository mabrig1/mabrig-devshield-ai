# Competitive Roadmap

MABRIG DevShield AI v1.1 establishes a fast, transparent PR security gate. The next moat should come from **context, proof, prevention, and remediation**, not from endlessly adding regexes.

## Shipped in v1.1

- Diff-aware changed-line scanning
- 50+ deterministic checks
- Secrets, injection, CI/CD, supply-chain, IaC, and container coverage
- Policy-as-code
- SARIF + JSON output
- Stable fingerprints
- Noise-aware risk scoring
- Inline non-critical suppressions
- AI prompt-injection hardening and expanded redaction
- Configurable balanced/strict/secrets-only policies
- Repository scan mode

## P0 — next release: security intelligence

### Dependency intelligence
Integrate GitHub's dependency review data when available so DevShield can report newly introduced vulnerable dependencies, advisory IDs, fixed versions, dependency scope, and policy violations.

### Repository-context security graph
Build a lightweight context graph for routes, auth middleware, data stores, permission checks, sensitive sinks, and configuration. Feed only the minimum relevant neighborhood into the AI reviewer. This is the most important step toward finding authorization and business-logic flaws that line-pattern scanners miss.

### Evidence-backed AI findings
Require AI findings to contain:
- file and line
- source-to-sink or trust-boundary explanation
- exploit preconditions
- confidence
- concrete remediation

Reject AI findings that cannot point to evidence in the reviewed revision.

### Suggested-fix mode
Generate review suggestions or patch artifacts for high-confidence fixes, but never auto-commit security fixes without an explicit user workflow.

## P1 — prevention before CI

### DevShield CLI
Add a local CLI with:
- staged-diff scanning
- full repository scan
- SARIF/JSON output
- the same `.devshield.json` policy

### Pre-commit and pre-push hooks
Catch secrets and dangerous workflow changes before they leave the developer machine.

### AI-tool guard
Add an optional local guard for files/prompts/tool outputs so credentials can be detected before they are sent to an AI coding tool.

## P1 — triage and governance

- Baseline mode for adopting DevShield on legacy repositories without blocking on old findings
- Fingerprint-based "new / existing / resolved" finding state
- CODEOWNERS-aware security routing
- Organization policy packs
- Rule expiration dates for temporary exceptions
- Audit trail for suppressions and severity changes
- Security trend/MTTR analytics in the commercial GitHub App

## P2 — advanced analysis

- Taint/dataflow engines for supported languages
- API authorization and IDOR-focused checks
- IaC graph checks across related resources
- Secret validity verification through provider-safe mechanisms
- SBOM ingestion and license policy
- Reachability-aware dependency risk
- Test generation for confirmed security findings
- Multi-model consensus only for high-risk ambiguous changes
- Self-hosted/air-gapped inference for regulated teams

## Product positioning

The public Action should remain:
- dependency-light
- transparent
- deterministic-first
- BYOK/AI-optional
- useful on free/public GitHub workflows

The commercial GitHub App should own:
- repository-scale context
- cross-repository policy
- vulnerability/advisory intelligence
- installation analytics
- managed AI
- collaboration and remediation workflows

That split keeps the open Action credible while giving the paid product a defensible reason to exist.
