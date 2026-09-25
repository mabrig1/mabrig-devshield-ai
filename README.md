# MABRIG DevShield AI

**Security-first pull request review before merge — deterministic, diff-aware, policy-driven, and AI-optional.**

MABRIG DevShield AI is a dependency-free GitHub Action that reviews pull-request changes for exposed secrets, injection risks, unsafe configuration, GitHub Actions supply-chain weaknesses, infrastructure-as-code mistakes, and container privilege risks.

**Developed and maintained by MABRIG Technologies.** For paid installation, security hardening, team rollout or managed support, contact **mabrig@mabrigkorie.org**. See [Pricing & Packaging](docs/PRICING.md) and the [Monetization Plan](docs/MONETIZATION.md).

It runs without an AI key. Teams can optionally add OpenRouter for a second-pass contextual review after DevShield filters excluded paths and redacts common secret formats.

## Why DevShield

DevShield is built around one question: **does this change make the repository meaningfully riskier?**

Version 2.8 hardens Runtime Guard against DNS-rebinding/TOCTOU behavior by pinning each probe connection to a freshly validated public IP while preserving the original TLS hostname, on top of the v2.7 MCP authorization guard:

- **Diff-aware by default** — scans newly added lines instead of re-reporting legacy issues in every touched file.
- **50+ deterministic checks** across secrets, injection, authentication, CI/CD, supply chain, IaC, containers, TLS, CORS, and crypto hygiene.
- **Policy-as-code** with a repository-owned `.devshield.json`.
- **SARIF 2.1.0 + JSON reports** for GitHub Code Scanning and external security pipelines.
- **Stable fingerprints** for downstream deduplication and triage.
- **Native dependency intelligence** using GitHub dependency review when available, including GHSA and license policy findings.
- **Legacy-repository baselines** that distinguish new findings from accepted existing debt without hiding either from reports.
- **Inline suppressions** for non-critical findings, with critical findings deliberately kept unsuppressible inline.
- **Balanced, strict, and secrets-only policies**.
- **Changed-lines, changed-files, and full-repository scan scopes**.
- **Prompt-injection-resistant AI handoff** that treats the diff as untrusted data and redacts secrets before external analysis.
- **No Action runtime dependencies** beyond Node.js already present on GitHub-hosted runners.
- **Local staged-change CLI** so the same policy can stop risky code before commit, not only in CI.
- **Privacy-safe DevShield Cloud bridge** for paid dashboards, analytics, usage metering and organization features without exporting source snippets or diff text.
- **Agentic security loop** that turns findings into prioritized remediation tasks, heuristic attack-path hypotheses, and explicit verification steps without silently mutating code.
- **Approval-gated remediation proposals** that generate exact allowlisted patch candidates in CI while requiring a matching mission approval before any local source mutation.
- **Offline npm dependency evidence** for lockfile package identity, declared license, integrity metadata, source transport, stable fingerprints, and policy gating without package installation.
- **Agentic dependency intelligence** that correlates lockfile evidence with GitHub dependency-review advisories, direct JS/TS imports, lifecycle-script metadata, CI workflows, container/IaC context, and existing security findings—while explicitly refusing to infer exploitability.
- **Repository Security Graph** with typed file/package/finding/advisory/workflow nodes, traceable import/finding/advisory edges, contextual install edges, stable graph IDs, bounded multi-hop path discovery, and JSON/Markdown/Graphviz DOT exports.
- **Security Control Plane** with graph snapshot diffing, bounded changed-file blast radius, evidence-weighted review-priority propagation, best-effort CODEOWNERS ownership hints, and post-remediation observation checks.
- **Security Graph History & Regression Detection** with SHA-256 hash chaining, optional HMAC-SHA256 signing, bounded risk-exposure snapshots, and explicit `regression`, `improvement`, `unchanged`, or first-snapshot `unclassified` states.
- **Policy-Aware Regression Gates** with report-only defaults, opt-in enforcement, severity thresholds for new risk, warn/block controls for expanded exposure, inherited-debt visibility, and optional blast-radius owner approval using verifiable individual CODEOWNERS reviews.
- **Time-Bound Risk Acceptance** with owner/rationale/review/expiry metadata, fingerprint or graph-path scoping, automatic expiry, critical-regression refusal by default, and lifecycle history for introduced, renewed, lapsed, and scope-changed exceptions.
- **Runtime Guard** for opt-in preview/staging checks using controlled, non-destructive attack-shaped markers, HTTPS/private-network guardrails, JSON/SARIF evidence, optional enforcement, and Vercel Deployment Protection bypass support.
- **Emerging Threat Shield (v2.5)** for full-SHA GitHub Action checks, npm trusted-publishing migration signals, GitLab/Supabase secret detection, and MCP transport/approval/tool-scope guardrails.
- **Trust-Boundary Hardening (v2.6)** for structured MCP config auditing, hard-coded MCP env secrets, unpinned `npx` MCP servers, unsafe privileged PR checkout opt-outs, fork-repository checkout, and npm provenance downgrade signals.
- **MCP Authorization & Protocol Guard (v2.7)** for insecure OAuth endpoints, embedded OAuth/bearer credentials, deprecated DCR/SSE configurations, and strict-mode overbroad OAuth scopes.
- **Runtime DNS Pinning (v2.8)** resolves and validates the target immediately before each runtime request, forces the socket to that approved IP, disables connection reuse, preserves TLS/SNI hostname validation, and rejects public-to-private DNS rebinding.

## Quick start

```yaml
name: DevShield
on:
  pull_request:
    types: [opened, synchronize, reopened]

permissions:
  contents: read
  pull-requests: write
  issues: write

jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
        with:
          fetch-depth: 0

      - uses: mabrig1/mabrig-devshield-ai@v1
        with:
          github-token: ${{ github.token }}
          fail-on: high
```

The default `changed-lines` scope keeps reviews focused on risk introduced by the current change.

## Runtime Guard

Runtime Guard is disabled by default. Enable it only for an explicitly configured preview or staging URL:

```yaml
- uses: mabrig1/mabrig-devshield-ai@main
  with:
    fail-on: critical
    runtime-guard: probe
    runtime-target: ${{ steps.preview.outputs.url }}
    runtime-enforce: false
```

Runtime Guard currently measures runtime/WAF protection signals; a passed-through marker is **not** proof that the application is exploitable. See [Runtime Guard v2.8](docs/runtime-guard.md) for safety defaults, protected-preview configuration, outputs, and enforcement guidance.

## Local CLI and pre-commit protection

Run DevShield before code reaches GitHub:

```bash
npm run scan
```

The local CLI defaults to staged changes and `fail-on=high`. It reads the **Git index snapshot**, not the mutable working-tree copy.

```bash
npm run scan -- --strict --fail-on medium
npm run scan -- --repository --fail-on high
```

See [Local DevShield CLI](docs/LOCAL-CLI.md) and [examples/pre-commit.sh](examples/pre-commit.sh).

For the current developer-security research basis behind v2.5, see [Emerging Threat Research — September 2026](docs/EMERGING-THREATS-2026-09.md).

### Offline dependency evidence

Generate a local npm dependency inventory with package identities, declared licenses, integrity metadata, source transport findings, and traceable evidence:

```bash
npm run inventory
npm run scan -- --inventory --fail-on medium
```

The inventory works offline against npm v2/v3 lockfiles, does not install packages or execute lifecycle scripts, and distinguishes recorded metadata from verified security evidence. It does **not** perform vulnerability lookup, registry-signature verification, package download, or artifact-byte integrity validation.

See [Offline dependency evidence](docs/DEPENDENCY-INVENTORY.md) and [AI assistance disclosure](docs/AI-ASSISTANCE.md).

### Agentic dependency intelligence

Normal DevShield scans can now build a separate dependency mission from the local npm lockfile and repository context:

```yaml
- uses: mabrig1/mabrig-devshield-ai@v1
  with:
    github-token: ${{ github.token }}
    dependency-agentic: auto
```

The mission links evidence such as a GitHub dependency advisory, direct `import`/`require` references, root dependency declarations, declared install scripts, CI workflow presence, and container/IaC files. It labels paths as `evidence-linked`, `contextual`, `heuristic`, or `heuristic-elevated` instead of presenting them as proven exploit chains.

Reports are written to `.devshield/devshield-dependency-mission.json` and `.devshield/devshield-dependency-mission.md`. In local staged scans, `auto` avoids correlating the mutable working-tree lockfile; use `--dependency-agentic on` only when that behavior is intentional.

See [Agentic Dependency Intelligence](docs/DEPENDENCY-AGENT.md).

### Repository Security Graph

DevShield v1.9 turns repository evidence into a bounded graph instead of flattening every signal into a list:

```yaml
- uses: mabrig1/mabrig-devshield-ai@v1
  with:
    github-token: ${{ github.token }}
    security-graph: auto
```

Graph nodes include files, packages, findings, and dependency advisories. Direct edges represent concrete evidence such as package imports, relative source imports, a finding located in a file, or an advisory attached to a package. Contextual edges represent weaker repository context, such as a workflow that runs dependency installation.

The graph derives prioritized multi-hop review paths such as **package → imported module → API route**, **package → source file → security finding**, and **package → dependency-install workflow → CI finding**. Path confidence inherits the weakest edge, so a contextual relationship cannot become a confirmed exploit chain merely because it appears in a longer path.

Artifacts:

- `.devshield/devshield-security-graph.json`
- `.devshield/devshield-security-graph.md`
- `.devshield/devshield-security-graph.dot`

The graph stores no source snippets or secret values. In local staged scans, `security-graph: auto` disables working-tree graphing to avoid mixing staged and unstaged evidence.

See [Repository Security Graph](docs/SECURITY-GRAPH.md).

### Security Control Plane

DevShield v2.0 coordinates the graph evidence into a review-control layer:

```yaml
- uses: mabrig1/mabrig-devshield-ai@v1
  with:
    github-token: ${{ github.token }}
    security-graph: auto
    control-plane: auto
    security-graph-baseline-file: .devshield-security-graph-baseline.json
```

The control plane compares the current graph with a reviewed committed snapshot, calculates the bounded graph neighborhood around changed files, propagates **review priority** from finding/advisory severity with confidence decay, resolves impacted files against CODEOWNERS as ownership hints, and checks whether exact remediation candidates are still observed by rule/file in the current graph.

Review priority is not CVSS, exploit probability, or breach likelihood. A finding that is absent after a scan is recorded as **not observed after scan**, not declared permanently fixed.

Generated artifacts:

- `.devshield/devshield-control-plane.json`
- `.devshield/devshield-control-plane.md`
- `.devshield/devshield-security-graph-baseline-candidate.json`

After reviewing the candidate, commit it as `.devshield-security-graph-baseline.json` to enable graph-to-graph change reporting on later runs.

See [Security Control Plane](docs/CONTROL-PLANE.md).

### Security Graph History & Regression Detection

DevShield v2.1 can retain a reviewed, tamper-evident sequence of graph/control-plane snapshots:

```yaml
- uses: mabrig1/mabrig-devshield-ai@v1
  with:
    github-token: ${{ github.token }}
    security-history: auto
    security-history-file: .devshield-security-history.json
    security-history-signing-key: ${{ secrets.DEVSHIELD_SECURITY_HISTORY_KEY }}
```

Without a signing key, entries are **SHA-256 hash-chained** and DevShield calls them sealed/hash-chained, not signed. When the optional secret is provided, each new entry is additionally authenticated with **HMAC-SHA256**. The key is never written to reports or Cloud telemetry.

Regression classification compares stable finding/advisory nodes and their bounded graph exposure:

- **new risk** — a finding/advisory node appears that was absent from the previous committed history entry;
- **expanded exposure** — an existing risk node reaches more graph nodes than before;
- **reduced exposure** — an existing risk node reaches fewer graph nodes;
- **resolved risk** — a previous risk node is no longer present;
- **unchanged inherited debt** — the same risk node remains with unchanged bounded exposure.

A first snapshot is `unclassified`; DevShield does not pretend there is historical evidence when none exists.

Generated artifacts:

- `.devshield/devshield-security-history.json`
- `.devshield/devshield-security-history.md`
- `.devshield/devshield-security-history-candidate.json`

After review, commit the candidate as `.devshield-security-history.json` to make it the next trusted comparison point. The Action never writes this committed history automatically.

See [Security Graph History](docs/SECURITY-HISTORY.md).

### Policy-Aware Regression Gates

DevShield v2.2 separates **policy outcome** from **enforcement**. The default is `report`, so regression policy is visible but cannot fail CI until a team deliberately switches to `enforce`.

Example:

```yaml
- uses: mabrig1/mabrig-devshield-ai@v1
  with:
    github-token: ${{ github.token }}
    regression-gate: enforce
    regression-new-risk-severity: critical
    regression-expanded-exposure: warn
    regression-inherited-debt: ignore
    regression-blast-radius-threshold: 25
    regression-blast-radius-action: require-owner-approval
```

This policy means:

- block on newly introduced **critical** risk nodes;
- warn when an existing risk node reaches more graph context than before;
- permit unchanged inherited debt without hiding it from history;
- when more than 25 graph nodes are inside the changed-file blast radius, require an active GitHub `APPROVED` review from at least one verifiable **individual** CODEOWNERS owner.

Team CODEOWNERS entries such as `@org/security` are never guessed from reviewer identity. If only team ownership is available, the approval condition remains unresolved. GitHub branch-protection and CODEOWNERS review requirements remain authoritative.

The v2.2 gate is additive: the existing deterministic `fail-on` gate still executes independently. `regression-gate: report` never fails the build even if its calculated decision is `block` or `approval-required`.

Artifacts:

- `.devshield/devshield-regression-policy.json`
- `.devshield/devshield-regression-policy.md`

See [Policy-Aware Regression Gates](docs/REGRESSION-POLICY.md).

### Time-Bound Risk Acceptance

DevShield v2.3 lets teams accept narrowly scoped **regression-policy** risk without suppressing the underlying evidence.

Example `.devshield-exceptions.json`:

```json
{
  "schemaVersion": 1,
  "exceptions": [
    {
      "id": "risk-2026-001",
      "owner": "@security-owner",
      "rationale": "Temporary acceptance while the dependency upgrade is tested in staging.",
      "reviewedAt": "2026-09-19T00:00:00Z",
      "expiresAt": "2026-10-10T00:00:00Z",
      "scope": {
        "findingFingerprints": [
          "0123456789abcdef0123456789abcdef"
        ],
        "graphPathIds": []
      }
    }
  ]
}
```

A valid exception must have an ID, owner, meaningful rationale, review timestamp, expiry timestamp, and at least one finding fingerprint or graph path ID. The default maximum acceptance duration is **90 days**.

Expired exceptions are ignored automatically. Invalid exceptions are ignored and reported. By default, matching **critical** regression items are not accepted. Even when critical regression acceptance is explicitly enabled, the original deterministic finding, SARIF entry, annotation, graph node, and `fail-on` behavior remain unchanged.

History records only compact lifecycle evidence—exception ID, timestamps, status, and a scope hash—not the owner or rationale text. This allows v2.3 to distinguish exception **introduced**, **renewed**, **lapsed**, and **scope changed** events without copying sensitive internal rationale into the history chain.

Artifacts:

- `.devshield/devshield-risk-exceptions.json`
- `.devshield/devshield-risk-exceptions.md`

See [Time-Bound Risk Acceptance](docs/RISK-EXCEPTIONS.md).

### Approval-gated remediation

After a scan generates an agentic plan, inspect the proposed exact hardening edits:

```bash
npm run remediate
npm run remediate -- --apply --approve <missionId> --dry-run
npm run remediate -- --apply --approve <missionId>
npm run scan -- --repository --fail-on high
```

The GitHub Action never applies these edits. Local application requires the scan mission ID and rejects stale source lines or symlink paths. See [Approval-Gated Auto-Remediation](docs/AUTO-REMEDIATION.md).

## Optional AI review

Store `OPENROUTER_API_KEY` in **Repository settings → Secrets and variables → Actions**:

```yaml
      - uses: mabrig1/mabrig-devshield-ai@v1
        with:
          github-token: ${{ github.token }}
          openrouter-api-key: ${{ secrets.OPENROUTER_API_KEY }}
          model: openrouter/auto
          fail-on: high
```

AI mode is optional. Deterministic scanning, scoring, JSON reporting, SARIF output, annotations, and merge gating work without any AI provider.

## Optional DevShield Cloud

DevShield v1.4 can export structured scan metadata to a managed DevShield Cloud endpoint while keeping source code and diff text inside the customer's runner.

```yaml
      - id: devshield
        uses: mabrig1/mabrig-devshield-ai@v1
        with:
          github-token: ${{ github.token }}
          fail-on: high
          cloud-api-url: https://<managed-devshield-cloud-host>/api/v1/scans
          cloud-token: ${{ secrets.DEVSHIELD_CLOUD_TOKEN }}
```

Cloud export is disabled by default. The exported payload contains finding/risk metadata, fingerprints, file/line locations and dependency advisory metadata, but **not source code, source snippets, diff text, GitHub tokens or the Cloud token**.

Use `cloud-required: true` when a paid/regulated deployment should fail if managed ingestion is unavailable.

See [DevShield Cloud Integration Contract](docs/CLOUD-INTEGRATION.md).

## Policy-as-code

Create `.devshield.json` in the repository root:

```json
{
  "policy": "balanced",
  "scanScope": "changed-lines",
  "excludePaths": [
    "fixtures/**",
    "generated/**"
  ],
  "ignoreRules": [
    "debug-mode"
  ],
  "ignoreCategories": [],
  "severityOverrides": {
    "shell-exec": "high"
  },
  "maxFileBytes": 1500000,
  "inlineSuppressions": true,
  "dependencyReview": true,
  "dependencySeverity": "low",
  "dependencyDenyLicenses": [],
  "baselineFile": ".devshield-baseline.json",
  "baselineMode": "new-only",
  "agenticMode": "plan",
  "remediationMode": "propose",
  "dependencyAgenticMode": "auto",
  "securityGraphMode": "auto",
  "controlPlaneMode": "auto",
  "securityGraphBaselineFile": ".devshield-security-graph-baseline.json",
  "securityHistoryMode": "auto",
  "securityHistoryFile": ".devshield-security-history.json",
  "securityHistoryMaxEntries": 60,
  "regressionGateMode": "report",
  "regressionNewRiskSeverity": "critical",
  "regressionExpandedExposure": "warn",
  "regressionInheritedDebt": "ignore",
  "regressionBlastRadiusThreshold": 0,
  "regressionBlastRadiusAction": "warn",
  "riskExceptionsMode": "auto",
  "riskExceptionsFile": ".devshield-exceptions.json",
  "riskExceptionMaxDays": 90,
  "riskExceptionAllowCritical": false
}
```

Action inputs take precedence when explicitly set. `exclude-paths` is merged with configuration-file exclusions.

### Policies

| Policy | Purpose |
|---|---|
| `balanced` | High-signal default checks for normal pull requests |
| `strict` | Balanced checks plus lower-confidence hardening rules |
| `secrets-only` | Credential and secret exposure checks only |

### Scan scopes

| Scope | Behavior |
|---|---|
| `changed-lines` | Default. Scans newly added lines in changed files |
| `changed-files` | Scans all lines in changed files |
| `repository` | Scans tracked text files across the repository, up to `max-files` |
| `staged` | Local CLI/pre-commit mode; scans newly added lines from the Git index |

## Dependency intelligence

When a pull request supplies `github-token`, DevShield can query GitHub's dependency-review API and turn newly introduced vulnerable packages into normal DevShield findings. These findings participate in risk scoring and `fail-on` just like code findings.

You can also deny licenses for newly introduced dependencies:

```yaml
with:
  github-token: ${{ github.token }}
  dependency-review: auto
  dependency-severity: low
  dependency-deny-licenses: AGPL-3.0, GPL-3.0
```

If GitHub dependency review is unavailable, DevShield warns and continues local deterministic scanning.

## Finding baselines

For legacy repositories, generate a reviewed fingerprint baseline with a repository-scope scan. Commit the reviewed candidate as `.devshield-baseline.json`, then use:

```yaml
with:
  baseline-file: .devshield-baseline.json
  baseline-mode: new-only
```

Existing baseline findings remain visible in JSON/SARIF, while only new findings contribute to the merge gate and risk score.

See [Dependency Intelligence & Baselines](docs/DEPENDENCY-BASELINES.md).

## Suppressing intentional findings

For non-critical findings, use a narrow inline suppression:

```js
// devshield:ignore shell-exec
exec("controlled-static-command");
```

Or suppress all non-critical rules on the next/current line:

```js
// devshield:ignore
```

Critical findings cannot be suppressed inline. If a critical detector is intentionally triggered by a fixture, exclude the fixture path or explicitly ignore the rule in `.devshield.json` so the exception is visible in repository policy.

## SARIF and GitHub Code Scanning

DevShield writes:

- `.devshield/devshield-report.json`
- `.devshield/devshield.sarif`

To upload SARIF into GitHub Code Scanning:

```yaml
permissions:
  contents: read
  pull-requests: write
  issues: write
  security-events: write

steps:
  - uses: actions/checkout@v7
    with:
      fetch-depth: 0

  - id: devshield
    uses: mabrig1/mabrig-devshield-ai@v1
    with:
      github-token: ${{ github.token }}
      fail-on: high

  - name: Upload DevShield SARIF
    if: always()
    uses: github/codeql-action/upload-sarif@v4
    with:
      sarif_file: ${{ steps.devshield.outputs.sarif-file }}
```

SARIF availability in GitHub depends on the repository and GitHub security features enabled for that repository.

## What DevShield checks

### Secrets and credentials
Private keys, GitHub tokens, AI-provider keys, AWS access keys, Stripe live keys, Slack tokens, Google API keys, SendGrid keys, credential-bearing URLs, package-registry credentials, tracked `.env` files, browser-exposed secret-like `NEXT_PUBLIC_` variables, and strict-mode generic hardcoded secrets.

### Injection and unsafe execution
Dynamic `eval`, shell execution, interpolated shell commands, Python `os.system`, `subprocess(..., shell=True)`, unsafe pickle deserialization, unsafe YAML loading, request-built SQL, DOM HTML sinks, and React `dangerouslySetInnerHTML`.

### Authentication, transport, and configuration
Disabled TLS verification, Python `verify=False`, disabled JWT signature verification, wildcard CORS, debug mode, MD5/SHA-1 hardening checks, and unsafe file permissions.

### GitHub Actions and software supply chain
Moving Action refs, strict-mode mutable Action refs, `permissions: write-all`, risky `pull_request_target`, direct interpolation of untrusted PR/event text into `run:`, privileged PR-head checkout patterns, remote `curl|sh`/`wget|sh`, and floating npm dependency declarations.

### IaC and containers
World-open CIDRs, wildcard IAM actions/resources, public Terraform ACLs, Kubernetes privileged mode, host networking, root UID, privilege escalation, Docker root users, privileged Docker execution, host networking in Compose, and all-capability grants.

See [`docs/RULES.md`](docs/RULES.md) for policy guidance.

## Inputs

| Input | Default | Purpose |
|---|---|---|
| `github-token` | empty | Posts/updates the PR summary comment |
| `openrouter-api-key` | empty | Enables AI-assisted second pass |
| `model` | `openrouter/auto` | OpenRouter model slug |
| `fail-on` | `critical` | `critical`, `high`, `medium`, `low`, `none` |
| `comment` | `true` | Post/update a PR comment |
| `max-files` | `120` | Maximum text files selected for scanning |
| `max-file-bytes` | engine/config default | Per-file read cap |
| `exclude-paths` | empty | Comma-separated exclusion globs |
| `config-file` | `.devshield.json` | JSON policy file |
| `policy` | config or `balanced` | `balanced`, `strict`, `secrets-only` |
| `scan-scope` | config or `changed-lines` | `changed-lines`, `changed-files`, `repository` |
| `inline-suppressions` | config or `true` | Enable non-critical `devshield:ignore` comments |
| `dependency-review` | config or `auto` | Use GitHub dependency review on pull requests |
| `dependency-severity` | config or `low` | Minimum vulnerable-dependency severity to report |
| `dependency-deny-licenses` | empty | Comma-separated SPDX licenses to reject |
| `baseline-file` | config or `.devshield-baseline.json` | Fingerprint baseline file |
| `baseline-mode` | config or `new-only` | `new-only`, `report`, or `off` |
| `agentic-mode` | config or `plan` | `off`, `plan`, or `ai` |
| `remediation-mode` | config or `propose` | `off` or proposal-only `propose` |
| `dependency-agentic` | config or `auto` | `off`, `auto`, or `on`; correlates lockfile/dependency/source/CI context |
| `security-graph` | config or `auto` | `off`, `auto`, or `on`; builds the repository security graph and traceable paths |
| `control-plane` | config or `auto` | `off`, `auto`, or `on`; enables graph diffing, blast radius, review priority, ownership hints, and remediation verification |
| `security-graph-baseline-file` | `.devshield-security-graph-baseline.json` | Reviewed committed graph snapshot used for graph diffing |
| `security-history` | config or `auto` | `off`, `auto`, or `on`; enables tamper-evident graph history and regression classification |
| `security-history-file` | `.devshield-security-history.json` | Reviewed committed history chain used for the next comparison |
| `security-history-max-entries` | `60` | Maximum retained history entries, bounded to 1–200 |
| `security-history-signing-key` | empty | Optional HMAC-SHA256 key; supply via GitHub secret, never repository config |
| `regression-gate` | config or `report` | `off`, `report`, or `enforce`; only `enforce` may fail CI |
| `regression-new-risk-severity` | `critical` | `critical`, `high`, `medium`, `low`, or `none` |
| `regression-expanded-exposure` | `warn` | `ignore`, `warn`, or `block` |
| `regression-inherited-debt` | `ignore` | `ignore` or `warn` |
| `regression-blast-radius-threshold` | `0` | Impacted-node threshold; `0` disables threshold policy |
| `regression-blast-radius-action` | `warn` | `ignore`, `warn`, `block`, or `require-owner-approval` |
| `risk-exceptions` | config or `auto` | `off`, `auto`, or `on`; applies time-bound acceptance only to regression policy |
| `risk-exceptions-file` | `.devshield-exceptions.json` | Reviewed repository-relative risk-acceptance JSON file |
| `risk-exception-max-days` | `90` | Maximum reviewed duration, bounded to 1–365 days |
| `risk-exception-allow-critical` | `false` | Allow critical regression-policy acceptance only; deterministic findings remain unsuppressed |
| `sarif` | `true` | Generate SARIF |
| `report-dir` | `.devshield` | Directory for machine-readable reports |
| `cloud-api-url` | empty | Optional HTTPS DevShield Cloud ingestion endpoint |
| `cloud-token` | empty | Optional managed installation token stored as a secret |
| `cloud-required` | `false` | Fail if configured Cloud ingestion cannot complete |

## Outputs

- `findings-count`
- `new-findings`
- `existing-findings`
- `dependency-findings`
- `dependency-review-status`
- `risk-score`
- `risk-level`
- `scanned-files`
- `ignored-findings`
- `report-file`
- `sarif-file`
- `baseline-output-file`
- `cloud-export-status`
- `agentic-state`
- `agentic-tasks`
- `agentic-attack-paths`
- `agentic-plan-file`
- `remediation-candidates`
- `remediation-plan-file`
- `dependency-agentic-state`
- `dependency-agentic-packages`
- `dependency-agentic-paths`
- `dependency-agentic-references`
- `dependency-agentic-plan-file`
- `security-graph-state`
- `security-graph-nodes`
- `security-graph-edges`
- `security-graph-paths`
- `security-graph-file`
- `security-graph-markdown`
- `security-graph-dot`
- `control-plane-state`
- `control-plane-graph-changes`
- `control-plane-blast-radius`
- `control-plane-ranked-nodes`
- `control-plane-ownership-hints`
- `control-plane-remediation-checks`
- `control-plane-file`
- `control-plane-markdown`
- `security-graph-baseline-candidate`
- `security-history-state`
- `security-history-sequence`
- `security-history-new-risk`
- `security-history-expanded-exposure`
- `security-history-reduced-exposure`
- `security-history-resolved-risk`
- `security-history-inherited-debt`
- `security-history-signed`
- `security-history-file`
- `security-history-markdown`
- `security-history-candidate`
- `regression-gate-state`
- `regression-gate-decision`
- `regression-gate-failed`
- `regression-gate-blocks`
- `regression-gate-warnings`
- `regression-gate-approval-required`
- `regression-gate-file`
- `regression-gate-markdown`
- `risk-exceptions-status`
- `risk-exceptions-active`
- `risk-exceptions-expired`
- `risk-exceptions-invalid`
- `risk-exceptions-applied`
- `risk-exceptions-critical-skipped`
- `risk-exceptions-introduced`
- `risk-exceptions-renewed`
- `risk-exceptions-lapsed`
- `risk-exceptions-file`
- `risk-exceptions-markdown`

## Risk scoring

DevShield scores findings by severity and caps repeated hits from the same rule/file so one noisy pattern does not dominate the score. The risk level always reflects the highest active severity:

- `critical`
- `high`
- `medium`
- `low`

Use `fail-on` independently from the numerical score to define the merge gate.

## Security and privacy model

Deterministic scanning runs on the GitHub Actions runner.

When AI mode is enabled:

1. Excluded paths are not sent to the AI reviewer.
2. The diff is truncated.
3. Common secret formats are redacted.
4. The model receives a system instruction to treat code, comments, and diff text as **untrusted data**, not instructions.
5. Deterministic findings are passed without source snippets.

Repositories with source-code residency restrictions should leave AI mode disabled.

DevShield Cloud export is a separate opt-in path. Its payload contains structured findings and metadata but excludes source code, source snippets, diff text and authentication tokens. See [docs/CLOUD-INTEGRATION.md](docs/CLOUD-INTEGRATION.md).

## Design philosophy

DevShield is designed to complement—not impersonate—full SAST, dependency-vulnerability intelligence, secret-validity checking, and human AppSec review. Its advantage is a fast, transparent merge-risk layer that works immediately, produces portable output, and can grow into deeper repository-context analysis without forcing teams to send code to an LLM.

See [Agentic Security Engine](docs/AGENTIC-ENGINE.md) for the observe → prioritize → attack-path → remediate → verify workflow, [Agentic Dependency Intelligence](docs/DEPENDENCY-AGENT.md) for cross-layer package correlation, [Repository Security Graph](docs/SECURITY-GRAPH.md) for traceable graph relationships and multi-hop paths, [Security Control Plane](docs/CONTROL-PLANE.md) for graph diffing, blast radius and review coordination, [Security Graph History](docs/SECURITY-HISTORY.md) for hash-chained regression history, [Policy-Aware Regression Gates](docs/REGRESSION-POLICY.md) for longitudinal policy enforcement, [Time-Bound Risk Acceptance](docs/RISK-EXCEPTIONS.md) for scoped exception governance, and [Approval-Gated Auto-Remediation](docs/AUTO-REMEDIATION.md) for the exact-patch approval model.

See [`docs/COMPETITIVE-ROADMAP.md`](docs/COMPETITIVE-ROADMAP.md) for the next expansion targets.

## Development

```bash
npm test
```

The smoke suite validates:

- critical secret and workflow findings
- diff-aware noise reduction
- inline suppression behavior
- configuration-file policy
- JSON/SARIF generation
- dependency-review findings and license policy
- offline dependency evidence and agentic dependency correlation
- repository security graph construction and multi-hop confidence propagation
- security control plane graph diffing, blast radius, ownership hints, review priority, and remediation observation checks
- security history chain integrity, optional HMAC verification, and exposure-regression classification
- policy-aware regression report/enforce behavior, severity thresholds, blast-radius actions, and owner-approval verification
- time-bound exception validation, automatic expiry, fingerprint/path scoping, critical-risk guardrails, and lifecycle history
- v2.5 checks for immutable Action refs, npm publishing credentials, MCP trust boundaries, and modern provider tokens
- v2.6/v2.7 structured MCP, OAuth, protocol-deprecation, and privileged-workflow trust-boundary checks
- v2.8 Runtime Guard DNS pinning and DNS-rebinding regression coverage
- baseline new-versus-existing classification
- staged-index CLI blocking and safe staged changes
- merge-failure thresholds

## Marketplace release

1. Confirm **DevShield CI** passes.
2. Publish the release.
3. Keep the stable `v1` compatibility ref pointed at the latest backward-compatible v1 release.
4. Validate the Action from a separate repository using `mabrig1/mabrig-devshield-ai@v1`.

## Professional services and commercial edition

The public Action and CLI remain useful, transparent and self-managed. MABRIG Technologies monetizes DevShield through:

- **DevShield Launch Setup** — installation, baseline, merge gates, SARIF and policy tuning
- **Security Hardening Sprint** — multi-repository hardening, dependency/license policy and remediation reporting
- **Team Security Rollout** — shared policy, CI deployment and developer onboarding
- **Managed Security Retainer** — ongoing triage, policy tuning, reporting and priority support
- **DevShield Cloud / GitHub App** — planned managed repository context, organization policy, analytics, remediation workflows and Marketplace subscriptions

See [docs/PRICING.md](docs/PRICING.md), [SUPPORT.md](SUPPORT.md), [PRIVACY.md](PRIVACY.md) and [TERMS.md](TERMS.md).

**Sales & support:** mabrig@mabrigkorie.org

© 2026 MABRIG Technologies.
