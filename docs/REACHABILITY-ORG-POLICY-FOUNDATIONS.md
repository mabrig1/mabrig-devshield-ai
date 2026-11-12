# Reachability Evidence + Organization Policy Foundations (November 2026)

**Status:** opt-in, review-stage foundations. These changes do **not** install CodeQL, provide a native whole-program taint solver, enforce organization policy in repositories, deploy a Worker, create a GitHub App, charge customers, or prove that any vulnerability is exploitable. Existing free Action, risk gates, and deployment remain unchanged.

## 1. Source-to-sink evidence, not another regex detector

The importer in `src/reachability-evidence.mjs` accepts **CodeQL SARIF 2.1.0** with `codeFlows[].threadFlows[].locations[]`. CodeQL performs the analysis; DevShield validates the reported locations against a checkout, extracts an explicit first-to-last path, and produces an evidence report. This is a useful, dependency-free interoperability layer while a standalone multi-language analyzer is not available.

CodeQL supports JavaScript/TypeScript, Python and Go. Exact query coverage depends on the configured CodeQL security suite and framework models. Not every result contains source-to-sink path evidence; those results are **not upgraded** to confirmed findings.

```bash
# Produce SARIF through your authorized CodeQL analysis workflow first.
# Run within the same checked-out revision that produced the SARIF:
node bin/reachability.mjs --sarif ./codeql-results/javascript.sarif \
  --workspace . --out ./devshield-path-evidence.json
```

Reports include stable fingerprints, rule ID, analyzer, severity if CodeQL supplied a numeric security-severity, source/sink file and line, intermediate steps, evidence-completeness score (not a statistical exploit probability), explicit preconditions, and remediation guidance. No source snippets, secrets, or entire files are exported. Paths with traversal, symlink escapes, absent files, invalid line numbers, missing flows, or an unrecognized analyzer are dropped. Inputs are capped at 8 MiB; output is created with private mode and refuses to overwrite existing files.

**Trust boundary:** metadata can be forged by whoever supplies SARIF. The module recognizes CodeQL-labeled output but does not cryptographically authenticate its producer. For trusted decisions, run a pinned CodeQL workflow on the exact revision in a trusted CI context, attach checksums/provenance, and prevent untrusted pull requests from replacing the SARIF. Do not treat `engine-reported-code-flow` as proof that a deployed path is exploitable. No automatic merge failure, AI autofix, or repository write is triggered.

**Next technical milestone:** add opt-in provenance verification and source/sink classifications; benchmark precision and recall against test fixtures and public SAST suites; determine whether approved CodeQL/Semgrep integrations supply desired cross-file coverage. Prove authorization/IDOR paths separately with trust-boundary models and authorization tests, rather than promising that raw taint propagation detects business logic automatically.

- CodeQL support: https://docs.github.com/en/code-security/concepts/code-scanning/codeql/codeql-code-scanning
- CodeQL SARIF output: https://github.com/github/codeql-action/blob/main/analyze/action.yml
- SARIF concepts: https://docs.github.com/en/code-security/concepts/code-scanning/sarif-files

## 2. Tenant-scoped centralized organization policy API

The commercial Worker already has tenant-scoped API keys and scan ingestion. This phase adds a **single versioned organization policy document per tenant** with an explicit repository allowlist, strict field validation, optimistic compare-and-swap updates, separate `policies:read` / `policies:write` scopes, and an audit row appended by SQL triggers on every successful write.

**Operator-only schema migration (staging first):**

```bash
# Confirm account and database ID before executing; back up D1 first.
npx wrangler d1 execute devshield-commercial --remote \
  --file commercial-api/org-policy-migration.sql
```

This command is **documentation only**; this PR does not run it. Existing `commercial-api/schema.sql` remains the base schema. Introduce scoped API credentials only for approved administrators; existing scan-only keys are not automatically given policy permissions.

| Endpoint | Required scope | Behavior |
| --- | --- | --- |
| `GET /v1/org-policy` | `policies:read` | Returns only the authenticated tenant's document, revision, hash and ETag. |
| `PUT /v1/org-policy` | `policies:write` | Requires `If-Match: "0"` to initialize or the last revision (e.g. `"1"`) to update. Returns 409 on conflict. |

**Example JSON for PUT** (supply bearer token through a protected secret, never inline in a repository):

```json
{
  "schemaVersion": 1,
  "name": "security-baseline",
  "repositories": ["example-org/api", "example-org/dashboard"],
  "controls": {
    "policy": "strict",
    "failOn": "high",
    "dependencySeverity": "medium",
    "legalComplianceMode": "advisory",
    "riskExceptionMaxDays": 14,
    "riskExceptionAllowCritical": false
  }
}
```

The API **stores and returns** a policy document. The free Action does not yet fetch, authenticate, verify, merge, or enforce those controls. A repository listed in the pack is not evidence that the GitHub App was authorized for that repository; before enforcement, validate installation IDs and repository membership from trusted GitHub App credentials, bind each tenant to authorized installations, and sign/version the effective policy delivered to CI.

For safe production rollout: add RBAC and admin authentication; migration/backups/retention and immutable audit export; GitHub App installation lifecycle, webhook signature verification, repository authorization, and uninstall cleanup; policy inheritance and lock/floor semantics; CODEOWNERS review; managed AI keys kept server-only and isolated per tenant; quota/billing reconciliation; dashboard and customer support. None of these are implemented here.

**Payments:** GitHub Marketplace subscriptions require an approved App and handling `marketplace_purchase` webhook events and effective dates. Do not call customer policy or scan quotas a paid billing ledger.

- GitHub Marketplace API: https://docs.github.com/en/apps/github-marketplace/using-the-github-marketplace-api-in-your-app
- Marketplace webhooks: https://docs.github.com/en/apps/github-marketplace/using-the-github-marketplace-api-in-your-app/webhook-events-for-the-github-marketplace-api

## Verification

```bash
node --test test/reachability-evidence.test.mjs
node --test commercial-api/test/*.test.mjs
node --check src/reachability-evidence.mjs
node --check bin/reachability.mjs
node --check commercial-api/worker/src/org-policy.mjs
node --check commercial-api/worker/src/index.mjs
npm test
```

The new tests cover CodeQL path presence, deterministic fingerprints, symlink/traversal rejection, invalid pack fields, cross-tenant isolation, 409 conflicts, separate scopes, and audit history. Run the existing complete CI matrix before merge. Require an independent security review before any deployment or real customer onboarding.
