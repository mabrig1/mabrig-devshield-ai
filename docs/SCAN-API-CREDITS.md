# DevShield Scan API & Scan Credits — Experimental (November 2026)

The API has TWO deliberately separate components: a local authenticated API that executes deterministic scanners **on the customer's own workstation**, and a multi-tenant Cloudflare Worker that accepts **only bounded structured report metadata**, not source files.

**Status:** code proposal, not an active public endpoint or commercial billing service. No production D1 migration, DNS change, checkout execution, payment, customer provisioning, deployment, or entitlement change is performed by this PR.

## A. Local Scan API (can scan source without uploading)

Set a locally generated 32+ character URL-safe secret in DEVSHIELD_LOCAL_API_TOKEN. Run:

    node bin/local-scan-api.mjs --workspace /trusted/project --port 9339

The listener binds **only 127.0.0.1**; neither source nor reports are forwarded. Requests need:

    Authorization: Bearer <DEVSHIELD_LOCAL_API_TOKEN>
    Content-Type: application/json

Available endpoints:

| HTTP operation | Mode | Meaning |
| --- | --- | --- |
| GET /v1/capabilities | metadata | Local capabilities and supported output formats |
| POST /v1/scans/full | full | Read-only source preflight, API trust, compliance, optional npm lockfile, context graph |
| POST /v1/scans/staged-diff | staged-diff | Inspect only indexed Git files using git diff --cached --name-only |
| POST /v1/scans/preflight | preflight | Untrusted-project threat indicators without running build hooks |
| POST /v1/scans/dependency-inventory | dependency-inventory | Deterministic npm lockfile metadata checks, not live CVE consultation |
| POST /v1/scans/api-agent-trust | api-agent-trust | Static API and agent trust heuristics |
| POST /v1/scans/legal-compliance | legal-compliance | Advisory legal/compliance signals, **not legal advice** |
| POST /v1/scans/waap-policy | waap-policy | OpenAPI v3 JSON → candidate WAAP policy, never deploys it |
| POST /v1/scans/security-graph | security-graph | Repository context graph; edges are hypotheses, not proof of exploitation |

JSON body is {} or {"format":"sarif"}; in waap-policy mode you can supply a **relative** file path such as {"spec":"api/openapi.json"}. The server's --workspace is fixed at startup; API callers cannot select arbitrary directories or execute commands. Responses are JSON or SARIF; no automatic uploads. Runs are read-only, bounded, offline, and heuristic. Staged-diff requires a trusted Git index. Syntax, tests, and security review are required before consumer release.

Local scans may expose filenames, remediation messages, and graph metadata to the local caller. Treat the local token as a secret, use only localhost, and do not proxy it onto the public Internet. This is not a full antivirus or EDR.

## B. Cloud Report Ingestion API (not server-side source scanning)

Existing POST /api/v1/scans remains backward compatible. New aliases accept privacy-limited DevShield report metadata with a type label:

    POST /v1/scan-reports/full
    POST /v1/scan-reports/staged-diff
    POST /v1/scan-reports/preflight
    POST /v1/scan-reports/dependency-inventory
    POST /v1/scan-reports/api-agent-trust
    POST /v1/scan-reports/legal-compliance
    POST /v1/scan-reports/waap-policy
    POST /v1/scan-reports/security-graph

Routes authenticate with scans:write and the existing API key. The body uses the **existing normalized schemaVersion=1 scan report format**, optionally containing scanType; a path/body mismatch is rejected. Server-side source scanning is **not** implemented and not claimed. The new route simply ingests a result *already calculated locally*. Do not upload raw source, SARIF snippets, logs, webhook payloads, or private model prompts.

GET /v1/capabilities (scans:read) describes the actual cloud scope. GET /v1/credits (credits:read) returns tenant-specific balance plus today's use; balances of other tenants are never returned.

## C. Opt-in scan credits ("token-as-API" metering foundation)

The proposed additive migration in commercial-api/scan-credit-migration.sql adds:
- scan_credit_grants and a trigger that credits the tenant wallet for operator-issued grants.
- scan_credit_wallets with nonnegative scan balance.
- scan_credit_debits recording each genuinely inserted scan.
- A **SQL AFTER INSERT** trigger that atomically deducts one scan credit **only** when a new scan is committed. Idempotent duplicates do not debit twice; insufficient credits abort the scan transaction.
- api_key_request_buckets for opt-in per-key requests per UTC minute.

**Manual staging prerequisites:** apply the base schema first; back up the D1 database; apply the new migration; test wallet balance, duplicates, quota, tenant isolation, concurrent API keys, revocation, and recovery in staging. Example operator grant pattern (use placeholders, execute only after review):

    INSERT INTO scan_credit_grants (id, tenant_id, amount, reference, issued_by)
    VALUES ('unique-grant-id', 'approved-tenant-id', 100, 'manual-trial-2026-11', 'operator');

The grant insert trigger creates or tops up the tenant wallet. Use a unique grant ID for idempotency and documented operator approval. No public grant or payment endpoint is exposed.

Set CREDIT_METERING_REQUIRED=true **only after** every paying tenant has an account, grants, reconciliation, and the migration has run. Per-key limiting is opt-in after migration using ENFORCE_API_KEY_RATE_LIMIT=true and SCAN_REQUESTS_PER_MINUTE=30 (allowed 1..120). Existing daily tenant scan caps remain enforced even with credits. Request buckets require scheduled retention and operational monitoring.

**"Token" means a scan credit. It is NOT OpenRouter/LLM tokens, a digital asset, or proof of purchased usage.** Balances/quotas are metering primitives; there is **no** production payment capture, Stripe/Paystack checkout, refunds, recurring billing, usage invoicing, fraud protection, marketplace listing, or advertised live prices in this change.

## Verification

    node --test commercial-api/test/*.test.mjs
    node --test test/local-scan-api.test.mjs
    node --check commercial-api/worker/src/index.mjs
    node --check src/local-scan-api.mjs
    npm test

Security hardening before deployment: threat model the localhost server; replay/attempt rate controls and proxy filtering, local sandboxing or process isolation for malformed/untrusted artifacts; D1 retention pruning for request buckets, secret/key rotation and audit; versioned SDKs, authenticated tenant onboarding, trusted identity for connected repositories; verified billing webhooks; load/concurrency tests; TLS and production staging certification.
