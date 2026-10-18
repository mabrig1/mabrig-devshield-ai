# DevShield Commercial API — MVP (deployment candidate)

This package adds a **tenant-isolated Cloudflare Worker + D1 ingestion API** for MABRIG DevShield AI. It is an initial commercial platform backend, **not** a deployed SaaS product, payment system, live WAF control plane, or completed security audit.

The existing GitHub Action already supports `cloud-api-url` and `cloud-token` exports. This Worker receives **schemaVersion=1** export payloads and records **selected metadata and structured findings**, not full source code or diffs.

## API endpoints

| Route | Scope | Purpose |
| --- | --- | --- |
| `GET /health` | Public | Readiness without secret data |
| `POST /api/v1/scans` | `scans:write` | Existing GitHub Action export endpoint; aliases `/v1/scans` |
| `GET /v1/scans?limit=20` | `scans:read` | Tenant's recent scans (max 50 per response) |
| `GET /v1/scans/{id}` | `scans:read` | Tenant-scoped structured report |
| `GET /v1/usage` | `scans:read` | Tenant's daily scan count and configured allowance |

All protected requests use `Authorization: Bearer <api-key>`. Browser CORS is intentionally not enabled. Other routes respond 404. Tenant identity is **always resolved from the hashed API key**; clients cannot choose a tenant in their request. API keys are 256-bit random values; only SHA-256 digests are stored in D1.

**Limits:** maximum 256 KiB request, 250 structured findings, 50 listed scans, tenant-scoped daily quota. Replays from the same GitHub workflow run are deduplicated automatically using run metadata. For other API clients, include a unique `Idempotency-Key` header (8–128 safe characters). Unique keys identify one logical scan and should not be reused for unrelated payloads.

### Run tests

```bash
node --test commercial-api/test/*.test.mjs
node --check commercial-api/worker/src/index.mjs
```

Tests use Node's built-in SQLite and a D1-compatible adapter; no paid Cloudflare account is required to run unit/integration tests. Production must still be tested against real D1 and Cloudflare Workers.

## Cloudflare deployment (operator-controlled)

These are deployment **instructions**, not confirmation that DNS or production is configured.

1. Create a Cloudflare D1 database named `devshield-commercial` in the Cloudflare account for `mabrigkorie.org`. Create it with `npx wrangler d1 create devshield-commercial`.
2. Copy `wrangler.toml.example` to `commercial-api/wrangler.toml`, and replace `database_id` with the real D1 database UUID. **Do not guess a UUID or paste secrets in source code.** The local config is gitignored.
3. Apply `commercial-api/schema.sql` with `npx wrangler d1 execute devshield-commercial --remote --file commercial-api/schema.sql` after verifying you are using the correct account/database.
4. Locally (not in CI), generate tenant SQL + a one-time key:

   ```bash
   node commercial-api/bin/provision.mjs demo-customer "Demo Customer" 50
   ```

   Securely record the generated key; apply the output SQL statements to D1 using an operator-only terminal. Never commit the output. To rotate, issue a new key record and revoke the previous `api_keys` row.
5. In `commercial-api/`, install Wrangler and deploy only after tests:

   ```bash
   npm install
   npx wrangler deploy
   ```

6. After hostname verification, attach `api.devshield.mabrigkorie.org` as a Cloudflare Workers custom domain/route. Set `cloud-api-url` in an opted-in customer's GitHub Action to `https://api.devshield.mabrigkorie.org/api/v1/scans`, and `cloud-token` from `secrets.DEVSHIELD_CLOUD_TOKEN`.
7. Test isolated tenants, key revocation, quotas, duplicate delivery, downstream consumer Action exports and network failures against a **staging** Worker before accepting real private-repository customers.

**GitHub Action example:**

```yaml
- uses: mabrig1/mabrig-devshield-ai@v1
  with:
    github-token: ${{ github.token }}
    cloud-api-url: https://api.devshield.mabrigkorie.org/api/v1/scans
    cloud-token: ${{ secrets.DEVSHIELD_CLOUD_TOKEN }}
    cloud-required: false
```

The ingestion API is intentionally separate from `devshield.mabrigkorie.org` (future customer portal) and `mabrigkorie.org/devshield` (future marketing landing page).

## Security boundaries

- Authentication, scoped keys, tenant-isolated reads, parameterized D1 queries, basic caps, atomic SQL daily scan quota and GitHub run idempotency are implemented.
- No source/diff snippets are persisted; unknown finding fields are rejected, and auxiliary fields not in the structured contract are discarded.
- Logs do not deliberately include request bodies, tokens or findings.
- Only trusted operators can currently provision tenants and keys. There is **no self-service registration**, password recovery, subscription checkout, API key management UI, paid feature entitlements, or webhook delivery.
- Per-IP network abuse controls, trusted-edge routing, database backups, expiration/retention, tenant deletion/export, formal DPA/privacy documentation, customer support SLA, penetration testing, and billing reconciliation are **required before commercial production**.
- Scan counts are allowance controls, **not** a billing ledger; don't charge customers until usage accounting and retries are audited. D1 query consistency and Cloudflare platform rate limiting must be verified under concurrency.
- `GET /health` is public and intentionally provides only component/version availability, not customer data.

## Commercial roadmap

1. **Portal**: authenticated customer dashboard and role-scoped organization/team management at `devshield.mabrigkorie.org`.
2. **Billing**: server-verified Paystack/Stripe subscriptions, webhook signature checks, cancellation/grace-period handling and transparent usage limits.
3. **GitHub App**: verified per-installation identities, customer onboarding, repository authorization and policy configuration.
4. **Managed WAAP**: provisioning and observing per-customer Worker policies; never let one tenant edit another origin or WAF policy.
5. **Operations**: security review, observability, durable rate limiting, incident response, encrypted backups, deletion/export and end-to-end deployment certification.

### Contact

MABRIG Technologies — mabrig@mabrigkorie.org
