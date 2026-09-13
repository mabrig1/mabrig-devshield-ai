# DevShield Cloud Integration Contract

MABRIG DevShield AI v1.4 introduces an **opt-in** bridge from the self-managed Action to a managed DevShield Cloud service.

The public scanner remains fully functional without DevShield Cloud.

## Enable Cloud export

Store the customer installation token as a GitHub Actions secret and configure the managed ingestion endpoint:

```yaml
- id: devshield
  uses: mabrig1/mabrig-devshield-ai@v1
  with:
    github-token: ${{ github.token }}
    fail-on: high
    cloud-api-url: https://<managed-devshield-cloud-host>/api/v1/scans
    cloud-token: ${{ secrets.DEVSHIELD_CLOUD_TOKEN }}
```

For organizations that require managed reporting to be available for every scan:

```yaml
    cloud-required: true
```

When `cloud-required` is false (the default), a Cloud outage does not prevent deterministic security scanning or the repository's normal merge gate.

## What is exported

The Cloud payload is versioned and contains:

- DevShield version
- GitHub Actions run metadata
- GitHub App installation ID when present
- repository ID, full name, and private/public flag
- revision SHA and pull-request number
- active DevShield policy/scope
- baseline and dependency-review status
- aggregate risk score and category/severity counts
- structured findings:
  - fingerprint
  - rule ID
  - severity/category
  - file path and line number
  - baseline status
  - CWE/confidence
  - generic detector message and remediation
  - dependency/advisory metadata when relevant

## What is not exported

The Cloud bridge deliberately does **not** include:

- source code
- source-line text
- code snippets
- Git diff text
- the OpenRouter request/response
- GitHub tokens
- the DevShield Cloud token
- local environment variables

Finding fingerprints are one-way hashes used for deduplication/state tracking.

## Transport and authentication

- `cloud-api-url` must use HTTPS.
- `cloud-token` is sent as a bearer token in the Authorization header.
- The token is never serialized into the scan payload.
- Network requests use a bounded timeout.
- Failed export returns a non-secret status value through `cloud-export-status`.

## cloud-export-status

Possible values:

- `disabled` — no Cloud configuration was supplied
- `success` — managed ingestion accepted the payload
- `failed` — configured export failed
- `misconfigured` — URL/token configuration is incomplete or invalid
- `fixture` — internal regression-test capture mode

## Backend responsibilities

The private DevShield Cloud service should:

1. authenticate and scope each installation token
2. enforce subscription entitlements and repository limits
3. apply idempotency using run/delivery metadata
4. store only the data needed for dashboard/history features
5. meter usage for plan enforcement
6. provide customer deletion/export workflows
7. process GitHub Marketplace purchase/change/cancel events
8. isolate tenants and encrypt sensitive metadata at rest
9. never trust client-supplied plan names or entitlements
10. retain audit trails for entitlement and policy changes

## Commercial boundary

The open Action owns detection and the privacy-safe export contract. The private managed service owns entitlement, billing, dashboards, organization policy, analytics, managed AI, and remediation workflows.
