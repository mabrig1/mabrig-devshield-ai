# MABRIG DevShield AI v1.1.0

**High-signal security review for the code that actually changed.**

Version 1.1.0 upgrades DevShield from a lightweight deterministic PR scanner into a stronger security-review foundation with diff-aware scanning, policy-as-code, portable SARIF/JSON reporting, broader CI/IaC/container coverage, and safer optional AI analysis.

## Highlights

- Changed-line scanning by default to reduce legacy-noise false positives.
- 50+ deterministic security and supply-chain checks.
- `.devshield.json` repository policy.
- Balanced, strict, and secrets-only modes.
- Non-critical inline suppressions with critical findings protected from inline suppression.
- SARIF 2.1.0 and structured JSON outputs.
- Stable finding fingerprints for deduplication.
- Expanded GitHub Actions security checks, including expression-to-shell injection and risky `pull_request_target` patterns.
- IaC/container checks for public CIDRs, wildcard IAM, privileged containers, host networking, root execution, and privilege escalation.
- Stronger AI privacy: excluded paths stay excluded, common/generic secrets are redacted, and the model is explicitly instructed to treat diff content as untrusted data.

## Quick start

```yaml
name: DevShield
on:
  pull_request:

permissions:
  contents: read
  pull-requests: write
  issues: write

jobs:
  devshield:
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

## GitHub Code Scanning

DevShield writes `.devshield/devshield.sarif`. Consumers can upload it with `github/codeql-action/upload-sarif@v4` when their repository supports code scanning.

## Compatibility

This release remains on the v1 compatibility line. Existing v1 workflows continue to work; new inputs are optional.

## Validation

The expanded smoke suite covers secrets, CI workflow risks, changed-line behavior, suppression policy, config policy, JSON/SARIF generation, and fail thresholds.
