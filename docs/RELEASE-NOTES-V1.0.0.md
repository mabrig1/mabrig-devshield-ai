# MABRIG DevShield AI v1.0.0

**Security-first pull request review before merge.**

MABRIG DevShield AI v1.0.0 is the first public release of the DevShield GitHub Action. It adds deterministic security scanning to pull requests, with an optional AI-assisted review layer for teams that want deeper contextual analysis.

## Highlights

- Runs without an AI key.
- Detects exposed secrets and risky code/configuration patterns.
- Produces PR annotations, a job summary, risk score, risk level, and finding count.
- Can block a pull request when findings meet a configured severity threshold.
- Optionally sends a redacted diff to OpenRouter for a second-pass review.
- Supports exclusion globs for test fixtures and generated files.
- Uses current GitHub-hosted workflow dependencies (`actions/checkout@v7`, `actions/setup-node@v7`).

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

## Optional AI-assisted review

Store an OpenRouter key in the consuming repository as `OPENROUTER_API_KEY`, then pass it to DevShield:

```yaml
      - uses: mabrig1/mabrig-devshield-ai@v1
        with:
          github-token: ${{ github.token }}
          openrouter-api-key: ${{ secrets.OPENROUTER_API_KEY }}
          model: openrouter/auto
          fail-on: high
```

## Security model

Deterministic scanning runs entirely on the GitHub-hosted runner. AI mode is opt-in and sends only a truncated, redacted diff to OpenRouter. Teams with source-code residency restrictions should use deterministic-only mode.

## Release validation

The launch pull request passed both the smoke-test and self-scan jobs, and the post-merge `main` workflow also completed successfully.

## Commercial edition

The companion MABRIG DevShield AI GitHub App is planned as a separate commercial service with managed reviews, organization policies, centralized usage, installation entitlements, and paid subscription tiers.
