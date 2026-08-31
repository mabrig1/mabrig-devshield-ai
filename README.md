# MABRIG DevShield AI

**Security-first pull request review before merge.**

MABRIG DevShield AI is a GitHub Action that scans changed files for exposed secrets, risky configuration, insecure code patterns, floating dependencies, and supply-chain weaknesses. It works without an AI key. Teams can optionally add an OpenRouter key for a second-pass AI review after DevShield redacts common secret formats from the diff.

## Features

- Deterministic secret scanning with no external API required
- Pull request security annotations and job summaries
- Optional OpenRouter AI review using `openrouter/auto`
- Redaction before AI analysis
- Configurable fail threshold
- Configurable path exclusions for intentional fixtures/generated files
- No build step or third-party runtime dependencies in the Action itself
- Works with JavaScript/TypeScript, Python, PHP, Java, Go, configuration files, and most text-based repositories

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

### Optional AI review

Add `OPENROUTER_API_KEY` in **Repository settings → Secrets and variables → Actions**, then:

```yaml
      - uses: mabrig1/mabrig-devshield-ai@v1
        with:
          github-token: ${{ github.token }}
          openrouter-api-key: ${{ secrets.OPENROUTER_API_KEY }}
          model: openrouter/auto
          fail-on: high
```

### Excluding intentional fixtures

Security test fixtures sometimes contain fake keys or deliberately unsafe code. Exclude those paths explicitly instead of weakening the scanner:

```yaml
          exclude-paths: 'test/**,fixtures/**'
```

## Inputs

| Input | Default | Purpose |
|---|---|---|
| `github-token` | empty | Posts/updates PR review comment |
| `openrouter-api-key` | empty | Enables AI-assisted second pass |
| `model` | `openrouter/auto` | OpenRouter model slug |
| `fail-on` | `critical` | `critical`, `high`, `medium`, `low`, `none` |
| `comment` | `true` | Post a PR comment |
| `max-files` | `80` | Maximum changed text files scanned |
| `exclude-paths` | empty | Comma-separated path globs to skip, such as `test/**,fixtures/**` |

## Outputs

- `findings-count`
- `risk-score`
- `risk-level`

## What DevShield checks

DevShield's deterministic MVP includes checks for private keys, GitHub/API/AWS/Stripe live keys, tracked `.env` files, secrets exposed through `NEXT_PUBLIC_`, disabled TLS verification, wildcard CORS, risky shell execution, dynamic `eval`, possible request-built SQL, moving-branch GitHub Actions references, and floating npm dependency versions.

## Security model

The deterministic scan runs on the GitHub-hosted runner. If AI mode is enabled, DevShield sends only a truncated, redacted diff to OpenRouter. Do not enable AI mode for repositories whose policy prohibits source code from leaving the runner.

## Marketplace release

1. Confirm the **DevShield CI** workflow passes.
2. Create a release such as `v1.0.0`.
3. Select **Publish this Action to the GitHub Marketplace** during release.
4. Maintain a stable major tag (`v1`) that points to the current compatible release.

## Commercial edition

The companion **MABRIG DevShield AI GitHub App** adds managed AI reviews, centralized policy, usage tiers, installation-level entitlement, and GitHub Marketplace subscriptions. The commercial backend is maintained separately from this public Action repository.

© 2026 MABRIG Digital Media.
