# GitHub Marketplace Listing Copy

## Product name
MABRIG DevShield AI

## Tagline
High-signal security review for every pull request.

## Short description
DevShield combines diff-aware deterministic security checks, policy-as-code, SARIF/JSON reporting, and optional redacted AI review to catch secrets, injection risks, unsafe CI/CD, IaC mistakes, and container privilege problems before merge.

## Full description
MABRIG DevShield AI is a security-first merge gate for developers and growing engineering teams, developed and maintained by MABRIG Technologies.

It starts with transparent deterministic analysis that works without an AI key. By default, DevShield reviews only newly added lines so legacy issues do not drown out the risk introduced by the current pull request. Teams can tune policy in `.devshield.json`, upload SARIF into GitHub Code Scanning, and optionally enable an AI second pass after excluded paths are filtered and common secret formats are redacted.

### Highlights
- Diff-aware changed-line review
- 50+ deterministic checks
- Secret and credential exposure detection
- Injection, TLS, CORS, JWT, and unsafe execution checks
- GitHub Actions and supply-chain hardening
- IaC and container privilege checks
- Policy-as-code with severity overrides
- Balanced, strict, and secrets-only modes
- JSON + SARIF 2.1.0 output
- Stable finding fingerprints
- Optional OpenRouter AI review with prompt-injection-resistant instructions
- Pull-request annotations, summaries, risk score, and configurable merge gates
- No third-party runtime packages required by the Action

## Primary category
Security

## Secondary category
Code review

## Suggested screenshots
1. Pull request comment showing risk score, categories, and prioritized findings
2. Files-changed annotations for a blocked CI injection or exposed secret
3. GitHub Code Scanning view populated from DevShield SARIF
4. `.devshield.json` policy example
5. Team/organization dashboard from the future commercial GitHub App


## Commercial support

The Action is free and self-managed. MABRIG Technologies offers paid setup, repository hardening, team rollout and managed security support.

**Sales & support:** mabrig@mabrigkorie.org

- Pricing: `docs/PRICING.md`
- Support: `SUPPORT.md`
- Privacy: `PRIVACY.md`
- Commercial terms: `TERMS.md`
