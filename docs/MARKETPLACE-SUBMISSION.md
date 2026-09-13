# GitHub Marketplace Submission — MABRIG DevShield AI

Use this document for the first GitHub Marketplace publication and subsequent v1 releases.

## Current production release

- Version: `1.3.0`
- Tag to publish: `v1.3.0`
- Target: `main`
- Release title: `MABRIG DevShield AI v1.3.0`
- Stable compatibility ref: `v1`
- Release notes source: `docs/RELEASE-NOTES-V1.3.0.md`
- Automated release workflow: `.github/workflows/release-v1.yml`

## Marketplace identity

- Name: `MABRIG DevShield AI`
- Tagline: `Security-first pull request review before merge.`
- Primary category: Security
- Secondary positioning: Continuous integration / code quality / AI-assisted developer tooling
- Publisher: MABRIG Digital Media

## Short description

MABRIG DevShield AI reviews pull-request changes for exposed secrets, insecure code patterns, risky configuration, vulnerable dependencies, license-policy violations, and supply-chain weaknesses. Deterministic checks run without an AI key; teams can optionally add OpenRouter for a redacted AI-assisted second pass. The same policy engine is also available locally for staged-change and pre-commit protection.

## Production preflight

Before publishing a release:

1. Confirm **DevShield CI** is green.
2. Confirm **Production Certification** is green. This workflow runs the full regression suite, proves the public `@v1` Action accepts a safe customer change, and proves it blocks an intentionally unsafe change.
3. Confirm `package.json` and the matching release-notes file use the same version.
4. Run **Release DevShield v1** from GitHub Actions with:
   - `version`: `1.3.0`
   - `confirm`: `RELEASE`
5. The release workflow reruns tests and self-scan, publishes the GitHub Release, and advances the stable `v1` branch.
6. For the first Marketplace publication, finish the Marketplace listing in the GitHub UI after the release exists.

## Key benefits

1. Catch security risks before merge.
2. Stop risky staged changes before commit.
3. Start without an external AI provider.
4. Add optional AI reasoning only when needed.
5. Enforce configurable severity, dependency, license, and baseline policy.
6. Produce JSON and SARIF reports for downstream security workflows.

## First-publication checklist

- [ ] Production Certification is green on `main`.
- [ ] Run **Release DevShield v1** for `1.3.0`.
- [ ] Confirm GitHub Release `v1.3.0` exists.
- [ ] Confirm `v1` resolves to the intended production commit.
- [ ] Accept the GitHub Marketplace Developer Agreement if prompted.
- [ ] Choose the option to publish the Action to GitHub Marketplace.
- [ ] Confirm the Marketplace name matches `action.yml`.
- [ ] Add categories and listing copy from `docs/MARKETPLACE-LISTING.md`.
- [ ] Add final support/contact information.
- [ ] Publish the Marketplace listing.
- [ ] Validate the listing from a separate customer/test repository.

## After publication

- Add the Marketplace listing URL to the README.
- Add screenshots showing a clean scan, a blocked high-risk PR, dependency intelligence, and the GitHub Actions job summary.
- Track installations and support requests.
- Keep `v1` backward-compatible; breaking changes must move to a new major compatibility ref.
- Prepare the commercial GitHub App only after the public Action has a stable adoption path.
