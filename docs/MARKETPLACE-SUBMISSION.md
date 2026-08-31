# GitHub Marketplace Submission — MABRIG DevShield AI

Use this document when publishing the first GitHub Marketplace release.

## Release

- Tag: `v1.0.0`
- Target: `main`
- Release title: `MABRIG DevShield AI v1.0.0`
- Major compatibility ref: `v1`
- Release notes source: `docs/RELEASE-NOTES-V1.0.0.md`

## Marketplace identity

- Name: `MABRIG DevShield AI`
- Tagline: `Security-first pull request review before merge.`
- Primary category: Security
- Secondary positioning: Continuous integration / code quality / AI-assisted developer tooling
- Publisher: MABRIG Digital Media

## Short description

MABRIG DevShield AI reviews pull-request changes for exposed secrets, insecure code patterns, risky configuration, and supply-chain weaknesses. Deterministic checks run without an AI key; teams can optionally add OpenRouter for a redacted AI-assisted second pass.

## Key benefits

1. Catch security risks before merge.
2. Start free without an external AI provider.
3. Add AI reasoning only when needed.
4. Fail builds by configurable severity.
5. Integrate using a small GitHub Actions workflow.

## Release checklist

- [ ] Open GitHub → Releases → Draft a new release.
- [ ] Create tag `v1.0.0` targeting `main`.
- [ ] Paste release notes from `docs/RELEASE-NOTES-V1.0.0.md`.
- [ ] Choose the option to publish the Action to GitHub Marketplace when available.
- [ ] Accept the GitHub Marketplace Developer Agreement if prompted.
- [ ] Confirm the Marketplace name is available and matches `action.yml`.
- [ ] Add categories and listing copy from `docs/MARKETPLACE-LISTING.md`.
- [ ] Add support/contact information.
- [ ] Publish the release.
- [ ] Confirm a consuming test repository can use `mabrig1/mabrig-devshield-ai@v1`.

## After publication

- Add the Marketplace listing URL to the README.
- Add screenshots showing a clean scan, a blocked high-risk PR, and the GitHub Actions job summary.
- Track installations and support requests.
- Prepare the commercial GitHub App only after the public Action has a stable adoption path.
