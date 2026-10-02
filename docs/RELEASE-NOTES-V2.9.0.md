# MABRIG DevShield AI v2.9.0 — Unified Assurance

Released: 2026-10-02

DevShield v2.9 integrates the Legal & Compliance Shield into the normal Action and CLI workflow.

## Highlights

- Legal/compliance evidence is now part of the standard DevShield run.
- Advisory mode is enabled by default and does not alter merge gating.
- Explicit enforce mode can include legal/compliance signals in the existing severity gate.
- New Action outputs expose compliance state, counts and report location.
- Dedicated JSON and Markdown evidence artifacts are generated.
- `.devshield.json` supports `legalComplianceMode`.
- Legal/compliance tests now run in the full smoke regression suite.

## Upgrade example

```yaml
- uses: mabrig1/mabrig-devshield-ai@main
  with:
    github-token: ${{ github.token }}
    fail-on: high
    legal-compliance: advisory
```

## Enforcement example

```yaml
- uses: mabrig1/mabrig-devshield-ai@main
  with:
    github-token: ${{ github.token }}
    fail-on: high
    legal-compliance: enforce
```

## Important limitation

Legal & Compliance Shield performs automated risk spotting from repository-facing evidence. It is not legal advice and does not determine compliance.
