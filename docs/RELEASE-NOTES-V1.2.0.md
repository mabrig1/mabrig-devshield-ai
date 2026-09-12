# MABRIG DevShield AI v1.2.0

**Know whether a pull request introduces vulnerable software—and whether a security finding is actually new.**

Version 1.2 adds two major security-product capabilities on top of the v1.1 diff-aware scanner: native GitHub dependency intelligence and fingerprint-based finding baselines.

## Dependency intelligence

On pull requests, DevShield can call GitHub's dependency-review API using the supplied `github-token`. Newly introduced or updated dependencies are converted into first-class DevShield findings when GitHub reports known vulnerabilities.

Dependency findings include:
- package name and version
- ecosystem
- manifest
- package URL
- license
- GHSA ID
- advisory URL and summary
- vulnerability severity

DevShield can also reject newly introduced dependencies whose SPDX license appears in `dependency-deny-licenses`.

If GitHub dependency review is not available for a repository, DevShield emits a warning and continues deterministic source scanning instead of failing open or terminating the review.

## Finding baselines

Legacy repositories often already contain issues. DevShield v1.2 can generate and consume a committed fingerprint baseline.

With `baseline-mode: new-only`:
- findings matching the baseline are marked `existing`
- new findings remain merge-gated
- existing findings remain visible in JSON and SARIF
- PR risk score reflects newly introduced risk

For the strongest initial baseline, run once with `scan-scope: repository` and review the generated `.devshield/devshield-baseline.json` before committing it as `.devshield-baseline.json`.

## New inputs

- `dependency-review`: `auto`, `true`, or `false`
- `dependency-severity`: `critical`, `high`, `medium`/`moderate`, or `low`
- `dependency-deny-licenses`: comma-separated SPDX license identifiers
- `baseline-file`
- `baseline-mode`: `new-only`, `report`, or `off`

## New outputs

- `new-findings`
- `existing-findings`
- `dependency-findings`
- `dependency-review-status`
- `baseline-output-file`

## Compatibility

All new controls are optional and remain on the v1 compatibility line.
