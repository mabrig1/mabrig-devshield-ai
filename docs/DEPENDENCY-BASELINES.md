# Dependency Intelligence & Baselines

## Native dependency review

DevShield can use GitHub's dependency-review API during pull requests when:
- the workflow supplies `github-token`
- the event is a pull request
- GitHub dependency review is available for the repository

Recommended workflow:

```yaml
- id: devshield
  uses: mabrig1/mabrig-devshield-ai@v1
  with:
    github-token: ${{ github.token }}
    fail-on: high
    dependency-review: auto
    dependency-severity: low
    dependency-deny-licenses: AGPL-3.0, GPL-3.0
```

The global `fail-on` threshold applies to dependency findings just like source-code findings.

### Availability behavior

Dependency review is an enrichment layer. If the GitHub endpoint is unavailable, DevShield reports `dependency-review-status=unavailable` and continues its local deterministic review.

## Baseline adoption

A baseline is a reviewed set of finding fingerprints that already exist in a repository.

### Create a baseline candidate

Run DevShield with:

```yaml
with:
  scan-scope: repository
  baseline-mode: off
```

Review the generated path from `baseline-output-file`. If the findings are accepted as current legacy debt, commit the reviewed candidate as:

```
.devshield-baseline.json
```

### Gate only new findings

```yaml
with:
  baseline-file: .devshield-baseline.json
  baseline-mode: new-only
```

In `new-only` mode:
- matching fingerprints are classified as existing
- existing findings remain in JSON and SARIF
- only new findings contribute to risk scoring and `fail-on`

### Report mode

`baseline-mode: report` classifies findings as new/existing but still gates on both.

### Off mode

`baseline-mode: off` ignores the baseline file entirely.

## Baseline security guidance

Treat baseline changes as security-policy changes:
- require normal code review
- consider CODEOWNERS protection
- avoid mass-accepting findings without triage
- regenerate intentionally, not automatically
- keep temporary exceptions narrow and documented

A baseline should help teams adopt DevShield without blocking on old debt; it should not become a permanent hiding place for unresolved critical risk.
