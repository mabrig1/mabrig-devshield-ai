# Policy-Aware Regression Gates

DevShield v2.2 converts v2.1 regression history into an optional policy layer. The design goal is to let teams express longitudinal security expectations without silently changing the original deterministic finding gate.

## Two independent gates

DevShield now has two separate gate families:

1. **Deterministic finding gate** — controlled by `fail-on`; this remains the primary finding-based security gate.
2. **Regression policy gate** — controlled by `regression-gate`; this evaluates history/control-plane changes.

The regression gate never weakens, bypasses, or replaces `fail-on`.

## Modes

### off

Regression policy is disabled.

### report

Default. DevShield calculates the policy result and writes outputs/reports, but **never fails CI because of regression policy**.

This is the recommended adoption mode.

### enforce

A regression decision of `block` or `approval-required` sets a failing exit code in addition to any deterministic gate result.

## New-risk threshold

`regression-new-risk-severity` accepts:

- `critical`
- `high`
- `medium`
- `low`
- `none`

When historical comparison is available, a newly introduced finding/advisory at or above the threshold produces a `block` policy outcome.

`none` disables new-risk threshold gating.

A first/unclassified history snapshot never produces a regression block because there is no trusted comparison point.

## Expanded exposure

`regression-expanded-exposure` accepts:

- `ignore`
- `warn`
- `block`

Expanded exposure means the same stable risk node remains but reaches more nodes in the bounded v2.1 graph-exposure snapshot.

It remains a graph-evidence signal, not proof that exploitability increased.

## Inherited debt

`regression-inherited-debt` accepts:

- `ignore`
- `warn`

Inherited debt is never hidden from history. This setting only controls whether unchanged historical risk creates a policy warning.

## Blast-radius threshold

Set:

```yaml
regression-blast-radius-threshold: 25
```

The threshold uses the v2.0 bounded changed-file blast-radius node count.

`0` disables blast-radius threshold policy.

Actions:

- `ignore`
- `warn`
- `block`
- `require-owner-approval`

## CODEOWNERS approval semantics

For `require-owner-approval`, DevShield reads the ownership hints already resolved by the v2.0 control plane and fetches pull-request reviews through the GitHub API.

Automatic verification is intentionally narrow:

- `@alice` can be matched to GitHub reviewer `alice`;
- the latest submitted review from that individual controls their state;
- at least one eligible individual owner with latest state `APPROVED` satisfies the condition;
- `@org/security` is a team owner and is **not** inferred from a reviewer login;
- if review evidence is unavailable, the condition remains unresolved.

This is a DevShield policy signal only. GitHub branch protection, required reviewers, and native CODEOWNERS enforcement remain authoritative.

## Example policies

### Report-only rollout

```yaml
regression-gate: report
regression-new-risk-severity: high
regression-expanded-exposure: warn
regression-inherited-debt: ignore
```

Even if DevShield calculates `block`, CI does not fail in report mode.

### Block new critical risk only

```yaml
regression-gate: enforce
regression-new-risk-severity: critical
regression-expanded-exposure: ignore
regression-blast-radius-threshold: 0
```

### Block expanded exposure

```yaml
regression-gate: enforce
regression-new-risk-severity: none
regression-expanded-exposure: block
```

### Require owner approval on large blast radius

```yaml
regression-gate: enforce
regression-new-risk-severity: critical
regression-expanded-exposure: warn
regression-blast-radius-threshold: 25
regression-blast-radius-action: require-owner-approval
```

The Action needs `github-token` to retrieve PR review evidence.

## Outputs

The regression gate emits:

- state and highest decision;
- whether enforcement failed;
- number of block, warning, and approval-required rules;
- JSON and Markdown report paths.

Artifacts:

```text
.devshield/devshield-regression-policy.json
.devshield/devshield-regression-policy.md
```

## Privacy

The local JSON report can contain CODEOWNERS approval evidence such as eligible/approved individual owner handles because the repository itself supplied those ownership rules.

DevShield Cloud receives only compact policy mode/state/decision/summary/configuration. Reviewer identities and CODEOWNERS mappings are not included in the v2.2 Cloud field.

## Guardrails

The v2.2 regression policy:

- defaults to non-blocking `report`;
- cannot lower the deterministic `fail-on` gate;
- never treats graph exposure as exploit probability;
- never infers team membership;
- never auto-assigns reviewers;
- never edits branch protection;
- never mutates source or history files;
- never blocks on the first trusted history snapshot due to missing comparison evidence.
