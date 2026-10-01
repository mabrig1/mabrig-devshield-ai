# Human Control Boundary Engine

The Human Control Boundary Engine is an experimental DevShield module for deciding **how much human control an agentic software action should retain**.

It is designed for research and evaluation, not to turn a heuristic score into a claim about exploitability or moral authority.

## Why this exists

AI coding agents can modify repositories, dependencies, CI workflows, infrastructure, credentials and external services. A fixed rule such as “always require a human click” can create *oversight theatre*: the approval exists, but the reviewer lacks the evidence or attention needed to make the decision meaningful.

The engine makes the control allocation explicit and inspectable:

- `delegate` — no extra human intervention indicated by current evidence.
- `review` — surface the action for human review.
- `require-approval` — keep an explicit human approval boundary.
- `block` — a configured policy or accumulated evidence warrants stopping the action pending investigation.

## Evidence model

`recommendHumanControl()` accepts bounded, observable inputs:

- privilege level;
- reversibility;
- external side effects;
- credential access;
- policy-bypass capability;
- observed security-graph blast radius;
- evaluation uncertainty;
- quality of evidence available to a reviewer;
- highest observed finding severity; and
- DevShield regression-policy decision.

Every score contribution is returned in `scoreComponents`. Hard constraints are returned separately so a caller can distinguish “score was high” from “an explicit policy boundary required approval.”

## Guardrails

The module deliberately states that:

- its score is **not exploit probability**;
- it never auto-approves an action;
- it does not mutate a repository;
- model output is not treated as independent evidence; and
- the existence of a human approval step is not assumed to make a workflow safe.

## Oversight-theatre signal

When review or approval is recommended, the engine separately reports an `oversightTheatre` risk.

For example, requiring approval while giving the reviewer weak evidence can raise the theatre warning. This is intended to support experiments comparing evidence-rich approval against low-information approval.

## Example

```js
import { recommendHumanControl } from './src/human-control-boundary.mjs';

const result = recommendHumanControl({
  privilege: 'high',
  reversibility: 'low',
  credentialAccess: true,
  blastRadiusNodes: 18,
  uncertainty: 0.3,
  evidenceQuality: 0.9,
  highestFindingSeverity: 'high',
  regressionDecision: 'pass'
});

console.log(result.boundary);
console.log(result.scoreComponents);
console.log(result.oversightTheatre);
```

## Measuring whether human control actually helped

`compareHumanControlOutcome()` records a paired experimental observation:

```js
import { compareHumanControlOutcome } from './src/human-control-boundary.mjs';

const comparison = compareHumanControlOutcome({
  autonomous: { unsafe: true, taskSuccess: true },
  humanControlled: { unsafe: false, taskSuccess: true },
  reviewLatencyMs: 18000
});
```

This can label the paired result `improved`, `degraded`, `neutral`, or `inconclusive`.

A single paired result is explicitly **not** a population-level causal estimate. The intended next step is to run repeated controlled trials across agent tasks and aggregate those observations in a research harness.

## Grant/research relevance

This module is the first implementation step toward DevShield's Human Control Boundary research program:

1. make control allocation explicit;
2. preserve the evidence behind the recommendation;
3. detect conditions where approval may be ceremonial;
4. compare autonomous and human-controlled conditions; and
5. publish reproducible results, including negative findings.

The module is intentionally dependency-free so experiments remain easy to reproduce.
