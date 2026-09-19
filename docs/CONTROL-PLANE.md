# Security Control Plane

DevShield v2.0 turns the v1.9 Repository Security Graph into a review-coordination layer. It does not create a second hidden merge gate and does not reinterpret graph reachability as exploitability.

## Capabilities

### Graph snapshot diffing

Commit a reviewed graph snapshot as:

```text
.devshield-security-graph-baseline.json
```

A later scan compares stable node, edge, and path IDs and reports added/removed graph structure plus new and no-longer-observed finding nodes.

The generated candidate is:

```text
.devshield/devshield-security-graph-baseline-candidate.json
```

Adopting or updating the committed baseline is a human review decision.

### Blast-radius analysis

For changed files that exist in the graph, DevShield traverses the graph neighborhood in both directions up to three edges by default. The result is an **evidence neighborhood**, not a runtime compromise simulation.

Each impacted node retains whether its path is:

- `evidence-linked` — all traversed graph edges are direct;
- `contextual` — at least one traversed edge is contextual.

### Review-priority propagation

Finding and advisory severities seed a 0–100 review-priority value. Priority decays across graph edges:

- direct edge: 72% of the previous score;
- contextual edge: 42% of the previous score.

Only the strongest propagated signal is retained for a node. Propagation is bounded to four edges.

This score is **not CVSS, exploit probability, breach probability, or business-impact probability**. It is a deterministic triage aid for deciding what to inspect first.

### CODEOWNERS hints

DevShield searches the standard locations in this order:

1. `.github/CODEOWNERS`
2. `CODEOWNERS`
3. `docs/CODEOWNERS`

It applies rules in file order and treats the last matching rule as the ownership hint. The parser intentionally implements a conservative subset of CODEOWNERS glob behavior.

These are best-effort hints. GitHub branch protection and review requirements remain authoritative.

### Remediation observation checks

For exact v1.6 remediation candidates, the control plane checks whether a current graph finding still matches the candidate's rule and file.

Statuses:

- `still-observed`
- `not-observed-after-scan`

A finding that is not observed is verification evidence, not proof that the underlying issue can never recur or that all equivalent paths are safe.

## Control-plane artifacts

```text
.devshield/devshield-control-plane.json
.devshield/devshield-control-plane.md
.devshield/devshield-security-graph-baseline-candidate.json
```

The machine-readable report contains graph-diff summaries, blast-radius nodes, ranked review-priority nodes, ownership hints, and remediation-observation results.

## Cloud bridge

When DevShield Cloud export is enabled, v2.0 adds only:

- control-plane ID and state;
- baseline status;
- aggregate control-plane summary;
- aggregate graph-diff summary.

The Cloud bridge does **not** receive graph nodes/edges, CODEOWNERS mappings, graph paths, source snippets, or secret values through the v2.0 control-plane field.

## Local staged scans

Working-tree graph evidence can diverge from staged Git-index content. Therefore the existing `security-graph: auto` behavior disables graphing during ordinary local staged scans, and the control plane also disables itself automatically when the graph is disabled.

For an intentional working-tree repository analysis:

```bash
npm run scan -- --repository --security-graph on --control-plane on
```

## Guardrails

The control plane:

- does not mutate repository files;
- does not assign reviewers automatically;
- does not change branch protection;
- does not bypass the deterministic merge gate;
- does not claim exploit probability;
- does not replace CVSS;
- does not store source snippets or secret values;
- keeps contextual graph relationships visibly contextual;
- labels CODEOWNERS output as best-effort;
- labels absent remediation findings as not observed rather than proven fixed.
