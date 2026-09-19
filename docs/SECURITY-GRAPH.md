# Repository Security Graph

DevShield v1.9 models repository security evidence as a bounded typed graph so reviewers can trace how packages, source files, workflows, advisories, and deterministic findings relate to one another.

## Node types

The graph currently emits:

- **package** — a prioritized dependency from the v1.8 dependency mission;
- **file** — source, API route, workflow, container, infrastructure, or generic repository file;
- **finding** — a deterministic DevShield finding represented by fingerprint, rule, severity, category, file, line, and baseline status;
- **advisory** — dependency-review advisory evidence such as a GHSA identifier.

Node IDs are stable hashes of their evidence identity. The graph does not store source snippets or secret values.

## Edge types

Each edge includes a confidence label and evidence metadata.

| Edge | Confidence | Evidence |
| --- | --- | --- |
| `referenced-by` | direct | A source file statically imports/requires the dependency. |
| `consumed-by` | direct | One repository source file imports another relative repository source file. Direction is from imported module to importer so impact can propagate toward callers/routes. |
| `has-finding` | direct | DevShield emitted a finding at that file/line/fingerprint. |
| `has-advisory` | direct | GitHub dependency-review evidence attaches an advisory to that package identity. |
| `installation-context` | contextual | A workflow contains a package-manager install command while the dependency is present in the repository dependency mission. It does not prove every job installs or executes that package. |

Future graph edges should follow the same rule: no relationship without inspectable evidence, and weaker relationships must remain visibly weaker.

## Multi-hop paths

DevShield performs bounded traversal from package nodes with a maximum depth of five edges. Security-relevant targets include findings, advisories, API routes, and workflows.

Examples:

```text
package -> referenced-by -> module -> consumed-by -> API route
package -> referenced-by -> source file -> has-finding -> secret/security finding
package -> installation-context -> workflow -> has-finding -> CI-security finding
package -> has-advisory -> advisory
```

Path confidence uses the weakest edge:

- all direct edges → `evidence-linked`;
- one or more contextual edges → `contextual`.

A longer path never upgrades a weak edge into proof of exploitability.

## Artifacts

A normal scan can generate:

```text
.devshield/devshield-security-graph.json
.devshield/devshield-security-graph.md
.devshield/devshield-security-graph.dot
```

The DOT file can be rendered with Graphviz outside DevShield.

## Bounds

The graph is intentionally bounded to protect CI performance and reviewability:

- repository file input is capped by DevShield's repository file selection;
- source import parsing is bounded;
- graph nodes default to at most 500;
- graph edges default to at most 1,200;
- discovered review paths default to at most 40;
- source files above the graph read limit are skipped;
- symlinks and unsafe relative paths are not read.

## Local staged safety

Repository graphing uses working-tree file relationships, while local staged scanning reads staged source from the Git index. Therefore `security-graph: auto` disables graph generation during ordinary local staged scans.

Use a repository scan when you intentionally want the current working tree represented:

```bash
npm run scan -- --repository --security-graph on
```

## AI mode

When `agentic-mode: ai` is enabled, the external AI reviewer receives only a compact graph summary and the top path titles/confidence levels. Full source content is not added by the graph layer, and deterministic merge gates remain authoritative.

## Security properties

The graph:

- does not execute repository code;
- does not install packages;
- does not store source snippets;
- does not store secret values;
- does not mutate repository files;
- does not infer exploitability from graph reachability;
- marks workflow installation relationships as contextual;
- exposes the evidence behind every edge in JSON;
- uses stable graph/node/edge IDs for downstream comparison and audit.

The graph is an evidence-navigation layer, not a replacement for SAST, runtime tracing, package exploitability analysis, or human AppSec review.
