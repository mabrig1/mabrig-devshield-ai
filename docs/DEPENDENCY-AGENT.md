# Agentic Dependency Intelligence

DevShield v1.8 correlates dependency evidence with repository context without turning weak metadata into invented vulnerabilities.

## Evidence sources

The dependency mission can combine:

- npm v2/v3 lockfile metadata from the existing offline inventory engine;
- root dependency declarations such as runtime, development, optional, and peer relationships;
- GitHub dependency-review findings, including GHSA metadata when GitHub supplies it;
- direct JavaScript/TypeScript/Vue/Svelte `import`, dynamic `import()`, and `require()` references;
- declared package install-script metadata from the lockfile;
- GitHub workflow-file presence;
- container and infrastructure-as-code file presence;
- deterministic DevShield findings such as CI-security and secret findings.

It does not install dependencies, execute lifecycle scripts, download package bytes, query a registry, or inspect `node_modules`.

## Confidence model

A dependency path is never silently promoted to a confirmed exploit chain.

| Confidence | Meaning |
| --- | --- |
| `evidence-linked` | Two concrete facts are linked, such as a GitHub advisory and a direct source import. Exploitability is still unproven. |
| `contextual` | Relevant repository context exists, but the exact execution path has not been established. |
| `heuristic` | Multiple signals create a review hypothesis that requires explicit verification. |
| `heuristic-elevated` | A heuristic path also has sensitive deterministic context, such as CI-security or secret findings. |

## Generated mission

Normal Action scans use `dependency-agentic: auto` by default through repository config. When a supported lockfile exists, DevShield writes:

- `.devshield/devshield-dependency-mission.json`
- `.devshield/devshield-dependency-mission.md`

The JSON contains a stable mission ID, priority queue, evidence, repository context, attack-path hypotheses, and verification tasks.

The priority score is an investigation-order heuristic. It is **not CVSS**, exploit probability, or a vulnerability severity rating.

## Example correlations

DevShield can surface review missions such as:

- a GitHub dependency advisory plus direct application imports;
- an insecure HTTP package source plus CI workflow presence;
- missing/weak integrity metadata plus CI workflow presence;
- a declared package lifecycle script plus CI execution context;
- an advisory-linked directly imported package in a repository with container/IaC deployment files.

Each path contains verification instructions. For example, a direct import proves source usage, but not whether the vulnerable API is reachable.

## Local staged safety

Local staged scans read source from the Git index, while the npm lockfile inventory is working-tree evidence. To avoid mixing snapshots, `dependency-agentic: auto` disables the dependency mission for local `staged` scans.

To opt in deliberately:

```bash
npm run scan -- --repository --dependency-agentic on
```

For a pure lockfile metadata report, continue using:

```bash
npm run inventory
```

## AI mode

When `agentic-mode: ai` is enabled, only a compact dependency-mission summary is added to the existing redacted AI review context. The model is instructed not to infer exploitability. Deterministic gates remain authoritative.

## Guardrails

The dependency agent:

- does not mutate repository files;
- does not auto-upgrade packages;
- does not infer that a metadata gap is a vulnerability;
- does not infer exploitability from package presence or source imports;
- does not treat container/IaC presence as proof of runtime reachability;
- preserves the existing merge gate rather than creating a hidden dependency gate.

Use dependency-review advisories, application tests, package-manager evidence, and human AppSec review to confirm remediation.
