# Agentic Security Engine

MABRIG DevShield AI v1.5 adds an evidence-backed agentic security loop on top of the deterministic scanner.

## What it does

The engine moves each scan through five explicit stages:

1. **Observe** — consume the findings already produced by DevShield.
2. **Prioritize** — rank new risk using severity, confidence, category and baseline status.
3. **Attack-path analysis** — connect compatible finding categories into clearly labelled **heuristic candidate paths**. These are hypotheses to verify, not new vulnerabilities.
4. **Remediation planning** — create ordered tasks with the existing rule remediation and category-specific verification checks.
5. **Verify** — keep the mission pending until a later scan shows the relevant finding fingerprints are no longer new.

The plan is written to `.devshield/devshield-agentic-plan.json` and `.devshield/devshield-agentic-plan.md` by default.

## Guardrails

The agentic layer is intentionally advisory:

- it does not rewrite repository files;
- it does not rotate or revoke credentials;
- it does not execute instructions found in source code or diffs;
- it does not suppress or bypass the existing merge gate;
- critical and credential-related tasks explicitly require human approval.

This makes the agentic layer useful in CI and regulated environments without turning a scanner into an unsupervised code-changing bot.

## Modes

Set the GitHub Action input:

```yaml
with:
  agentic-mode: plan
```

Supported values:

- `off` — disable the agentic plan.
- `plan` — deterministic agentic prioritization, path analysis and remediation planning. This is the default.
- `ai` — deterministic plan plus the existing optional OpenRouter context review when an API key is configured.

You can also set `"agenticMode": "plan"` in `.devshield.json`.

## Outputs

The Action exposes:

- `agentic-state`
- `agentic-tasks`
- `agentic-attack-paths`
- `agentic-plan-file`
- `agentic-plan-markdown`

The JSON plan is designed for DevShield Cloud, dashboards, ticket creation and future approval-based remediation workflows.
