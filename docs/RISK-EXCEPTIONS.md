# Time-Bound Risk Acceptance

DevShield v2.3 adds narrow, reviewable security exceptions to the v2.2 regression-policy layer.

The key boundary is deliberate:

> A risk exception can change the **regression-policy decision**, but it cannot erase the underlying security evidence.

Deterministic findings, SARIF, annotations, the Repository Security Graph, Security Graph History, and the original `fail-on` gate are not suppressed by v2.3 exceptions.

## File format

Default file:

```text
.devshield-exceptions.json
```

Schema:

```json
{
  "schemaVersion": 1,
  "exceptions": [
    {
      "id": "risk-2026-001",
      "owner": "@security-owner",
      "rationale": "Temporary acceptance while the upstream fix is validated.",
      "reviewedAt": "2026-09-19T00:00:00Z",
      "expiresAt": "2026-10-10T00:00:00Z",
      "scope": {
        "findingFingerprints": [
          "0123456789abcdef0123456789abcdef"
        ],
        "graphPathIds": [
          "path-0123456789abcdef"
        ]
      }
    }
  ]
}
```

## Required metadata

Every exception requires:

- **id** — stable, human-reviewable exception identifier;
- **owner** — person/team responsible for the accepted risk;
- **rationale** — meaningful explanation, minimum 12 characters;
- **reviewedAt** — ISO date/time of the current review;
- **expiresAt** — ISO date/time when acceptance stops;
- **scope** — at least one finding fingerprint or graph path ID.

Duplicate IDs are invalid.

## Time limits

The default maximum `reviewedAt → expiresAt` duration is 90 days.

Configure:

```yaml
risk-exception-max-days: 30
```

Allowed range is 1–365 days.

When the current time reaches `expiresAt`, the exception becomes `expired` and is ignored automatically. No separate cleanup job is needed for enforcement.

## Scope

### Finding fingerprints

Fingerprint scope is the narrowest option and is preferred when a stable DevShield finding fingerprint is available.

An exception matches only the exact fingerprint.

### Graph path IDs

A graph-path exception can match a finding/advisory risk node contained in that exact v1.9 security path.

This allows an acceptance to follow a documented graph relationship without becoming a repository-wide rule exception.

## Critical-risk behavior

Default:

```yaml
risk-exception-allow-critical: false
```

A matching critical regression item remains unaccepted.

Teams can explicitly enable critical **regression-policy** acceptance:

```yaml
risk-exception-allow-critical: true
```

This still does **not** suppress the deterministic critical finding. The finding remains in reports/SARIF/annotations/graph/history and still participates in the independent `fail-on` gate.

## Exception lifecycle history

v2.3 stores a compact exception snapshot in the tamper-evident security history.

It deliberately excludes:

- owner text;
- rationale text;
- raw finding fingerprints;
- raw graph path IDs.

History keeps:

- exception ID;
- status;
- reviewed/expires timestamps;
- hash of the scoped identifiers.

This supports lifecycle classification:

- **introduced** — ID appears for the first time;
- **renewed** — expiry date moves later;
- **lapsed** — a previously active exception expires or disappears;
- **scope changed** — the hashed scope changes.

These counts are included in the history chain and risk-exception report.

## Interaction with regression policy

Processing order:

1. DevShield generates raw deterministic findings.
2. It builds graph/control-plane evidence.
3. It creates the raw security-history regression classification.
4. Active risk exceptions are matched to eligible regression items.
5. DevShield creates a separate **effective regression for policy**.
6. v2.2 regression policy evaluates that effective view.
7. The raw finding/history evidence remains unchanged.

This means an accepted risk is still auditable.

## Invalid exceptions

Invalid entries are ignored and reported.

Examples:

- missing owner/rationale;
- malformed timestamps;
- expiry before review;
- duration longer than the configured maximum;
- missing scope;
- malformed fingerprint/path ID;
- duplicate exception ID.

If an intended exception is invalid, the underlying regression remains eligible to block in `regression-gate: enforce` mode.

## Modes

`risk-exceptions` accepts:

- `off` — do not load exception policy;
- `auto` — default; load the file when present;
- `on` — enable and warn when the configured file is missing.

## Reports

```text
.devshield/devshield-risk-exceptions.json
.devshield/devshield-risk-exceptions.md
```

Reports include aggregate counts, applied exception IDs, expired/invalid entries, critical matches skipped by policy, unused active exceptions, and lifecycle information.

## Privacy

DevShield Cloud receives only:

- exception source status;
- aggregate active/expired/invalid/applied counts;
- aggregate lifecycle counts;
- whether critical regression acceptance is enabled.

Owner names, rationale text, exception IDs, fingerprints, path IDs, and scope hashes are not sent through the v2.3 Cloud field.

The optional AI reviewer receives only aggregate exception counts.

## Guardrails

Risk acceptance:

- cannot suppress deterministic findings;
- cannot remove SARIF/annotations;
- cannot mutate source;
- cannot alter the finding fingerprint baseline;
- cannot erase raw graph/history evidence;
- expires automatically;
- is scope-limited;
- is time-limited;
- refuses critical regression acceptance by default;
- requires explicit configuration to relax that critical regression rule.
