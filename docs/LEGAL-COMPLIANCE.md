# Legal & Compliance Shield

MABRIG DevShield AI v2.9 integrates repository-facing legal and compliance risk spotting into the normal DevShield Action and local CLI.

## What it checks

The current deterministic checks look for signals such as:

- missing root software licence documentation;
- missing privacy notice;
- missing terms of service;
- inconsistent package licence metadata;
- health/medical claims;
- financial or guaranteed-return claims;
- legal-service claims;
- children/minor-related processing language;
- AI-related functionality without an obvious AI-use disclosure.

These are repository-facing review signals. They are not findings of unlawful conduct and they are not a substitute for professional legal advice.

## Modes

### advisory

This is the default. DevShield generates legal/compliance evidence and exposes Action outputs, but the signals do not alter the security risk score and do not participate in `fail-on`.

```yaml
with:
  legal-compliance: advisory
```

### enforce

Legal/compliance signals are normalized into the standard DevShield finding model and participate in the existing baseline, risk-score and `fail-on` mechanics.

```yaml
with:
  legal-compliance: enforce
  fail-on: high
```

Use this only when your organization has deliberately decided that these repository signals should be part of its CI gate.

### off

```yaml
with:
  legal-compliance: off
```

## Policy file

```json
{
  "legalComplianceMode": "advisory"
}
```

Accepted values are `off`, `advisory`, and `enforce`.

## Outputs

- `legal-compliance-state`
- `legal-compliance-findings`
- `legal-compliance-high`
- `legal-compliance-file`

## Evidence files

DevShield writes:

- `.devshield/devshield-legal-compliance.json`
- `.devshield/devshield-legal-compliance.md`

The main `devshield-report.json` also includes the legal/compliance configuration, summary and raw advisory findings.

## Safety model

The scanner deliberately uses transparent, deterministic repository evidence. It does not:

- claim that a product is legally compliant or non-compliant;
- infer jurisdiction-specific legal conclusions;
- replace counsel, a data-protection officer, or a regulated professional;
- silently block existing customers.

Advisory mode is therefore the default. Enforcement requires an explicit opt-in.
