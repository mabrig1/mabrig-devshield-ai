# MABRIG DevShield AI v1.4.0

**Connect the transparent DevShield scanner to a managed security control plane without sending source code.**

## DevShield Cloud bridge

Version 1.4 adds an optional managed-export path designed for DevShield Cloud and commercial GitHub App features.

New Action inputs:

- `cloud-api-url`
- `cloud-token`
- `cloud-required`

New output:

- `cloud-export-status`

## Privacy-first payload

Cloud export sends structured security metadata and findings, including fingerprints, rule/severity/category, file/line locations, aggregate risk, dependency advisory metadata and GitHub run/repository identifiers.

It does **not** send source code, source snippets, diff text, GitHub tokens, Cloud tokens or local environment variables.

## Fail-open or fail-closed

The default remains resilient: if managed export fails, local deterministic scanning continues.

Paid or regulated deployments can use:

```yaml
cloud-required: true
```

to require successful managed ingestion.

## Compatibility

All Cloud inputs are optional. Existing `@v1` workflows remain backward-compatible and continue to work without DevShield Cloud.
