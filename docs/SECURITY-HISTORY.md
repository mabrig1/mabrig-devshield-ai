# Security Graph History

DevShield v2.1 adds reviewed security history on top of the v2.0 control plane. The goal is to make security regressions visible across commits without inventing exploitability or silently trusting mutable artifacts.

## History file

The default committed history path is:

```text
.devshield-security-history.json
```

A scan generates a candidate at:

```text
.devshield/devshield-security-history-candidate.json
```

The Action never commits or overwrites the trusted history file. Review the candidate before adopting it.

## Integrity model

Every entry contains:

- a monotonically increasing sequence number;
- repository/revision metadata;
- graph ID and canonical graph SHA-256 digest;
- control-plane summary and blast-radius summary;
- a bounded risk-exposure snapshot;
- regression-classification summary;
- the previous entry hash;
- the current entry SHA-256 hash.

This forms a tamper-evident hash chain.

### Optional signing

Set the Action input with a GitHub secret:

```yaml
security-history-signing-key: ${{ secrets.DEVSHIELD_SECURITY_HISTORY_KEY }}
```

Or for the local CLI, set:

```bash
export DEVSHIELD_SECURITY_HISTORY_SIGNING_KEY='...'
npm run scan -- --repository --security-history on
```

Do not pass signing keys as command-line arguments.

With a key, DevShield computes HMAC-SHA256 over each entry hash. Without a key, history remains hash-chained but is not described as signed.

If an existing history file fails chain or signature validation, DevShield warns and refuses to trust it as comparison history. It generates a new candidate chain instead of silently accepting corrupt evidence.

## Risk-exposure snapshot

Risk seeds are current graph nodes of type:

- `finding`
- `advisory`

For each seed, DevShield records the bounded graph neighborhood reachable within four edges, including the count of evidence-linked and contextual nodes.

The history file stores these compact exposure snapshots rather than full source code.

## Regression taxonomy

When a previous valid committed history entry exists, DevShield classifies:

### New risk

A finding/advisory node exists now but not in the previous history entry.

### Expanded exposure

The same risk node remains, but its bounded reachable-node count increased.

### Reduced exposure

The same risk node remains, but its bounded reachable-node count decreased.

### Resolved risk

A previous risk node is absent from the current graph.

### Unchanged inherited debt

The same risk node remains with the same bounded reachable-node count.

The overall state is:

- `regression` if there is any new risk or expanded exposure;
- `improvement` when there is no regression and at least one resolved risk or reduced exposure;
- `unchanged` when neither regression nor improvement is observed;
- `unclassified` for the first trusted snapshot.

These labels describe graph evidence, not breach probability or exploitability.

## Retention

The default history limit is 60 entries and can be configured from 1 to 200.

When retention truncates older entries, the retained chain is resealed from its new first entry. If a signing key is supplied, retained entries are HMAC-signed during resealing.

## Privacy

History records identifiers, hashes, revision metadata, aggregate summaries, and risk-exposure metadata. It does not store source snippets or secret values.

DevShield Cloud receives only compact history state, sequence, signing-status flag, integrity/signature validation state, and regression summary. The committed history chain and HMAC values are not exported through this field.

## Relationship to other DevShield baselines

The three mechanisms serve different purposes:

- `.devshield-baseline.json` — finding fingerprint debt baseline used by merge gating;
- `.devshield-security-graph-baseline.json` — one reviewed graph snapshot used by v2.0 structural graph diffing;
- `.devshield-security-history.json` — multiple reviewed, hash-chained exposure snapshots used by v2.1 longitudinal regression detection.

None is mutated automatically by the GitHub Action.
