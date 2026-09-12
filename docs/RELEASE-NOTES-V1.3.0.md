# MABRIG DevShield AI v1.3.0

**Catch risky changes before they leave the developer's machine.**

Version 1.3 brings the DevShield policy engine to local Git workflows.

## Local CLI

```bash
npm run scan
```

By default the CLI scans staged Git changes and fails at high severity.

Useful options:

```bash
npm run scan -- --strict --fail-on medium
npm run scan -- --repository --fail-on high
node bin/devshield.mjs --staged --baseline .devshield-baseline.json
```

## Pre-commit protection

An example hook is available at `examples/pre-commit.sh`.

The staged scanner reads the actual Git index snapshot, not the current working-tree file. This means a risky file that is staged and then edited to look safe in the working tree is still scanned correctly before commit.

## Reused policy

The CLI consumes the same:
- `.devshield.json`
- baseline format
- deterministic rules
- severity overrides
- exclusions
- SARIF/JSON reports
- merge/fail thresholds

used by the GitHub Action.

## Compatibility

The GitHub Action interface remains backward-compatible on the v1 line.
