# Local DevShield CLI

DevShield can run before GitHub Actions.

## Staged scan

```bash
npm run scan
```

The default local mode is equivalent to:

```bash
node bin/devshield.mjs --staged --fail-on high
```

## Why the Git index matters

A pre-commit scanner must inspect the exact snapshot that Git will commit. DevShield's staged mode reads each staged file from the Git index, so later working-tree edits do not change what is reviewed.

## Common commands

```bash
# Strict staged review
npm run scan -- --strict --fail-on medium

# Full repository review
npm run scan -- --repository --fail-on high

# Use a baseline
npm run scan -- --baseline .devshield-baseline.json --baseline-mode new-only

# Disable SARIF locally
npm run scan -- --no-sarif
```

## Pre-commit hook

Copy or symlink `examples/pre-commit.sh` to `.git/hooks/pre-commit`, then make it executable.

```bash
cp examples/pre-commit.sh .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

The hook exits non-zero when the configured severity threshold is met, preventing the commit.

## Recommended team workflow

1. Commit `.devshield.json` so CI and developer machines share policy.
2. Commit a reviewed `.devshield-baseline.json` when adopting DevShield on a legacy repository.
3. Run staged scanning pre-commit.
4. Keep the GitHub Action as the server-side enforcement layer.
5. Protect changes to policy and baseline files with normal review/CODEOWNERS.
