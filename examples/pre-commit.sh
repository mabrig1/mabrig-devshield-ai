#!/usr/bin/env bash
set -euo pipefail

# Example Git pre-commit hook.
# Copy or symlink this file to .git/hooks/pre-commit and make it executable.
node "$(git rev-parse --show-toplevel)/bin/devshield.mjs" --staged --fail-on high
