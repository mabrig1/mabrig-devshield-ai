# DevShield 3.3.0 — October runtime advisory checks

Adds offline, source-linked checks for PHP2Shell, the October Node.js security
release, and references to LiteLLM's October 21 compromised artifacts. Includes
PHP's October 23 conditional session advisory and an explicit runtime-version CLI.

The normal scanner integrates these checks with scoped scans, policy, exclusions,
baselines, JSON/SARIF and severity gates. Version reporting now reads package.json,
correcting the previous scanner/package mismatch.

Declarations do not prove deployment or compromise. Unresolved versions remain
review signals; no live probing, host patching, secret rotation, automatic WAF rules
or release-tag movement is included. See [coverage and rollout](OCTOBER-2026-ADVISORIES.md).

Validation: deterministic branch-boundary, input parsing, false-positive, CLI,
policy/baseline, staged-index, changed-line, JSON/SARIF and full-suite checks.
