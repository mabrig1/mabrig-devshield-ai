# DevShield Threat Intelligence Agent (experimental)

Runs every six hours using GitHub Actions (subject to GitHub scheduling delays) and on demand. Fetches up to 100 reviewed GitHub Security Advisories, optionally queries OSV for explicitly supplied package/version pairs, emits a JSON evidence artifact, and reports collector failures.

This is an **advisory collection agent**, not a fully autonomous patcher, exhaustive vulnerability database, continuous real-time sensor, or production WAF update. It does not mutate application code or deploy blocking rules.

To check specific packages, supply a JSON array via the workflow environment or run locally:
```sh
DEVSHIELD_WATCH_PACKAGES='[{"name":"axios","version":"1.14.1","ecosystem":"npm"}]' node scripts/threat-intel-agent.mjs
```

The resulting artifact is in `reports/threat-intel-latest.json`. Failures are explicitly marked and return a nonzero exit status. The scheduled run does not persist a historical database or deduplicate issues; configure monitoring and alert routing before relying on it operationally.

Next phases: incremental advisory pagination, verified lockfile inventory, diff against persisted snapshots, severity and exploitability triage, PR proposals with tests, human approval and rollback. Restrict the Actions permissions and pin third-party actions to full audited commit SHAs before enforcing organization-wide use.
