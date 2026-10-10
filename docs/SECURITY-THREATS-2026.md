# 2026 supply-chain incident response and hardening

This checklist supplements the existing DevShield v3.2 dependency intelligence, WAAP and approval-gated remediation. It does not claim a dependency is compromised without matching evidence.

## High-priority incidents to investigate

- **Axios (March 31):** check lockfiles and installation records for `axios@1.14.1` and `axios@0.30.4`. These versions were maliciously published. An affected install requires host and credential incident response, not just upgrading the dependency.
- **Shai-Hulud / ChainDrop (August):** inspect install lifecycle scripts, unexpected `setup.mjs` or Bun executables, unauthorized package releases and new outbound destinations.
- **Tensorlake (October 8):** investigate any installation of `tensorlake@0.5.144`; confirm advisories and affected artifacts before declaring compromise.
- **GitHub Actions trust boundaries:** inspect `pull_request_target`, checkout of untrusted fork code, shared caches, workflow token permissions and unpinned actions.

## Detection pipeline (advisory first)

1. Parse lockfiles offline. Never execute dependencies to inspect them.
2. Correlate package name + **exact version** against OSV, GitHub Advisory Database and vendor notices, retaining source, timestamp and confidence.
3. Flag install scripts, suspicious registry URLs, unexpected new dependencies and publishing provenance inconsistencies for review; these signals alone are not proof of malware.
4. Review privileged GitHub workflows and cross-trust cache usage; report file and line evidence.
5. Emit stable fingerprints and SARIF/JSON using existing DevShield reporting facilities.
6. Keep newly introduced detections in report-only mode until validated on fixture repositories.
7. For confirmed malicious installs: isolate runners, revoke and rotate reachable tokens from a clean device, audit repository/package releases, rebuild artifacts and review cloud access.

## Acceptance criteria

- Unit fixtures cover malicious-version exact matches and benign neighboring versions.
- No package installation, shell execution, credential reads or network calls are required for offline scanning.
- Network advisory retrieval uses timeouts, bounded payloads and a failure state of **unknown**, not safe.
- All proposed blocking rules have tests for false positives and a documented rollback.
- Remediation remains approval-gated; no automatic secret rotation or destructive actions.

## Authoritative references

- Microsoft ChainDrop analysis: https://www.microsoft.com/en-us/security/blog/2026/08/04/chaindrop-supply-chain-compromise-anatomy-self-propagating-worm/
- GitHub supply-chain hardening: https://github.blog/security/supply-chain-security/disrupting-supply-chain-attacks-on-npm-and-github-actions/
- GitHub Advisory Database: https://github.com/advisories
- OSV: https://osv.dev/
- CISA KEV: https://www.cisa.gov/known-exploited-vulnerabilities-catalog

**Scope:** defensive research and operational guidance. This file alone does not activate new scanning or WAF enforcement.
