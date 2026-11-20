# DevShield Incident Signals — five early warnings (experimental)

Offline, read-only triage of operator-supplied aggregate telemetry, complementing DevShield repository scans and WAF/WAAP. Not an antivirus, EDR, SIEM, breach detector, or hosted monitoring service.

## Five categories

- email: dailySent and baselineDailySent for the same daily period; unusual volume is at least 100/day, five times a valid baseline of at least 20. unexpectedSender:true is a separate alert.
- outbound: approved boolean and bytesOut (per connection/aggregation); any unapproved connection is reviewed, large transfers of at least 1 MiB receive high severity.
- account: userReportedUnknownChange, unrecognizedSession or unknownTransaction, booleans from trusted records.
- process: approved boolean and cpuPercent; unexpected process with high CPU (at least 60%) receives high severity.
- redirect: expectedHost, observedHost, and optional exact allowlist approvedRedirectHosts; unapproved host mismatches require review.

## Sample private JSON input (use fictional values for first test)

    {
      "version": 1,
      "approvedRedirectHosts": ["checkout.example.org"],
      "events": [
        { "kind": "email", "dailySent": 15000, "baselineDailySent": 300 },
        { "kind": "outbound", "approved": false, "bytesOut": 5000000 },
        { "kind": "account", "unrecognizedSession": true },
        { "kind": "process", "approved": false, "cpuPercent": 86 },
        { "kind": "redirect", "expectedHost": "app.example.org", "observedHost": "other.example.org" }
      ]
    }

Run locally from repo root:

    npm run incident:signals -- --input ./local-aggregate.json
    npm run incident:signals -- --input ./local-aggregate.json --output ./local-private-report.json
    node --test test/incident-signals.test.mjs

CLI accepts a local non-symlink JSON file up to 1 MiB and 5000 events. It performs no outbound requests and outputs only generic rule identifiers, counts, coverage, severity, and recommended follow-ups. Input events, IPs, emails, URLs, credentials and process paths are never echoed. Optional output files are created exclusively, with 0600 mode on supported OSes.

## Interpretation and limitations

A warning is **not proof of a breach**, nor is a no-warning result a security guarantee. Missing evidence is explicitly represented by unassessedKinds and assessment=insufficient-evidence. Never use these heuristics to automatically disable accounts, delete data, stop processes or rotate credentials. An event is only as trustworthy as its source.

This change does NOT connect to Resend, GitHub, Cloudflare, Linux SSH, customer databases, or payment providers. An administrator must export appropriately anonymised, verified event counts. Do not submit raw customer reports, private keys, email bodies, API tokens, payment payloads or raw server logs.

Future provider adapters must be individually approved, least-privilege, read-only, with auditable ingestion, explicit retention, and careful treatment of sensitive information. Cloudflare Workers are not equivalent to self-managed Linux VPS processes.

CI smoke suite adds deterministic tests. No production DNS, secrets, runtime enforcement, scheduled workflow, or dashboard changed.
