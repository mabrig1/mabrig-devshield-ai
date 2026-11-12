# DevShield Endpoint Threat Guard (experimental, November 2026)

This tool is an **offline-first, developer-focused source, download and build-artifact threat preflight**, NOT a general-purpose antivirus, malware signature engine, OS endpoint protection/EDR, or a promise that suspicious packages cannot execute. It cannot detect arbitrary malware, running processes, rootkits, malicious binaries, or threats introduced after a scan.

**Status: proposal / review-stage CLI code.** Not a signed Windows installer, macOS app, Linux package, service, or production distribution.

## Quick start

Run in a trusted Node.js environment with the existing repository files:

    node bin/endpoint-shield.mjs --path /path/to/untrusted-project --fail-on high

Scan one download or artifact:

    node bin/endpoint-shield.mjs --path /path/to/download.zip --format json

Opt-in polling (NOT real-time OS protection):

    node bin/endpoint-shield.mjs --path /path/to/downloads --watch-seconds 10

For editor integration, use --format sarif to return SARIF 2.1.0 instead of the JSON report. Reports are written to standard output; no automatic upload, file deletion, quarantine, process termination, or script execution occurs.

Exit codes for one-shot mode:
- 0: scan completed with no findings at the configured severity threshold. Does NOT prove safety.
- 1: a finding met the threshold and the scan completed.
- 2: incomplete scan, unsafe input, missing permissions, invalid arguments, or another error.

Poll mode checks the path periodically and only prints JSON when the observed state changes. It does not hook the OS filesystem driver, block execution, intercept downloads, or maintain a protected quarantine. Use a trusted native antivirus/EDR for actual device protection.

## Detection scope

Reuses the existing deterministic Repository Threat Preflight source pattern checks, and the public DevShield token/secret rules, to spot known indicators in developer files. Also adds:

- Dangerous npm lifecycle hooks **only when** a package install/prepare hook pairs remote retrieval with execution, an encoded PowerShell command, or suspicious Windows download-to-execute utilities. Normal lifecycle hooks are not automatically malicious.
- ZIP/JAR/VSIX/NuGet/Python wheel **central-directory-only** review for unsafe traversal paths and extreme compressed/uncompressed expansion ratios. No archive extraction or decompression occurs; malicious contents inside archives are not detected.
- SHA-256 hashes for up to 300 files to support local investigation. Hashes alone do **not** establish malware identity or verify signatures.
- Explicit incomplete coverage for symlinks, unreadable/oversized inputs, unscanned native binaries, unsupported/large archives, and global scan limits.

All reported token matches use **fixed rule descriptions**, not credential values. Logs contain paths and static descriptions, which may themselves be sensitive; protect exported reports accordingly. Known network indicators are leads, not attribution or proof of infection.

## Bounded read-only behavior

Limits: max 2,000 visited paths, max 2 MiB per file, max 48 MiB of bytes per scan, depth 32; skips .git, node_modules, vendor and common virtual environment/cache folders; never follows symlinks. The scanner refuses unusual input types. Unsupported binaries are hashed only, marked incomplete, and **not** treated as clean.

Detection results use one of:
- suspicious: static indicators were observed;
- no-indicators-observed: the covered material had no matching patterns;
- incomplete: important content was skipped or could not be inspected.

No online reputation lookup, certificate verification, signature database update, machine-learning malware analysis, real-time prevention, privileged daemon, driver, tray icon, installation, or self-update has been implemented.

## Why this can become a commercial product

The **free** tool remains local and useful before a Git commit; a possible commercial version could add verified signed installers, a sandboxed archive parser, controlled signature updates, organization device policy, private telemetry opt-in, remediation review, and a console integrating DevShield Cloud. These are not included or enabled by this PR. Never collect filesystem contents, paths, or hashes centrally without explicit consent and documented retention/deletion controls.

## Test

    node --test test/endpoint-shield.test.mjs
    node --check src/endpoint-shield.mjs
    node --check bin/endpoint-shield.mjs
    npm test

Security review and artifact-parser fuzzing are needed before publishing a signed desktop product. No system protection or reliable negative malware verdict is claimed.
