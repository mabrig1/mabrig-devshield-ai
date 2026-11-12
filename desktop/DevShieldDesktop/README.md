# MABRIG DevShield Endpoint Threat Guard — Windows Desktop 0.3

**Status: unsigned, experimental Windows x64 portable application for developer-threat preflight.** Includes **optional ClamAV-based virus signature detection, official FreshClam definition updates and reversible user-approved quarantine** when you install the official ClamAV engine separately. It is not a certified antivirus, real-time system protection, Microsoft Defender replacement or EDR.

## Installing the portable version

1. From the GitHub Actions run **Endpoint Guard Windows EXE (unsigned review artifact)**, obtain **DevShield-Desktop-Windows-x64-UNSIGNED** (ZIP).
2. Extract the inner `DevShield-Desktop-Windows-x64-UNSIGNED.zip` to a directory you control.
3. Keep `DevShield-Desktop.exe` (graphical app) and `DevShield-Endpoint.exe` (static scan engine) in the **same folder**. Both are required.
4. Check the two SHA-256 hashes against `SHA256SUMS.txt` and the trusted GitHub Actions build. A checksum guards against accidental modification, **not** publisher authentication.
5. Launch `DevShield-Desktop.exe` from File Explorer with normal user permissions. You should **not** need to run as administrator.

Because the binaries are unsigned review artifacts, Windows may display security or SmartScreen warnings. Do not turn off Defender or bypass security protections to run an untrusted download. For wider distribution, DevShield requires independent code review, signed binaries, provenance, and trusted release infrastructure.

## Features

- Browse and scan a single file, folder, or Downloads directory.
- Offline read-only static checks for suspicious project build scripts, encoded PowerShell, source-embedded secrets, ZIP archive metadata, and limited Windows PE executable header/import/section indicators.
- Results shown with severity, rule, file and explanation; export a local JSON report.
- Optional **60-second polling** while the application window remains open; no kernel hooks, on-access blocking, startup service, background daemon or quarantine.
- No account, cloud key, Cloudflare R2 bucket, subscriptions, API uploads, install scripts, startup persistence, or driver installation.
- A failed, unsupported, oversized, blocked or incomplete scan is **not reported as clean**.
- Optional second engine: official Cisco Talos ClamAV `clamscan.exe` for malware signature detection, plus `freshclam.exe` for downloading official virus definitions. **Not bundled** in this ZIP.
- Manual, reversible quarantine of **ClamAV-confirmed** threats within user Documents/Desktop/Downloads on the system drive; no permanent deletion, no automatic removal, no repairs of running processes.

The GUI starts the trusted co-located `DevShield-Endpoint.exe` using an argument list (no shell), reads its JSON output and never executes the scanned file. Optional ClamAV installation runs a separately selected official vendor engine, also using argument arrays and never using a shell.

## Developer build

Using Windows with the .NET 8 SDK and Bun 1.4.4:

    bun build --compile --target=bun-windows-x64 ./bin/endpoint-shield.mjs --outfile dist/DevShield-Endpoint.exe
    dotnet publish desktop/DevShieldDesktop/DevShieldDesktop.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -o dist/desktop

Copy the scanner to `dist/desktop/DevShield-Endpoint.exe` before opening the GUI. The GitHub workflow builds and verifies both automatically.

## Verified boundaries

The native DevShield scanner does **not** scan arbitrary compressed archive contents, validate Authenticode signatures or a malware signature database, detect running or memory-only malware, guarantee protection against novel malicious programs, or perform full-system antivirus scans. A separately installed ClamAV engine can add official signature scanning for files and many archive formats but still does not guarantee malware-free status. Keep Microsoft Defender or your established endpoint antivirus enabled. Protect JSON reports because paths, hashes and security context may be sensitive.

The user's private Cloudflare R2 bucket `devshield-storage` is **not** required for local scanning. If later used to host downloads or reports, configure authenticated distribution with explicit tenant access controls; never expose secrets or scan content by default.

## ClamAV malware detection, definition updates, and safe removal

1. Obtain the latest stable Windows x64 **ClamAV** from the official vendor page: https://www.clamav.net/downloads (source: https://github.com/Cisco-Talos/clamav). The engine is GPLv2; DevShield does not redistribute it or download executables from GitHub mirrors.
2. Install ClamAV, then launch DevShield. It checks standard install folders, or choose **Set ClamAV folder** and point it at the trusted installation containing **clamscan.exe** and **freshclam.exe**. Do not select a random unknown executable that merely uses those filenames.
3. Click **Update definitions** and approve the outbound FreshClam update. FreshClam downloads official ClamAV signature databases to the current user's LocalApplicationData folder (not Cloudflare R2). The app never uploads scanned files or local source to the update service.
4. Select a file, Downloads, or a folder, then click **Virus definition scan**. Results display signature names. Updates are **on demand**, not periodic until an explicitly reviewed auto-update feature is implemented.
5. To remove a confirmed infected file from its original user folder, select its **ClamAV signature result** and choose **Quarantine selected**, then affirm the warning. DevShield checks the original SHA-256 again before moving it to private, local, **reversible** quarantine. It never permanently deletes the file.
6. **Restore...** recovers an item only with explicit approval, integrity verification and a nonconflicting safe original path.

Quarantine intentionally refuses system directories, source locations outside user Downloads/Desktop/Documents, symlinks, unsupported drives, and files that have changed after scanning. The quarantined file is renamed but not cryptographically sealed or protected from a sufficiently privileged local attacker. It does not stop running malware or repair an already-compromised machine. Keep Windows Defender enabled. Definitions may be stale until FreshClam succeeds, and any scan may miss unrecognized, encrypted, oversized or otherwise uninspected content.

### Open-source comparison and licensing

- ClamAV: https://github.com/Cisco-Talos/clamav — GPLv2 virus engine; official vendor databases and FreshClam updater.
- YARA-X: https://github.com/VirusTotal/yara-x — BSD-3-Clause pattern-matching engine for possible **future** separately reviewed custom rules; not an official ClamAV signature source.
- Neo23x0 signature-base: https://github.com/Neo23x0/signature-base — YARA/IOC intelligence with a separate Detection Rule License (DRL 1.1); **not mirrored or bundled**, and commercial reuse needs license review.

No third-party rules from GitHub are automatically trusted, downloaded, or enforced. ClamAV's normal vendor distribution manages database authenticity and compatibility. The product never promises that a 0-detection result means a computer is virus-free.

## Security hardening: ClamAV scan completeness and signature safety

Official ClamAV documentation warns that exceeding maximum scan limits may skip files and still report a clean result. The hardened app instead:

- Preflights targets before invoking ClamAV. Limits are 100 MiB per file, 1 GiB aggregate size, 2500 visited paths, and 30 directory levels. Unsupported, symlinked, oversized, unreadable or offline files cause INCOMPLETE, never clean.
- Requests explicit alert-exceeds-max and encrypted-container signals; matches named Heuristics.* alerts as REVIEW/INCOMPLETE, not confirmed malware.
- Requires a coherent ClamAV summary, sane exit code and sufficient scanned-file count. Warnings, errors, truncated output and skipped-file indications prevent a clean verdict.
- Checks the official daily signature file modification date conservatively (maximum 7 days) and refuses scanning when it is missing or stale. File timestamps are NOT cryptographic proof of signature authenticity or currentness.
- Prevents a manually modified FreshClam config from silently redirecting the signature mirror.
- Allows only eligible malware signature matches to unlock user-approved reversible quarantine. EICAR test, PUA, Heuristics.Limits.Exceeded, and other Heuristics.* detections cannot be quarantined by DevShield.
- Adds a synthetic parser/coverage/quarantine self-test to the Windows build. No malware or EICAR sample is downloaded or executed.

Limitations: ClamAV file content can change between preflight and scan; deeply nested archives may exceed internal processing limits, dynamic malware is not covered, and application-level quarantine has no anti-tamper Windows service. Full OS antivirus remains necessary. ClamAV itself is an external installation that requires separate independent authenticity checks.

Official references:
- https://docs.clamav.net/manual/Usage/Scanning.html
- https://github.com/Cisco-Talos/clamav/blob/main/docs/man/clamscan.1.in
- https://docs.clamav.net/manual/Usage/SignatureManagement.html
