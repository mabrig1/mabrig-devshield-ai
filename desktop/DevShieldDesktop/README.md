# MABRIG DevShield Endpoint Threat Guard — Windows Desktop 0.1

**Status: unsigned, experimental Windows x64 portable application for developer-threat preflight.** This is not a certified antivirus, real-time system protection, Microsoft Defender replacement, EDR, or a malware-removal tool.

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

The GUI starts only the trusted co-located `DevShield-Endpoint.exe` using an argument list (no shell), reads its JSON output and never executes the scanned file.

## Developer build

Using Windows with the .NET 8 SDK and Bun 1.4.4:

    bun build --compile --target=bun-windows-x64 ./bin/endpoint-shield.mjs --outfile dist/DevShield-Endpoint.exe
    dotnet publish desktop/DevShieldDesktop/DevShieldDesktop.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -o dist/desktop

Copy the scanner to `dist/desktop/DevShield-Endpoint.exe` before opening the GUI. The GitHub workflow builds and verifies both automatically.

## Verified boundaries

The desktop client does **not** scan arbitrary compressed archive contents, validate Authenticode signatures or a malware signature database, detect running or memory-only malware, guarantee protection against novel malicious programs, or perform full-system antivirus scans. Keep Microsoft Defender or your established endpoint antivirus enabled. Protect JSON reports because paths, hashes and security context may be sensitive.

The user's private Cloudflare R2 bucket `devshield-storage` is **not** required for local scanning. If later used to host downloads or reports, configure authenticated distribution with explicit tenant access controls; never expose secrets or scan content by default.
