# DevShield Endpoint v0.2 vs open-source antivirus, EDR and DevSecOps

**Audit date:** November 12, 2026. **DevShield baseline:** PR #48 (commit 9f6ad7dbfbf75f18a41a1d45a69eccf549f14175), experimental unsigned Windows x64 portable app. **Benchmark type:** official GitHub feature/capability comparison plus separate local synthetic fixture regression. This is NOT an antivirus detection-rate, false-positive-rate, or cross-vendor speed comparison.

## Verified current DevShield scope

- Native offline scanner: developer source indicators, malicious-looking package lifecycle scripts, exposed-secret patterns, ZIP central-directory metadata, and PE32/PE32+ structural/import/section/static string triage. Flags are investigative signals, NOT verified malware.
- Optional separately installed official ClamAV: malware-signature matching via clamscan.exe and user-approved official FreshClam definition updates. ClamAV and its virus database are NOT bundled.
- User-approved reversible quarantine for ClamAV-confirmed hits restricted to eligible user Documents/Desktop/Downloads files on the same volume. Not a system-protected anti-tamper facility; no automatic deletion.
- Review-stage Windows GUI with select file/folder/Downloads, JSON export and optional 60-second foreground polling. No system service, memory scan, real-time blocking, signature packaging, Authenticode signing, independent malware-detection certification or background updater.

## GitHub comparison — facts, not vendor efficacy claims

Official repositories were examined on November 12, 2026. Repo pushed dates only show activity, NOT security quality or support guarantees. Licenses must be examined at the exact code revision before redistribution.

| Project | Upstream repo | Confirmed function | Advantage over current DevShield | Suggested direction |
|---|---|---|---|---|
| Cisco Talos ClamAV (GPL-2.0, active Nov 2026) | https://github.com/Cisco-Talos/clamav | Actual signature-based file malware scanning, command-line and daemon, FreshClam signature updates | Actual malware engine; DevShield requires external installation | Maintain official, authenticated integration, engine/database version checks, and safe errors |
| ClamWin (GPL-2.0, Windows GUI, pushed May 2026) | https://github.com/clamwin/clamwin | Native Windows GUI frontend to ClamAV tools; Explorer context integration and installer build support | Stronger Windows packaging/user workflow | Consider a signed Explorer action and installer after review |
| Loki-RS (GPL-3.0, beta, pushed Sep 2026) | https://github.com/Neo23x0/Loki-RS | YARA-X scanning of files and some process memory, hash/filename/network IOC detection, ZIP content scanning, parallel workers, JSONL/HTML | Much wider rule/IOC/memory detection scope | Optional curated, signed/versioned YARA layer with consent and FP tests |
| YARA-X (BSD-3-Clause, active Nov 2026) | https://github.com/VirusTotal/yara-x | Rust pattern-matching engine with programmable YARA rules | Mature rule engine for future expansion, not an antivirus suite by itself | Evaluate isolated optional scan engine and rule provenance |
| Wazuh (active Nov 2026) | https://github.com/wazuh/wazuh | Central SIEM/XDR, endpoint agents, FIM, inventory, active response | Device-wide telemetry and policy-driven response | Long-term consent-based agent; large engineering/security lift |
| WHIDS (AGPL-3.0, last push Feb 2023) | https://github.com/0xrawsec/whids | Sysmon/Windows event-based EDR, event correlation and artifact collection | Runtime Windows event telemetry vs static file heuristics | Architectural reference only; maintenance recency concern |
| OpenEDR (license requires detailed examination) | https://github.com/ComodoSecurity/openedr | Windows EDR architecture | Deeper runtime/instrumentation coverage | Reference only; do not copy privileged components without independent review |
| Trivy (Apache-2.0, active Nov 2026) | https://github.com/aquasecurity/trivy | CVE/SBOM/dependency, misconfiguration, secret and license scans | Much wider software-vulnerability scope; not an antivirus | Optional report interoperability, not replacement of AV engine |
| Semgrep Community Edition (license varies by component, active Nov 2026) | https://github.com/semgrep/semgrep | Local multi-language SAST pattern analysis, IDE and CI workflows | Broader code semantics than DevShield source heuristics; CE cross-file limits documented | Opt-in SARIF finding interoperability |
| Gitleaks (MIT, security-maintenance status noted in README) | https://github.com/gitleaks/gitleaks | Dedicated Git-history/files/stdin secret scanning | More mature secret-history coverage; not antivirus | Optional result ingestion with verified redaction |

**Important:** Original Python Loki (https://github.com/Neo23x0/Loki) explicitly says it is in inactive maintenance/deprecated for new feature development. Compare the active beta Loki-RS instead.

## Capability matrix (documented, not performance-tested)

Legend: YES = documented function; OPTIONAL = needs external engine/configuration; PARTIAL = narrower implementation; NO = not present; N/A = different category.

| Capability | DevShield 0.2 | ClamAV | Loki-RS | Wazuh | Trivy |
|---|---|---|---|---|---|
| Actual malware signature matching | OPTIONAL (ClamAV) | YES | YES (YARA/IOC) | OPTIONAL/integrations | N/A |
| Official antivirus definition updates | OPTIONAL (manual FreshClam) | YES | Different YARA rule updater | N/A | N/A |
| Read-only malicious build-hook preflight | YES | N/A | PARTIAL | PARTIAL | PARTIAL |
| File/archive content malware signatures | OPTIONAL (ClamAV) | YES | YES | OPTIONAL | N/A |
| Process-memory or live event analysis | NO | Limited or separate integration | YES/limited by OS privileges | YES | N/A |
| Autonomous realtime OS response | NO | Requires separate integration | NO | YES, if configured | NO |
| Manual file quarantine | PARTIAL; user-only restricted paths | Tool/config dependent | N/A | Active response integration | N/A |
| Vulnerability/CVE/SBOM scanning | Separate DevShield repo modules; desktop limited | N/A | N/A | YES | YES |

YES and OPTIONAL do not measure actual detection accuracy. No competing engine was executed in this comparison.

## Reproducible native-engine synthetic regression

Commands:

    node --test test/endpoint-benchmark.test.mjs
    node benchmark/endpoint-synthetic.mjs
    node benchmark/endpoint-synthetic.mjs --json

Harness: 10 inert isolated temporary fixtures, 3 runs per fixture; all fixtures removed afterward.

- 2 ordinary benign controls: JS module, normal npm lifecycle script
- 7 explicit static indicators: encoded PowerShell, download-to-execute, risky install hook, synthetic placeholder credential, ZIP traversal path, anomalous ZIP expansion metadata, non-executable synthetic PE32 suspicious import metadata
- 1 intentionally malformed executable required to produce INCOMPLETE instead of a clean result

Each result gives rule IDs, complete/incomplete, bytes, and median milliseconds on the testing runner. The cases are selected from DevShield's existing rules. **A 10/10 test pass is NOT a malware detection rate, sensitivity, specificity, false-positive-rate measurement, or a cross-vendor speed benchmark.** No EICAR file, live secret, executable malware, third-party binary, or AV definitions are created/downloaded by the default harness.

To conduct a fair antivirus head-to-head, use an authorized isolated lab with signed provenance of samples, benign/known-malicious holdout corpus, independent ground truth, exact engine/definition versions, comparable scan scope, hardware/CPU/IO controls, repeat runs, miss/false-alert review and retention policy. EICAR is a safe interoperability smoke test only, NOT an indicator of real-world detection efficacy. Do not disable Windows Defender or execute real malware on personal machines.

## Prioritized improvement opportunities

1. **P0: Safer verdicts and containment:** mark stale/missing definitions, timeout, oversized/skipped files, malformed archive, driver/permission errors, and truncated scans INCOMPLETE. Avoid false-clean verdicts. Improve quarantine race resistance and directory ACLs; signed releases and publisher verification.
2. **P0: Harden ClamAV integration:** show engine/version/signature timestamps, enforce official update source, errors/retries/proxy support, update quotas; no automatic third-party GitHub rule downloading and no auto-deletion.
3. **P0: Real isolated lab:** confirm installed official ClamAV detects EICAR, test full and partial scans, clean baseline, tamper scenarios, restore and Defender compatibility. Never claim antivirus efficacy based on internal fixture tests.
4. **P1: Optional YARA-X integration:** vetted and versioned rules, license/provenance review, independent FP testing, isolate untrusted parsers, do not run arbitrary downloaded rules.
5. **P1: Better software supply chain coverage:** optional interoperable Trivy/Semgrep/Gitleaks reports; keep privacy-first static source analysis and no-source-upload guarantee.
6. **P2: System service/EDR only after threat modeling:** least privilege, signed update mechanism, controlled device policy, secure logs, strong endpoint management, recovery and specialist Windows kernel review.

## Official sources

https://github.com/Cisco-Talos/clamav
https://docs.clamav.net
https://github.com/clamwin/clamwin
https://github.com/Neo23x0/Loki-RS
https://github.com/Neo23x0/Loki
https://github.com/VirusTotal/yara-x
https://github.com/wazuh/wazuh
https://github.com/0xrawsec/whids
https://github.com/ComodoSecurity/openedr
https://github.com/aquasecurity/trivy
https://github.com/semgrep/semgrep
https://github.com/gitleaks/gitleaks
