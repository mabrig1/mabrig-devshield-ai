# Repository Threat Preflight (November 2026)

**Status:** offline, read-only, evidence-based pre-build screening. This is not antivirus, a sandbox, a guarantee of safety or a malware attribution engine.

Doctor Web's November 5, 2026 research documented malicious Visual Studio build events / .suo files and unusually whitespace-concealed Go and Python payloads in fake GitHub security projects. DevShield now offers a deterministic first-pass review designed for *untrusted cloned repositories before their first build or script execution*.

## Usage

On an existing **unexecuted** checkout, with Node.js 20+ already trusted and installed:

```bash
npm run preflight -- ./path/to/untrusted-checkout --fail-on high
# Or directly:
node bin/repository-preflight.mjs ./path/to/untrusted-checkout --fail-on critical
```

The scanner reads source as data; it does **not** run git, npm install, build commands, project scripts, downloaded executables, Python or Go. It does not fetch or clone GitHub URLs, open the network, require tokens or send source code to an AI model. A managed application such as BuildRx must provide a separate **safe checkout** with no credentials and ensure any later build occurs in an isolated, resource-limited worker.

JSON is written to standard output, with no source text or secrets. Exit codes:
- `0`: completed, no findings at/above the selected threshold. **Not a clean bill of health**.
- `1`: completed with findings at/above the selected threshold.
- `2`: invalid input/arguments, unsupported scan content, unreadable file, unsafe symlink or scan limit; **fail closed**.

Findings include stable rule names, severity, relative path and line, but no snippet. The `complete` and `status` fields distinguish *no indicators observed* from *incomplete* and *suspicious*. CI should block on nonzero exit codes by default. Set `--fail-on none` only for deliberate report-only evaluation; incomplete scans still exit 2.

## Initial checks

1. Visual Studio `.csproj`, `.vbproj`, `.fsproj`, `.targets`, `.props`: build events or MSBuild Exec invoking shell interpreters or download tools.
2. Suspicious PowerShell encoded commands and download-then-immediate-execute sequences.
3. Python and Go executable/network operations concealed behind unusually long leading whitespace.
4. Python execution of dynamically decoded/decompressed content; Go launching PowerShell.
5. Heuristic PowerShell strings in Visual Studio `.suo` binary data.
6. **Contextual investigative signals** for the domains and IPv4 address published by Doctor Web for this campaign (snapshot dated 2026-11-05).

**Source:** [Doctor Web's original investigation](https://news.drweb.com/show/?i=15311&lng=en) (November 5, 2026). Known indicators can appear in benign threat-intelligence fixtures; a match does not prove infection.

## Safety boundaries and known limits

- The scanner does **not** execute source code or parse executable malware. It does **not** unpack archives or inspect all binary formats. `.suo` checks are only crude string views, not a full compound-file parser. No independent malware database or online reputation lookup is included.
- The preflight examines a bounded set of known code/build-script extensions; README and other documentation, archives and generated dependencies are outside its scope. It skips `.git`, `node_modules`, `.next`, `.nuxt`, `dist`, `build`, `coverage`, `vendor` and Python virtual environments. Do not mistake excluded areas for inspected files.
- By default it stops trusting a result if a symlink appears outside excluded directories, a relevant file exceeds 1.5 MB, a traversal limit (2,000 entries / depth 40) is crossed, or source cannot be read. These limits favor refusal over a misleading pass.
- Static pattern detection has false positives and false negatives. Attackers can conceal code in archives, binaries, unusual formats, indirection or brand-new domains. Never claim “safe to run” based on this scanner alone.
- For a production service receiving arbitrary external repositories, use an ephemeral, unprivileged checkout with strict disk/time/network limits. Keep all production credentials, tokens and SSH agents out of the scanning and build environment. Validate immutable commit identifiers; never use this scanner as a reason to remove sandboxing.

## BuildRx integration boundary (follow-on)

1. Obtain a source snapshot using a separately trusted GitHub acquisition component; resolve a specific commit SHA. **Do not execute repository commands.**
2. Run `devshield-preflight` against that directory with no secrets or outbound networking; store the JSON result scoped to the submitting tenant.
3. **Reject or quarantine** when exit status is 1 or 2. Never silently bypass incomplete scans. Allow manual security review by an authorized operator, with an audit trail.
4. If policy permits, queue any later build to a different, isolated worker with no inherited production credentials, limited outbound access, quotas and cleanup.
5. Publish neither an automatically computed “trusted” badge nor an unreviewed auto-deploy feature based on these heuristics.

This first slice intentionally does **not** change BuildRx, publish new services or modify any cloud settings.
