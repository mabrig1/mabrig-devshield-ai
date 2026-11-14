# Modern-App Vulnerability Shield — November 2026 Advisory Snapshot

**Status:** opt-in offline installed-version advisory matcher prepared on November 14, 2026. It is not a live CVE feed, malware detector, proof of exploitability, dependency updater, or replacement for npm audit or GitHub dependency review.

## Threats covered

Critical modern-app advisories published or updated during October–November 2026 affect React Server Components, Next.js, Mongoose, Better Auth, TanStack Start, DOMPurify and Storybook. Risk often depends on specific server-side execution, public routes, auth plugin combinations, development servers, or sanitizer settings. A lockfile match calls for investigation and patching, never claims compromise.

The curated catalog has 13 package/range definitions, sourced from these vendor/GitHub advisories:

- CVE-2026-126187, GHSA-xqc2-xf4c-x3h3: React Server Components (react-server-dom-webpack/-turbopack/-parcel), vulnerable 19.0.0–19.0.8, 19.1.0–19.1.9, 19.2.0–19.2.8, 19.3.0; minimum patches 19.0.9, 19.1.10, 19.2.9, 19.3.1. https://github.com/advisories/GHSA-xqc2-xf4c-x3h3
- GHSA-673q-mjm6-r5xr: Next.js typed-array use cache RCE; versions 16.0.0–16.4.0; minimum patch 16.4.1. https://github.com/advisories/GHSA-673q-mjm6-r5xr
- GHSA-2464-fhr4-w9xw: Next.js image-optimizer SVG RCE; versions 10.0.0–15.5.27 and 16.0.0–16.4.0; minimum patches 15.5.28 and 16.4.1. https://github.com/advisories/GHSA-2464-fhr4-w9xw
- CVE-2026-125120, GHSA-pcrw-h46h-c93h: Mongoose countDocuments sanitizeFilter bypass; versions before 6.13.11, 7.8.12, 8.24.3, 9.9.2 by major. https://github.com/advisories/GHSA-pcrw-h46h-c93h
- CVE-2026-114607, GHSA-965c-763c-88jm: Better Auth OAuth state/Magic Link auth bypass, 1.4.0-beta.18 to before 1.7.7. https://github.com/advisories/GHSA-965c-763c-88jm
- CVE-2026-102989, GHSA-qx66-fv34-fjm8: TanStack Start server-function reflected XSS; patched react-start 1.168.60, solid-start 1.168.57, vue-start 1.168.56, start-server-core 1.169.39. https://github.com/advisories/GHSA-qx66-fv34-fjm8
- GHSA-cg2g-xh64-v4q7: DOMPurify SAFE_FOR_TEMPLATES shadow-root bypass, 3.4.4–3.4.16, patched 3.4.17. https://github.com/advisories/GHSA-cg2g-xh64-v4q7
- CVE-2026-114125, GHSA-f2ph-cmg5-wxc8: Storybook development-server origin validation; patched 8.6.19, 9.1.21, 10.6.2, and 11.0.0-alpha.6 (catalog includes reviewed 8/9/10 stable ranges only). https://github.com/advisories/GHSA-f2ph-cmg5-wxc8

Consult current vendor advisories before choosing a release: advisories and patched versions can change. Only exact ranges encoded in the matcher are assessed.

## Run locally without installing or executing project code

Run these commands FROM THE DIRECTORY OF THE APP BEING INSPECTED, using a DevShield checkout or installed package containing the scanner:

    node /path/to/devshield/bin/known-advisories.mjs --mode advisory

By default the scanner reads npm-shrinkwrap.json before package-lock.json, accepts npm v2/v3 lockfile structure, and writes:

    .devshield/known-advisories.json
    .devshield/known-advisories.sarif

To enforce critical-version matches after review:

    node /path/to/devshield/bin/known-advisories.mjs --mode enforce --fail-on critical

Exit 0: advisory-only, or complete enforcement scan with no threshold match.
Exit 1: critical match blocked.
Exit 2: incomplete enforcement (missing lockfile, unsupported installed versions or truncated findings) or invalid input.

Advisory mode never blocks on matches, but invalid input, corrupt lockfiles or unsafe paths still exit 2.

## GitHub Action integration (after review and release)

An Action reference containing this implementation supports:

    with:
      known-advisories: advisory

Values: off (default), advisory (report only), enforce (critical gate; incomplete coverage fails closed). Outputs include known-advisories-state, known-advisories-findings, known-advisories-report-file and known-advisories-sarif-file. Reports are separate from core diff-aware risk scoring and must be reviewed independently; use trusted artifact upload if you want to retain them in CI.

## Limitations and safeguards

- Exact installed npm lockfile versions only; package.json ranges and source-code text are not enough.
- Scoped, nested and aliased npm installations are supported with deterministic fingerprints and advisory source links.
- Unparseable candidate versions, missing/unsupported lockfiles and truncated results are explicitly incomplete in enforce mode.
- Local/workspace-linked packages are excluded from registry-package assumptions. Artifact provenance is not verified.
- No network calls, code execution, package installation, source upload, AI key or auto-upgrade occurs.
- No exploitability determination, active exploitation claim, or full CVE-database coverage. Supplement with npm audit, Dependabot, GitHub Dependency Review, OSV and vendor advisories.
- Snapshot is dated November 14, 2026; maintainers should review changes weekly and add tests for every revision before expanding enforcement.

No merge, Cloudflare deployment, D1 migration or production policy change is included in this upgrade proposal.
