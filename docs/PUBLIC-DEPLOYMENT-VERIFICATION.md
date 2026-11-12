# Public DevShield Website — Deploy Verification (2026-11-12)

This checklist is for **devshield.mabrigkorie.org**, not the separate Cloudflare commercial API prototype.

## Observed state as of November 12, 2026

- Merge of PR #46 on `main`: `2070da465c84a9113a8901df6b26287f2472d5f7`.
- The original confirmed Cloudflare Preview blocker was Wrangler's missing `previews` configuration. PR #46 introduced the empty Preview block in both Wrangler configuration roots.
- Cloudflare's own PR #46 comment reported a successful Preview build for `9322695` at 12:12 UTC. The subsequent PR #47 and PR #48 cloud previews also reported successful builds.
- A public fetch at approximately 15:09 UTC successfully retrieved the live homepage (title: “DevShield AI — Protect code before deployment”) and `/health`, returning a truthful JSON status with `hostedScanning:false` and `billing:false`.
- This is stronger than a local `wrangler deploy --dry-run`, but **does not verify interactive browser behavior, request routing on every device, full HTTPS edge settings, or commercial APIs**. Cloudflare's dashboard may still have production settings or bindings requiring separate review.

## Verify the actual deployment

Run manually from the repository on a machine that can reach the public domain:

    npm run public:smoke

Or run GitHub Actions: **DevShield Public Deployment Smoke** → **Run workflow**.

The checks issue only HTTPS GET requests; no secrets, source code, or POST bodies are submitted. They confirm:
1. The page is no longer the placeholder Hello World and contains the DevShield scanner.
2. `/health` is valid JSON with honest service flags.
3. The JavaScript and CSS assets are served.

On merge of the proposed check workflow it also runs daily (UTC 07:17), without production deployment rights or private API tokens. The workflow is **not activated just because the PR exists**.

## What this does not test

This is not an antivirus effectiveness or browser-interaction test. A passing site smoke does not imply a working paid cloud scan API, an installed antivirus daemon, or a functioning scan-credit payment pipeline. Interactive manual verification should paste a harmless test string into the browser-local scanner, click Run local preview, examine displayed findings, export a JSON report and reset. Never paste actual secrets. Browser-side scan data is intended to remain on device.

If the public check fails: compare Cloudflare Workers & Pages production builds and the deployed Worker version/route with `main`. Inspect the first failing log entry. A passing GitHub unit test or preview does not establish a passing production deployment. Avoid automatically rolling back or promoting an unreviewed Worker.
