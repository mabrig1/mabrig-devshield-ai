# Cloudflare Workers Builds: isolated build and deployment preparation

**State: review-stage only.** This directory is a minimal, nonproduction Worker candidate. It proves the repository can bundle a Worker without source checkout execution or external credentials. It does **not** replace the existing GitHub Action, provide live DevShield scan APIs, activate OpenRouter/Resend, or migrate D1.

## Why Cloudflare can fail while GitHub CI passes

The GitHub Action scanner is a Node.js CLI, not a Cloudflare Worker entrypoint. This repository's previous Cloudflare Worker files are inside `commercial-api/` and `runtime-waf/`, which have different roles. The repository root does not have an active Wrangler configuration. Cloudflare Workers Builds uses the configured **root directory**, **build command**, **deploy command**, and **preview command**; running `npx wrangler deploy` from an unconfigured root can fail or trigger automatic configuration.

Cloudflare also requires the Wrangler `name` to match the existing Worker name when connecting to that Worker. This candidate uses `name: mabrig-devshield-ai` for that reason. A different project name should be used only in a **separately created staging Worker** with a matching config.

**The exact first blocker from the dashboard failure is unverified.** The GitHub check only reports failure and the Cloudflare build URL; the Cloudflare build log is needed to distinguish incorrect root/command settings from missing Git permissions, account token privileges, Wrangler version, runtime imports, or another issue.

## Verify without touching production

From a working copy of this PR branch:

```bash
cd cloudflare-deploy
npm install --no-audit --no-fund
npm test
npx wrangler deploy --dry-run --outdir .dry-run
```

The dedicated GitHub Action `DevShield Worker Build Validation` performs these checks and publishes no Worker. No API tokens or Resend/OpenRouter keys are needed.

**Do not merge this directory and immediately point the existing production Worker at it.** Doing so would deploy a health/status stub in place of any existing production logic. First review the active Worker version and routes, export existing production settings, and run an isolated preview or staging deployment.

## Check the dashboard failure

Open **Cloudflare → Workers & Pages → mabrig-devshield-ai → Deployments → View build history**. Select the failed build and inspect the first red/error step.

Then inspect **Settings → Builds** (not the separate Settings → Variables and secrets page):

- Git repository: `mabrig1/mabrig-devshield-ai`
- Connected Worker: `mabrig-devshield-ai`
- Root directory for this **isolated candidate**: `cloudflare-deploy`
- Build command: `npm run check`
- Deploy command for an approved production promotion: `npx wrangler deploy`
- Preview command (if previews enabled): `npx wrangler preview`
- Production branch: the intended release branch, not an unreviewed PR

**Do not change the existing production Worker build/deploy settings before reviewing the active deployment**. A `deploy` command can promote this stub to production. For this review stage, rely on GitHub's dry-run workflow.

## API/email environment names

These are optional future runtime settings, **not prerequisites for the candidate's build**. Keep secrets in Cloudflare's encrypted secret type; do not add keys to GitHub or a Wrangler file.

```dotenv
# Server-side secret (real value added in dashboard, not in source)
OPENROUTER_API_KEY=sk-or-v1-REPLACE_WITH_REAL_KEY
# Optional text settings:
OPENROUTER_BASE_URL=https://openrouter.ai/api/v1
OPENROUTER_MODEL=openrouter/free

# Server-side secret (real value added in dashboard, not in source)
RESEND_API_KEY=re_REPLACE_WITH_REAL_KEY
# Must use a verified sending domain in Resend:
RESEND_FROM_EMAIL=DevShield AI <security@mabrigkorie.org>
# Replies may go to your Gmail inbox:
RESEND_REPLY_TO=victoryonline1@gmail.com
```

Merely defining these variables does not enable email, AI features, or paid scans. The Worker must implement those functions. The current candidate does not access or expose the variables.

## Deployment acceptance checklist

- Confirm failure details from Cloudflare build logs and fix the verified cause.
- Confirm root `cloudflare-deploy` and a matching Worker name in a **preview/staging** Cloudflare setup.
- Dry-run passes, entrypoint is valid, and test suite passes.
- Verify preview has `GET /health` returning JSON, unknown routes 404, API routes 503, and disallowed methods 405.
- Audit the current production routes, custom domains, D1 bindings, secret names and rollback version.
- Review the intended actual production worker implementation (commercial API is separate, requires operator-created D1). Never treat this status stub as production API.
- Only after approval, enable production deployment deliberately.

Sources:
- https://developers.cloudflare.com/workers/ci-cd/builds/configuration/
- https://developers.cloudflare.com/workers/ci-cd/builds/
