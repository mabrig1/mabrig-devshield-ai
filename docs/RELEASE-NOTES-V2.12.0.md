# MABRIG DevShield AI v2.12.0 — Bounded Runtime Abuse Verification

DevShield v2.12 extends Runtime Guard with a deliberately small preview/staging verification step for rate-limit, challenge, and blocking controls.

## What it does

When explicitly enabled, Runtime Guard performs a baseline request followed by **2 to 10 sequential GET requests** to a same-origin path. It records observable defense signals such as:

- HTTP 429
- HTTP 403
- `Retry-After`
- exhausted `RateLimit-Remaining` / `X-RateLimit-Remaining` style headers
- Cloudflare `cf-mitigated: challenge`

The probe can target routes such as `/api/login` without sending login credentials or request bodies.

## What it does not do

- no password guessing
- no account enumeration
- no credential stuffing
- no POST/PUT/PATCH/DELETE requests
- no concurrent flood
- no sustained load test
- no bypass attempts against challenges or rate limits

## Guardrails

- disabled by default
- maximum 10 requests
- sequential requests only
- minimum 100 ms delay between requests
- same-origin path only
- query strings and fragments rejected for the configured abuse path
- HTTPS required by default
- DNS pinning and private-address protections remain active
- redirects remain disabled

## Interpretation

`rate-limit-signal`, `challenge-signal`, or `block-signal` means the bounded probe observed a relevant defense response.

`no-abuse-control-signal` does **not** prove the route is vulnerable or unprotected. Provider policy may depend on longer windows, identity context, geographic signals, reputation, or thresholds outside this deliberately conservative probe.

Use `runtime-abuse-enforce: true` only when your preview policy is intentionally configured to respond within the bounded probe window.
