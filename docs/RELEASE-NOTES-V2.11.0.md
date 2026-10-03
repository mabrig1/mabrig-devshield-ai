# MABRIG DevShield AI v2.11.0 — Edge Abuse Shield

DevShield v2.11 extends the v2.10 Web Attack Shield with abuse-defense checks inspired by real-world origin-flooding and credential/form abuse patterns.

## New deterministic coverage

- high-value POST routes (login/auth/register/password reset/admin/payment/contact/form paths) with no observable in-file rate-limit or bot-challenge signal
- rate-limit logic that uses `X-Forwarded-For` without an observable trusted-proxy boundary
- process-memory counters used for rate limiting on high-value routes, which can fragment or reset across serverless/cluster instances
- client-side references to Turnstile/reCAPTCHA/hCaptcha secret/private/token environment variables

## Deployment guidance

The scanner does **not** infer that Cloudflare, Vercel Firewall, a CDN, API gateway, or another WAF is absent merely because policy is not present in the repository. Missing local signals are evidence to verify deployment controls.

A strong deployment keeps multiple layers:

1. edge/WAF filtering for known attack and bot patterns
2. route-specific rate limits for login, reset, registration, checkout, payment and form endpoints
3. challenge controls such as Turnstile/reCAPTCHA/hCaptcha where appropriate
4. trusted proxy/IP normalization before using client IP as a limiter key
5. shared atomic rate-limit state for horizontally scaled/serverless workloads
6. application-side authorization and abuse limits even when an edge provider is enabled

## Safety semantics

Findings describe observable code/configuration evidence. They do not claim that an attack succeeded, that a deployment lacks external controls, or that a particular provider must be used.
