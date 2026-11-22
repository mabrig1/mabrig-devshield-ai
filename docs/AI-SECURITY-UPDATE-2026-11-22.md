# AI security update: practical response

Reviewed on 22 November 2026 after a supplied video about Chrome security fixes,
reverse engineering, and AI-assisted development.

## Decision

Keep the existing application architecture and strengthen its trust boundaries.
Browser-delivered code must be treated as inspectable. Keep privileged credentials,
payment verification, entitlement decisions, and authorization on the server.
Moving a screen into an iframe does not provide authentication or protect an API.
Offline analysis and public UI code can remain local when that serves the product.

## What the evidence supports

Google describes AI-assisted source-code analysis, restricted execution environments,
reproduction of findings, conventional security testing, and developer review.
It does not establish the video's claim that decompilation caused all the Chrome
fixes, or that HTTP, JavaScript, Python, native apps, or software engineers are obsolete.
The television surveillance anecdote is unverified: the video supplies no model,
firmware, reproducible analysis, or traffic evidence. Do not use it as a finding.

The appropriate lesson is faster verification and patching, not a wholesale rewrite.
This review does not establish a breach of any MABRIG application.

## Implemented in this review branch

The API & Agent Trust Shield previously missed public references such as
`NEXT_PUBLIC_OPENROUTER_API_KEY` because its existing credential-name pattern
focused on words such as SECRET and ACCESS_TOKEN.

Extend the existing `api-client-secret-exposure` rule to exact names for
OpenRouter, OpenAI, Anthropic, Resend API keys and Supabase service-role keys
under NEXT_PUBLIC, VITE, REACT_APP and PUBLIC prefixes, or window/globalThis.
Reports retain file/line evidence and never include credential values.
Intentionally public Supabase anon/publishable and payment publishable keys are
not added to this privileged-key list. This is a static review signal, not proof
that a real key exists or has reached a deployed bundle.

Tests cover all 20 public-prefix/provider combinations, browser globals,
line evidence, value-free findings, benign public identifiers, server-only
references, repository scanning and SARIF output.

## Operational follow-through

1. Device owner: update Chrome through the official app store or desktop updater;
   relaunch when requested. Device patch status has not been inspected here.
2. Review and merge this focused detection change before promoting a release.
   Existing consumers pinned to older commits will not gain it automatically.
3. Run the API trust pass on DDEI, BuildRx and AI University checkouts, beginning
   with provider credentials and server-side payment/access enforcement.
   These application audits remain pending; this branch does not patch them.
4. For each signal, establish reachability and reproduce with synthetic data.
   Rotate credentials only if actual exposure is confirmed, then rebuild affected
   browser bundles and check caches. Never publish real credentials in findings.
5. Teach AI-assisted construction together with testing, access control and
   maintenance. The video provides no basis for a one-day guarantee of secure,
   production-ready replacements for arbitrary applications.

The detector remains heuristic: arbitrary aliases, computed property access,
custom build prefixes, generated bundles and files outside the selected scan
scope need separate inspection. There is no new live scanner, browser update,
deployment, scheduled job or automatic remediation in this change.

Rollback: revert the focused detection commit. No data migration is needed.

## Primary references

- Google Chrome Security Team, AI-assisted discovery and patching:
  https://blog.google/security/chrome-stronger-with-every-update/
- Chrome release announcements (use the latest applicable stable update):
  https://chromereleases.googleblog.com/
- Next.js public environment-variable behavior:
  https://nextjs.org/docs/app/guides/environment-variables
- Vite environment-variable exposure:
  https://vite.dev/guide/env-and-mode
- Official Chrome update instructions:
  https://support.google.com/chrome/answer/95414
