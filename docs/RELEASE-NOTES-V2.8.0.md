# MABRIG DevShield AI v2.8.0 — Runtime DNS Pinning

DevShield v2.8 hardens Runtime Guard against DNS rebinding and validation/request TOCTOU risk.

## Added

- Per-request DNS resolution immediately before Runtime Guard network access.
- Private/non-routable validation on every resolved address.
- DNS pinning through Node HTTP(S) custom lookup.
- Original hostname preservation for Host/TLS SNI and certificate checks.
- Fresh connections with agent reuse disabled.
- Remote socket-address verification.
- Regression tests that simulate a public hostname rebinding to 127.0.0.1 after initial validation.

## Security model

The previous Runtime Guard validated DNS and then used fetch, which could perform a second independent DNS lookup. v2.8 removes that gap for the normal Action/CLI transport by forcing the socket to the already validated address.

Redirects remain disabled, private targets remain opt-in, and reports do not expose the resolved IP.

Custom injected fetch functions are retained for tests/integrators; those executions are explicitly marked as not DNS-pinned.

## Research basis

Node HTTP(S) supports a custom `lookup` function, allowing the client to preserve the hostname while controlling the resolved socket address:
- https://nodejs.org/download/release/latest-v24.x/docs/api/http.html
- https://nodejs.org/download/release/latest-v24.x/docs/api/https.html
