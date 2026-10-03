# Runtime Guard v2.8

Runtime Guard adds an opt-in runtime-defense probe to MABRIG DevShield AI.

It sends a very small set of controlled, non-destructive attack-shaped markers to an explicitly configured preview or staging URL and records whether the observed HTTP layer blocks them. A passed-through marker is a WAF coverage signal; it is **not** proof that the application is exploitable.

## Safety defaults

- HTTPS required by default.
- Local, loopback, link-local, private and other non-routable targets are rejected by default.
- Embedded URL credentials are rejected.
- Query strings, fragments and credentials are removed from the target written to reports.
- Redirects are not automatically followed.
- DNS is resolved and validated immediately before each normal runtime request.
- The request socket is pinned to the validated address with a custom Node HTTP(S) lookup while retaining the original hostname for Host/TLS SNI validation.
- HTTP connection reuse is disabled for probes, so every request gets a fresh DNS validation + pinned connection.
- The connected socket address is checked against the validated address before the response is accepted.
- Active probes are limited to XSS-shaped, SQLi-shaped and traversal-shaped markers.
- No command execution, destructive request, credential attack or high-volume traffic is generated.
- Private targets require `runtime-allow-private: true` and should only be used on a trusted self-hosted runner.

## GitHub Action example

```yaml
permissions:
  contents: read

steps:
  - uses: actions/checkout@v7
    with:
      fetch-depth: 0

  - name: DevShield code + runtime review
    uses: mabrig1/mabrig-devshield-ai@main
    with:
      fail-on: critical
      runtime-guard: probe
      runtime-target: ${{ steps.preview.outputs.url }}
      runtime-enforce: false
```

For a Vercel preview protected by Deployment Protection, store the bypass token as a GitHub secret:

```yaml
      runtime-vercel-bypass-token: ${{ secrets.VERCEL_AUTOMATION_BYPASS_SECRET }}
```

Set `runtime-enforce: true` only after you have observed your application's normal Runtime Guard behavior. The default minimum block rate is 100%.

## Outputs

Runtime Guard writes:

- `.devshield/runtime-guard.json`
- `.devshield/runtime-guard.sarif`
- the GitHub job summary
- composite Action outputs for state, probe counts, block rate, and report paths

Runtime Guard v2.8 closes the DNS validation/request gap for the default Action/CLI transport. Custom injected fetch functions are still supported for testing and advanced integrations, but are reported as custom-fetch mode rather than DNS-pinned.

The next planned layer is an ephemeral Coraza + OWASP CRS policy-simulation adapter, followed by provider-backed temporary edge protection.


## v2.12 bounded abuse-control verification

Runtime Guard can optionally verify whether a preview/staging route emits a rate-limit, challenge, or blocking signal within a deliberately small request window.

```yaml
runtime-guard: probe
runtime-target: https://preview.example.com
runtime-abuse-probe: true
runtime-abuse-path: /api/login
runtime-abuse-request-count: 6
runtime-abuse-delay-ms: 250
runtime-abuse-enforce: false
```

Safety boundaries are fixed: the configured path must stay on the runtime target origin; query strings and fragments are rejected; the request count is clamped to 2-10; delays are clamped to 100-2000 ms; requests are sequential GETs with no body or credential attempt. This is **not** a load test.

Recognized evidence includes HTTP 429/403, `Retry-After`, exhausted common rate-limit remaining headers, and Cloudflare challenge metadata. `no-abuse-control-signal` means the bounded sequence observed none of those signals; it does not establish that the route is vulnerable or that no external WAF/rate-limit policy exists.

Set `runtime-abuse-enforce: true` only when the preview environment is deliberately configured to respond within this bounded sequence. Enforcement treats `rate-limit-signal`, `challenge-signal`, and `block-signal` as passing states.
