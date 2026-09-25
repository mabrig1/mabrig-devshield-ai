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
