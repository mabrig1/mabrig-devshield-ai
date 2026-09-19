# Runtime Guard v2.4

Runtime Guard adds an opt-in runtime-defense probe to MABRIG DevShield AI.

It sends a very small set of controlled, non-destructive attack-shaped markers to an explicitly configured preview or staging URL and records whether the observed HTTP layer blocks them. A passed-through marker is a WAF coverage signal; it is **not** proof that the application is exploitable.

## Safety defaults

- HTTPS required by default.
- Local, loopback, link-local, private and other non-routable targets are rejected by default.
- Embedded URL credentials are rejected.
- Query strings, fragments and credentials are removed from the target written to reports.
- Redirects are not automatically followed.
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

The next planned layer is an ephemeral Coraza + OWASP CRS policy-simulation adapter, followed by provider-backed temporary edge protection.
