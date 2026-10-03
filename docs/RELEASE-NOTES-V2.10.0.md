# DevShield v2.10.0 — Web Attack Shield

Released for review on 2026-10-03.

## What changed

DevShield now carries deterministic checks for current Next.js web-application advisories so a repository can be flagged even when a generic advisory feed, Dependabot mirror, or package scanner has not caught up yet.

### Added coverage

- **GHSA-vcvr-r3jv-pc5j / CVE-2026-94545** — critical remote code execution in the Node.js next/og ImageResponse path for affected Next.js 16.2.x/16.3.x releases. DevShield checks the vendor-affected version range and also detects request-controlled SVG generation patterns.
- **GHSA-2xp9-vwfh-vxw4** — critical unauthenticated RCE in Next.js AVIF image optimization. DevShield checks the affected 15.x and 16.x ranges.
- **GHSA-p9j2-gv94-2wf4 and July 2026 Next.js security cluster** — flags affected releases and dynamic external rewrite/redirect host patterns that can create SSRF/open-redirect exposure.

## Guardrails

- Exact semantic versions are matched deterministically. Non-exact Next.js ranges are only surfaced under strict policy for manual review rather than guessed as vulnerable.
- Source-pattern findings describe reachability signals, not proof of exploitation.
- The scanner recommends framework upgrades as the primary fix; it does not treat WAF rules as a complete substitute for patching.

## Current safe floor used by this release

For the latest next/og advisory covered here, Next.js **16.3.6+** is the patched 16.x floor. Applications on older supported lines should use the patched release named by the upstream advisory for that line.
