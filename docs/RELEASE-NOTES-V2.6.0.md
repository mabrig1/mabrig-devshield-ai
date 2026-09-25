# MABRIG DevShield AI v2.6.0 — Trust-Boundary Hardening

DevShield v2.6 extends the September 2026 Emerging Threat Shield with structured MCP configuration auditing and newer GitHub/npm hardening signals.

## Added

- Structured MCP JSON auditing for common `mcpServers` / MCP config files.
- Critical detection for secret-looking literals embedded in MCP server `env` blocks.
- Medium supply-chain detection for MCP servers launched with unpinned `npx` package references.
- Broader remote MCP URL coverage, including the common `url` field inside structured MCP configs.
- High-severity detection for GitHub Actions `allow-unsafe-pr-checkout: true`.
- Critical contextual detection when `pull_request_target` checks out a contributor-controlled fork repository.
- Medium supply-chain signal when an npm publishing workflow explicitly disables provenance.

## Research basis

- GitHub warns that `pull_request_target` runs with elevated trust and that checking out untrusted PR code can expose repository secrets and token authority.
- GitHub's default public-repository policy for `pull_request_target` is scheduled for enforcement on November 2, 2026.
- npm recommends trusted publishing with OIDC and recommends keeping provenance enabled.
- OWASP MCP guidance highlights tool poisoning, excessive privileges, secret exposure, and untrusted MCP server supply-chain risk.
- MCP 2026-07-28 strengthened authorization and deprecated legacy patterns as the protocol moves toward stronger production trust boundaries.

## Safety

These findings identify risky configuration or trust-boundary patterns. They do not claim that an exploit, prompt injection, or credential theft has occurred.
