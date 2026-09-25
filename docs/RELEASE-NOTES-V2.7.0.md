# MABRIG DevShield AI v2.7.0 — MCP Authorization & Protocol Guard

DevShield v2.7 updates MCP configuration review for the 2026-07-28 protocol generation and current agent-security guidance.

## Added

- HTTPS enforcement signals for remote MCP OAuth issuer, authorization, token, registration, and JWKS endpoints.
- Critical hard-coded OAuth client-secret detection.
- Critical literal bearer Authorization-header detection.
- Deprecated Dynamic Client Registration configuration detection.
- Deprecated HTTP+SSE MCP transport detection.
- Strict-mode review of wildcard/admin/full-access OAuth scopes.
- Regression coverage for safe modern and unsafe legacy MCP authorization configurations.

## Research basis

- MCP 2026-07-28 requires authorization-server issuer validation per RFC 9207, binds client credentials to issuers, and formally deprecates Dynamic Client Registration in favor of Client ID Metadata Documents.
- MCP 2026-07-28 also deprecates legacy HTTP+SSE transport with a migration window.
- OWASP MCP guidance highlights excessive OAuth permissions, exposed credentials, malicious/changed MCP servers, and supply-chain trust as major risks.

## Safety boundary

Static scanning cannot prove whether an application correctly validates the OAuth `iss` parameter at runtime. DevShield therefore reports configuration evidence—transport, embedded credentials, deprecated registration/transport choices, and scope breadth—without claiming an authorization-server mix-up vulnerability exists.
