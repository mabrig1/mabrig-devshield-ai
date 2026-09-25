# MABRIG DevShield AI v2.5.0 — Emerging Threat Shield

DevShield v2.5 updates deterministic security coverage for the September 2026 developer threat landscape without granting the scanner new mutation or execution authority.

## Added

- Balanced-policy detection for non-SHA third-party GitHub Action and reusable-workflow references.
- Contextual signal for `npm publish` workflows that rely on a long-lived repository-secret `NODE_AUTH_TOKEN`.
- GitLab token-family and Supabase personal-access-token detection/redaction.
- High-severity detection for remote MCP server URLs using plain HTTP.
- Strict-mode checks for globally disabled MCP approvals and wildcard tool surfaces.
- Regression fixtures covering the new threat rules.
- Research-basis document linking the relevant GitHub, npm, OpenAI, GitLab, and Supabase guidance.

## Safety boundaries

- MCP approval/wildcard checks are strict-only because intentionally trusted read-only configurations can legitimately reduce approval friction.
- The npm publishing rule is a migration signal toward OIDC trusted publishing or staged approval; it does not claim a credential is compromised.
- Static MCP configuration checks do not claim that a prompt injection has occurred or will succeed.
- DevShield still does not execute repository code or automatically mutate source files.

## Validation target

Release only after both **DevShield CI** and **Production Certification** succeed on this branch.
