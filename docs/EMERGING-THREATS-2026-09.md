# Emerging Threat Research — September 2026

This note records the public security signals used to design DevShield v2.5. It is not a vulnerability feed and does not claim that every repository using these patterns is exploitable.

## GitHub Actions supply-chain pressure

GitHub reported in July 2026 that recent supply-chain attacks used compromised GitHub credentials to push malicious Actions workflows designed to steal CI/CD credentials and continue attacks. GitHub now holds some potentially malicious public-repository workflows for authenticated approval.

GitHub's secure-use guidance continues to recommend pinning third-party Actions to a full-length commit SHA because tags and branches are mutable. GitHub also added same-repository `$/` syntax in July 2026 so internal Actions can follow the exact calling commit without defeating pinning.

Sources:
- https://github.blog/changelog/2026-07-28-github-actions-holds-potentially-malicious-workflows-for-approval/
- https://docs.github.com/en/code-security/tutorials/secure-your-organization/protect-against-threats
- https://github.blog/changelog/2026-07-30-reference-same-repository-actions-with-self-repository-syntax/

DevShield response:
- Promote non-SHA third-party `uses:` references to balanced-policy medium findings.
- Exclude local `./`, self-repository `$/`, Docker actions, and full commit SHAs.
- Detect custom JavaScript Actions that still declare `runs.using: node20`, which GitHub retired on September 23, 2026.
- Detect `pull_request_target` workflows that explicitly override the secure cache default with `cache-mode: write` or `write-only`.

Additional source:
- https://github.blog/changelog/2026-09-23-node-20-is-no-longer-available-in-github-actions/
- https://github.blog/changelog/2026-09-10-control-github-actions-cache-access-with-cache-mode/

## npm publishing and long-lived credentials

npm trusted publishing uses OIDC so CI workflows can publish without long-lived write tokens. npm recommends trusted publishing over traditional long-lived tokens. In September 2026 npm also expanded multiple trusted-publisher configurations and continues to recommend staged publishing when human approval is desired.

Sources:
- https://docs.npmjs.com/trusted-publishers/
- https://github.blog/changelog/2026-09-03-multiple-trusted-publishing-configurations-for-npm/
- https://github.blog/changelog/2026-07-08-npm-install-time-security-and-gat-bypass2fa-deprecation/

DevShield response:
- Detect workflows that combine `npm publish` with a repository-secret `NODE_AUTH_TOKEN`.
- Report this as a migration/credential-lifecycle risk, not proof of token compromise.

## AI agents, MCP, prompt injection, and excessive authority

OpenAI's current MCP guidance warns that remote MCP servers can receive sensitive context, request data, and take actions. It recommends trusted servers, logging/review, approvals for sensitive actions, and narrow `allowed_tools` scopes. OpenAI also notes that malicious MCP servers can place hidden prompt-injection instructions in tool definitions or outputs.

Sources:
- https://developers.openai.com/api/docs/guides/tools-connectors-mcp
- https://developers.openai.com/api/docs/guides/agent-builder-safety
- https://openai.com/index/designing-agents-to-resist-prompt-injection/

DevShield response:
- Detect plain-HTTP remote MCP URLs.
- In strict policy, detect globally disabled MCP approval and wildcard tool surfaces.
- Do not claim static configuration proves prompt-injection exploitability.

## Modern developer credentials

GitLab documents standard token prefixes including `glpat-`, `gldt-`, `glrt-`, `glcbt-`, and related token families. Supabase now documents scoped personal access tokens and recommends scoping tokens especially for AI agents, automation, and CI.

Sources:
- https://docs.gitlab.com/security/tokens/
- https://supabase.com/docs/guides/platform/personal-access-tokens

DevShield response:
- Detect/redact GitLab token families.
- Detect/redact Supabase `sbp_` personal access tokens.

## Boundary

These checks are intentionally deterministic and conservative. DevShield v2.5 does not execute repository code, contact configured MCP servers, rotate credentials, publish packages, or automatically change source files.
