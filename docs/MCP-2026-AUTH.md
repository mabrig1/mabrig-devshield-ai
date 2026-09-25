# MCP 2026 Authorization Security Notes

DevShield v2.7 is based on current public guidance as of September 25, 2026.

## MCP 2026-07-28

The MCP 2026-07-28 release hardens authorization by requiring clients to validate the authorization response issuer (`iss`) under RFC 9207, binding client credentials to the issuer that created them, and moving away from Dynamic Client Registration toward Client ID Metadata Documents (CIMD). The release also deprecates legacy HTTP+SSE transport.

Sources:
- https://blog.modelcontextprotocol.io/posts/2026-07-28/
- https://ts.sdk.modelcontextprotocol.io/v2/migration/support-2026-07-28

## OWASP MCP guidance

OWASP identifies tool poisoning, rug-pull changes, confused-deputy behavior, excessive OAuth permissions, data exfiltration, compromised MCP packages, and local-server host access as important MCP threat classes.

Source:
- https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html

## DevShield scope

v2.7 detects configuration evidence that can be reviewed safely without connecting to an MCP server. Runtime issuer validation, live tool-definition drift, and DNS-rebinding resistance remain separate runtime-verification concerns.
