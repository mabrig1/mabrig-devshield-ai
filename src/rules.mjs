// Built-in deterministic DevShield rules.
// Keep this module dependency-free so the Action remains transparent and fast.

function rule(id, severity, category, re, message, cwe, remediation, extra = {}) {
  return { id, severity, category, re, message, cwe, remediation, ...extra };
}

export const REDACTORS = [
  [/\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,})\b/g, '[REDACTED_GITHUB_TOKEN]'],
  [/\b(?:glpat|gldt|glrt|glrtr|glcbt|gloas|glptt|glft|glimt|glagent|glwt|glsoat|glffct)-[A-Za-z0-9_-]{12,}\b/g, '[REDACTED_GITLAB_TOKEN]'],
  [/\bsbp_[A-Za-z0-9_-]{16,}\b/g, '[REDACTED_SUPABASE_TOKEN]'],
  [/\bsk-(?:proj-|or-v1-)?[A-Za-z0-9_-]{20,}\b/g, '[REDACTED_AI_KEY]'],
  [/\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g, '[REDACTED_AWS_KEY]'],
  [/\b(?:sk_live|rk_live)_[A-Za-z0-9]{16,}\b/g, '[REDACTED_STRIPE_KEY]'],
  [/\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g, '[REDACTED_SLACK_TOKEN]'],
  [/\bAIza[0-9A-Za-z_-]{35}\b/g, '[REDACTED_GOOGLE_API_KEY]'],
  [/\bSG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\b/g, '[REDACTED_SENDGRID_KEY]'],
  [/(?:https?|postgres(?:ql)?|mysql|mongodb(?:\+srv)?):\/\/[^/\s:@]+:[^/\s@]+@/gi, '[REDACTED_CREDENTIAL_URL]@'],
  [/(\b(?:api[_-]?key|secret|password|passwd|access[_-]?token|auth[_-]?token)\b\s*[:=]\s*["']?)[^\s"']{8,}/gi, '$1[REDACTED_GENERIC_SECRET]'],
  [/((?:_authToken|password)\s*=\s*)[^\s]+/gi, '$1[REDACTED_REGISTRY_SECRET]'],
  [/-----BEGIN[\s\S]{0,3000}?PRIVATE KEY-----[\s\S]{0,6000}?-----END[\s\S]{0,80}?PRIVATE KEY-----/g, '[REDACTED_PRIVATE_KEY]']
];

export const rules = [
  // Secrets
  rule('private-key', 'critical', 'secrets', /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/, 'Private key material appears to be committed.', 'CWE-321', 'Remove the key, rotate it, and store credentials in a secret manager.'),
  rule('github-token', 'critical', 'secrets', /\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,})\b/, 'Possible GitHub token detected.', 'CWE-798', 'Revoke/rotate the token and move it to GitHub Actions secrets.'),
  rule('gitlab-token', 'critical', 'secrets', /\b(?:glpat|gldt|glrt|glrtr|glcbt|gloas|glptt|glft|glimt|glagent|glwt|glsoat|glffct)-[A-Za-z0-9_-]{12,}\b/, 'Possible GitLab access, runner, deploy, job, or service token detected.', 'CWE-798', 'Revoke/rotate the token and replace it with a narrowly scoped, short-lived credential where possible.'),
  rule('supabase-pat', 'critical', 'secrets', /\bsbp_[A-Za-z0-9_-]{16,}\b/, 'Possible Supabase personal access token detected.', 'CWE-798', 'Revoke/rotate the token and prefer a scoped token limited to only the required project permissions.'),
  rule('openai-key', 'critical', 'secrets', /\bsk-(?:proj-|or-v1-)?[A-Za-z0-9_-]{20,}\b/, 'Possible AI provider API key detected.', 'CWE-798', 'Rotate the key and load it from a protected secret store.'),
  rule('aws-access-key', 'critical', 'secrets', /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/, 'Possible AWS access key detected.', 'CWE-798', 'Deactivate the key and use short-lived credentials or workload identity.'),
  rule('stripe-live-key', 'critical', 'secrets', /\b(?:sk_live|rk_live)_[A-Za-z0-9]{16,}\b/, 'Possible Stripe live secret detected.', 'CWE-798', 'Rotate the key immediately and store it outside source control.'),
  rule('slack-token', 'critical', 'secrets', /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/, 'Possible Slack token detected.', 'CWE-798', 'Revoke and rotate the token.'),
  rule('google-api-key', 'critical', 'secrets', /\bAIza[0-9A-Za-z_-]{35}\b/, 'Possible Google API key detected.', 'CWE-798', 'Rotate the key and restrict it by API, referrer, IP, or workload.'),
  rule('sendgrid-key', 'critical', 'secrets', /\bSG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\b/, 'Possible SendGrid API key detected.', 'CWE-798', 'Revoke and rotate the key.'),
  rule('credential-url', 'critical', 'secrets', /(?:https?|postgres(?:ql)?|mysql|mongodb(?:\+srv)?):\/\/[^/\s:@]+:[^/\s@]+@/i, 'Credentials appear embedded in a connection URL.', 'CWE-798', 'Use environment variables or a secret manager instead of embedding credentials.'),
  rule('generic-secret-assignment', 'high', 'secrets', /\b(?:api[_-]?key|secret|password|passwd|access[_-]?token|auth[_-]?token)\b\s*[:=]\s*["'][^"']{16,}["']/i, 'A secret-looking value is assigned directly in source.', 'CWE-798', 'Move the value to a secret manager and rotate it if real.', { strictOnly: true }),

  // Code injection / unsafe execution
  rule('dangerous-eval', 'high', 'injection', /\beval\s*\(/, 'Dynamic eval() can enable code injection.', 'CWE-95', 'Avoid eval; parse or dispatch using explicit allowlisted operations.'),
  rule('shell-exec', 'medium', 'injection', /\b(?:exec|execSync)\s*\(/, 'Shell execution found. Confirm arguments cannot contain untrusted input.', 'CWE-78', 'Prefer execFile/spawn with argument arrays and validate untrusted values.'),
  rule('shell-interpolation', 'high', 'injection', /\b(?:exec|execSync)\s*\(\s*`[^`]*\$\{[^}]+\}/, 'Shell command is built with string interpolation.', 'CWE-78', 'Use execFile/spawn with an argument array instead of interpolated shell commands.'),
  rule('python-shell-true', 'high', 'injection', /subprocess\.(?:run|Popen|call|check_output|check_call)\([^)]*shell\s*=\s*True/, 'Python subprocess executes through a shell.', 'CWE-78', 'Use shell=False and pass arguments as a list.'),
  rule('python-os-system', 'high', 'injection', /\bos\.system\s*\(/, 'os.system() executes through a shell.', 'CWE-78', 'Use subprocess with shell=False and validated arguments.'),
  rule('unsafe-pickle', 'high', 'deserialization', /\bpickle\.(?:load|loads)\s*\(/, 'Python pickle deserialization can execute attacker-controlled code.', 'CWE-502', 'Use a safe serialization format for untrusted data.'),
  rule('unsafe-yaml-load', 'high', 'deserialization', /\byaml\.load\s*\((?![^\n)]*(?:Loader\s*=|SafeLoader))/, 'yaml.load() may deserialize unsafe objects.', 'CWE-502', 'Use yaml.safe_load() for untrusted YAML.'),
  rule('sql-string-build', 'high', 'injection', /(?:\bSELECT\b[^\n]{0,60}\bFROM\b|\bINSERT\s+INTO\b|\bUPDATE\s+[A-Za-z_][\w.]*\s+SET\b|\bDELETE\s+FROM\b)[^\n]{0,100}(?:\$\{|\+\s*(?:req|request|params)\.|%\s*\()/i, 'Possible SQL query construction with request data.', 'CWE-89', 'Use parameterized queries or prepared statements.'),
  rule('dangerous-innerhtml', 'medium', 'xss', /\b(?:innerHTML|outerHTML)\s*=/, 'Direct HTML assignment can enable DOM XSS when data is untrusted.', 'CWE-79', 'Use safe DOM APIs or sanitize trusted HTML explicitly.', { strictOnly: true }),
  rule('react-dangerous-html', 'medium', 'xss', /\bdangerouslySetInnerHTML\s*=/, 'React dangerouslySetInnerHTML bypasses normal escaping.', 'CWE-79', 'Avoid it or sanitize trusted HTML with a well-reviewed sanitizer.'),

  // Transport / runtime configuration
  rule('disabled-tls', 'high', 'configuration', /rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*["']?0/, 'TLS certificate verification appears disabled.', 'CWE-295', 'Enable certificate verification and install the correct trust chain.'),
  rule('python-verify-false', 'high', 'configuration', /\brequests\.(?:get|post|put|patch|delete|request)\([^)]*verify\s*=\s*False/, 'Python HTTP request disables TLS verification.', 'CWE-295', 'Remove verify=False and trust the correct CA certificate.'),
  rule('wildcard-cors', 'medium', 'configuration', /Access-Control-Allow-Origin["'\s,:=]+\*|origin\s*:\s*["']\*["']/, 'Wildcard CORS detected.', 'CWE-942', 'Restrict allowed origins to trusted applications.'),
  rule('debug-mode', 'low', 'configuration', /\bDEBUG\s*=\s*(?:true|1)\b|debug\s*:\s*true/i, 'Debug mode appears enabled.', 'CWE-489', 'Disable debug mode in production.', { strictOnly: true }),
  rule('jwt-verification-disabled', 'critical', 'authentication', /verify_signature["']?\s*[:=]\s*False|verify\s*=\s*False[^)]*jwt/i, 'JWT signature verification appears disabled.', 'CWE-347', 'Always verify JWT signatures and expected issuer/audience.'),
  rule('weak-md5-security', 'medium', 'cryptography', /\b(?:md5|createHash\(["']md5["']\)|hashlib\.md5)\b/i, 'MD5 is not suitable for security-sensitive hashing.', 'CWE-327', 'Use a modern cryptographic hash; for passwords use Argon2, scrypt, or bcrypt.', { strictOnly: true }),
  rule('weak-sha1-security', 'low', 'cryptography', /\b(?:sha1|createHash\(["']sha1["']\)|hashlib\.sha1)\b/i, 'SHA-1 is deprecated for security-sensitive hashing.', 'CWE-327', 'Use SHA-256+ for integrity or a password-hashing function for passwords.', { strictOnly: true }),

  // Supply chain / GitHub Actions
  rule('unpinned-action-moving', 'medium', 'supply-chain', /uses:\s*[^\s]+@(?:main|master|latest)\b/i, 'GitHub Action is pinned to a moving branch/tag.', 'CWE-829', 'Pin to a trusted full commit SHA or an immutable release reference.', { file: /\.ya?ml$/i }),
  rule('unpinned-action-tag', 'medium', 'supply-chain', /uses:\s*(?!\.\/)(?!\$\/)(?!docker:\/\/)[^\s]+@(?![a-f0-9]{40,64}\b)[^\s#]+/i, 'GitHub Action or reusable workflow reference is mutable.', 'CWE-829', 'Pin third-party Actions and reusable workflows to a reviewed full-length commit SHA.', { file: /\.github\/workflows\/.*\.ya?ml$/i }),
  rule('workflow-write-all', 'high', 'ci-security', /^\s*permissions\s*:\s*write-all\s*$/i, 'Workflow grants write-all token permissions.', 'CWE-250', 'Grant only the minimum required GITHUB_TOKEN permissions.', { file: /\.github\/workflows\/.*\.ya?ml$/i }),
  rule('workflow-pr-target', 'high', 'ci-security', /^\s*pull_request_target\s*:/i, 'pull_request_target runs with base-repository privileges and needs careful hardening.', 'CWE-829', 'Avoid executing untrusted PR code in pull_request_target workflows.', { file: /\.github\/workflows\/.*\.ya?ml$/i }),
  rule('workflow-expression-in-run', 'critical', 'ci-security', /run\s*:[^\n]*\$\{\{\s*github\.event\.(?:pull_request\.(?:title|body|head\.ref)|issue\.title|comment\.body)/i, 'Potential script injection: untrusted event text is interpolated directly into a run command.', 'CWE-78', 'Assign the expression to an environment variable and quote/use it as data.', { file: /\.github\/workflows\/.*\.ya?ml$/i }),
  rule('github-action-node20-runtime', 'high', 'ci-security', /^\s*using\s*:\s*["']?node20["']?\s*$/i, 'GitHub Actions Node 20 JavaScript runtime is retired and no longer available on hosted runners.', 'CWE-1104', 'Update the JavaScript Action metadata to runs.using: node24 and verify dependencies support Node 24.', { file: /(?:^|\/)action\.ya?ml$/i }),
  rule('curl-pipe-shell', 'high', 'supply-chain', /\bcurl\b[^|]{0,200}\|\s*(?:sudo\s+)?(?:sh|bash)\b|\bwget\b[^|]{0,200}\|\s*(?:sudo\s+)?(?:sh|bash)\b/i, 'Remote content is piped directly to a shell.', 'CWE-494', 'Download, verify checksum/signature, then execute a pinned artifact.'),

  // AI / agentic trust boundaries
  rule('mcp-plain-http', 'high', 'ai-security', /["']?(?:server_url|serverUrl|mcp_url|mcpUrl)["']?\s*[:=]\s*["']http:\/\//i, 'Remote MCP server is configured over plain HTTP.', 'CWE-319', 'Use HTTPS for remote MCP servers, or a secure tunnel for private servers, and validate the server before granting tool access.'),
  rule('mcp-approval-disabled', 'medium', 'ai-security', /["']?(?:require_approval|requireApproval)["']?\s*[:=]\s*(?:["']never["']|false)(?=\s*[,}\]]|\s*$)/i, 'MCP/tool approval appears disabled for the configured tool surface.', 'CWE-862', 'Require approval for sensitive tools or narrowly scope only trusted read-only tools that may skip approval.', { strictOnly: true }),
  rule('mcp-wildcard-tools', 'medium', 'ai-security', /["']?(?:allowed_tools|allowedTools)["']?\s*[:=]\s*(?:\[\s*["']\*["']\s*\]|["']\*["'])/i, 'Agent or MCP configuration allows a wildcard tool surface.', 'CWE-250', 'Allowlist only the tools the workflow needs and keep write-capable tools approval-gated.', { strictOnly: true }),

  // IaC / container hardening
  rule('world-open-ingress', 'high', 'iac', /\b0\.0\.0\.0\/0\b|\b::\/0\b/, 'Network rule appears open to the entire internet.', 'CWE-284', 'Restrict ingress/egress to required CIDRs and ports.', { file: /\.(?:tf|ya?ml|json)$/i }),
  rule('iam-action-wildcard', 'high', 'iac', /["']?Action["']?\s*[:=]\s*["']\*["']/, 'IAM policy grants wildcard actions.', 'CWE-250', 'Grant only the required actions.', { file: /\.(?:tf|json|ya?ml)$/i }),
  rule('iam-resource-wildcard', 'medium', 'iac', /["']?Resource["']?\s*[:=]\s*["']\*["']/, 'IAM policy applies to all resources.', 'CWE-250', 'Scope the policy to specific resource ARNs.', { file: /\.(?:tf|json|ya?ml)$/i }),
  rule('k8s-privileged', 'critical', 'container', /\bprivileged\s*:\s*true\b/i, 'Container runs in privileged mode.', 'CWE-250', 'Disable privileged mode and grant only required capabilities.', { file: /\.ya?ml$/i }),
  rule('k8s-host-network', 'high', 'container', /\bhostNetwork\s*:\s*true\b/, 'Pod uses the host network namespace.', 'CWE-250', 'Avoid host networking unless strictly required.', { file: /\.ya?ml$/i }),
  rule('k8s-root-user', 'high', 'container', /\brunAsUser\s*:\s*0\b/, 'Container is configured to run as root.', 'CWE-250', 'Run as a non-root UID and enforce runAsNonRoot.', { file: /\.ya?ml$/i }),
  rule('allow-privilege-escalation', 'high', 'container', /\ballowPrivilegeEscalation\s*:\s*true\b/i, 'Container explicitly allows privilege escalation.', 'CWE-250', 'Set allowPrivilegeEscalation: false.', { file: /\.ya?ml$/i }),
  rule('docker-root-user', 'medium', 'container', /^\s*USER\s+root\s*$/i, 'Docker image explicitly switches to root.', 'CWE-250', 'Run the final image as a dedicated non-root user.', { file: /(?:^|\/)Dockerfile(?:\..*)?$/i }),
  rule('chmod-777', 'medium', 'configuration', /\bchmod\s+(?:-R\s+)?777\b/, 'World-writable permissions are being granted.', 'CWE-732', 'Use the narrowest required file permissions.'),
  rule('docker-privileged-flag', 'high', 'container', /\bdocker\s+run\b[^\n]*--privileged\b/, 'Docker container is launched with --privileged.', 'CWE-250', 'Use specific capabilities/devices instead of privileged mode.'),
  rule('compose-host-network', 'high', 'container', /\bnetwork_mode\s*:\s*["']?host["']?/i, 'Container uses host networking.', 'CWE-250', 'Use an isolated bridge/network unless host networking is required.', { file: /\.ya?ml$/i }),
  rule('compose-cap-all', 'high', 'container', /cap_add\s*:\s*\[[^\]]*\bALL\b[^\]]*\]/i, 'Container appears to add all Linux capabilities.', 'CWE-250', 'Add only the specific capabilities required.', { file: /\.ya?ml$/i }),
  rule('terraform-public-acl', 'high', 'iac', /\bacl\s*=\s*["']public-(?:read|read-write)["']/i, 'Terraform resource appears configured with a public ACL.', 'CWE-284', 'Keep storage private and expose content through controlled access.', { file: /\.tf$/i })
];
