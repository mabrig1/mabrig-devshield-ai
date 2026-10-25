# October 2026 runtime and supply-chain checks

DevShield 3.3 adds a reviewed offline advisory snapshot dated **25 October 2026**.
The normal Action and CLI scan repository declarations. They do not query deployed
servers, run exploit probes, install dependencies, rotate credentials or patch hosts.

## Reviewed sources and patch floors

| Component | Scope | Published fixed releases / response |
| --- | --- | --- |
| PHP | CVE-2026-109618 and CVE-2026-109619 | 8.2.35, 8.3.36, 8.4.27, 8.5.12 on their respective branches |
| Node.js | October 21 security release, including Brotli, DNS and TLS fixes | 22.23.4, 24.22.1, 26.12.1 on their respective branches |
| LiteLLM | October 21 malicious PyPI release and container artifacts | Investigate 1.107.0 artifact origin/history; isolate and rebuild affected environments, rotate accessible credentials from a clean system |

Primary sources:

- [PHP announcements, October 21 and October 23](https://www.php.net/archive/2026.php)
- [Node.js October 21 security release](https://nodejs.org/en/blog/vulnerability/october-2026-security-releases)
- [LiteLLM incident notice, with updated investigation link](https://docs.litellm.ai/blog/security-incident-oct-21-2026)

These are branch-specific security floors for this snapshot, not a promise that
every later version is free of vulnerabilities. A distro may backport a fix without
changing the upstream version: verify its package advisory before accepting an exception.
Unknown future branches and prereleases are unresolved, not automatically cleared.

**PHP follow-up:** the October 23 notice identifies an additional conditional path
(CVE-2026-115560). Even after updating, review applications that configure
`session.serialize_handler` as `php_binary` or `php_serialize`, then switch it to
`php` at runtime before `session_start()`, with upload progress enabled. PHP
recommends disabling `session.upload_progress.enabled` until the next regular
bugfix release for relevant configurations. Validate application behavior and restart
workers after approved configuration changes. A WAF or plugin update does not replace
a PHP runtime patch.

## Automatic repository coverage

| Input | Interpretation |
| --- | --- |
| `.nvmrc`, `.node-version`, `.php-version`, `.tool-versions` | Exact stable runtime pins are compared against branch-specific floors |
| `package.json` `volta.node` | Exact pin; unrelated package names/versions are ignored |
| `package.json` `engines.node` | Compatibility constraint only; deployed version remains unverified |
| `composer.json` `require.php`, `require-dev.php`, `config.platform.php` | Constraint/emulated platform, not installed PHP evidence |
| Dockerfile/Containerfile `FROM`, Compose `image` | Recognized official Node/PHP images; known OS/SAPI suffixes supported; all stages reviewed |
| Literal LiteLLM requirements in `requirements*.txt`, `requirements*.in`, `requirements/*.txt` and `requirements/*.in` | Exact 1.107.0 reference is critical; unresolved requirements need review |
| Recognized LiteLLM Docker Hub/GHCR images | Incident version or the full known image-index digest is critical; mutable incident tags and other digests require review |
| PHP session settings in `.ini` files | Conditional medium-severity review; runtime serializer changes are not inferred |

Exact PHP pins below the published floor are critical; Node pins are high.
Unsupported upstream releases are high. Constraints, aliases, partial versions,
prereleases, and digest-pinned Node/PHP images are medium review signals. A digest
overrides a tag, so a patched-looking tag cannot clear an unknown image digest.

LiteLLM's official source tag was not the compromised artifact. A source checkout
or `latest` tag alone does not establish installation of a malicious package.
The known full digest covered here is the image index
`sha256:1bbcb1443bc962e45f5aad53fe3d2c30600e0379715fb6c664cdd3ac126c339e`.
Other variants/digests require comparison with the incident notice and build history.
If an implicated artifact ran, an ordinary package upgrade is insufficient. Do not
start Python or pip inside a suspected environment; use a clean incident-response environment.

## Use the checks

Normal repository audit (run from the repository to inspect):

```bash
node /path/to/devshield/bin/devshield.mjs --repository --fail-on high
```

No new Action input is required. Findings use the existing `fail-on`, policy,
exclusion, severity override, baseline and suppression behavior. Critical findings
are not suppressed inline under their default severity. JSON and SARIF include
advisory sources and evidence labels. JSON includes `runtimeAdvisorySnapshot`.

Compare known runtime versions without executing the application:

```bash
npm run runtime:advisories -- --node-version 24.22.1 --php-version 8.4.27
# Equivalent CLI dispatcher:
node bin/devshield.mjs --runtime-advisories --node-version 24.22.1
```

With no version arguments, only the scanner process's Node.js version is checked.
It is labelled `local-scanner-process`, never production evidence. Explicit values
are labelled `operator-supplied-version`; collect them from trusted deployment logs
or host inventory. PHP CLI and the web/FPM runtime can differ.

The command prints JSON to stdout. Exit 1 means the requested severity threshold
was met; exit 2 means invalid arguments. Exit 0 is not security certification.
Use `--fail-on medium` to require resolution of unknown branches as well.
`meets-listed-fix` only refers to the listed October 21 patch floors; PHP's separate
follow-up remains in the assessment.

## Boundaries and rollout

- Scans respect existing changed-line, staged, repository, excluded-path and file-size/count limits.
  Run repository scope to review old declarations; a changed-line scan will not rediscover untouched ones.
- No complete SBOM, runtime inventory, breach detection or package installation is performed.
  No finding means no covered signal was found, not that exposure is absent.
- Generated manifests, indirect Docker `ARG` base images, custom image registries,
  deployment dashboards, YAML anchors, multiline YAML, general Python TOML/lockfiles,
  and GitHub Actions `node-version` matrices are not resolved by this parser.
- Composer's platform emulation and package engines cannot certify a deployed host.
- Session analysis is local to each INI file; includes, per-directory overrides and
  application runtime changes require review. Malformed, duplicate-key or excessively
  nested JSON is skipped by these checks and is not deployment evidence.
- Evidence stores runtime numbers and hashes of declarations, not arbitrary source values.
- This snapshot is bundled and reviewable; it does not auto-update from headlines.
  PR #38's separate scheduled intelligence collector is not merged by this update.
- Release this branch through normal review, then update consumer pins deliberately.
  Existing release tags and running applications are unchanged until separately rolled out.

For each affected service: identify the active runtime/artifact, confirm the vendor
fix, test a rebuilt staging deployment, apply the approved rollout, then verify the
running version and investigate any signs of compromise. Patching does not undo theft.
