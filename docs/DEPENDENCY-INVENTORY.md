# Offline dependency evidence

DevShield can inspect an npm lockfile without installing dependencies, running lifecycle scripts, sending source code to an AI provider, or requiring a GitHub token. Use this alongside source scanning to produce reviewable dependency metadata for a customer security review or an open-source project evaluation.

## Run locally

From the DevShield checkout:

```bash
npm run inventory
npm run scan -- --inventory --fail-on medium
```

From the application you want to inspect, invoke the downloaded DevShield CLI:

```bash
node /path/to/mabrig-devshield-ai/bin/inventory.mjs --fail-on high
node /path/to/mabrig-devshield-ai/bin/inventory.mjs --lockfile apps/api/package-lock.json --report-dir .devshield-api
```

All input and output paths must stay inside the current working directory. Symlink paths are rejected. By default `npm-shrinkwrap.json` takes precedence over `package-lock.json`, matching npm. Lockfile versions 2 and 3 are supported; version 1, malformed entries, missing files, and files over 20 MiB fail explicitly. Select each monorepo lockfile separately.

## Reports and gates

The command writes `.devshield/dependency-inventory.json` and `.devshield/dependency-inventory.md` before applying the gate. It exits with 0 when the configured threshold passes, 1 when a metadata finding reaches the threshold, and 2 for invalid inputs or report failures. The default threshold is `high`; `--fail-on none` disables finding-based failure but does not suppress input errors.

| Evidence | Meaning |
| --- | --- |
| Package identity and version | Derived from the lockfile; nested packages and scoped names are retained. Unsupported version forms remain unknown. |
| Package URL | npm package identity when the name and version can be represented; not a download URL. |
| Lockfile SHA-256 and JSON pointer | Identifies the exact input and the package entry supporting a finding. |
| License | Declared and unverified, or unknown. No license compatibility conclusions are made. |
| Integrity | A supported, structurally valid digest is recorded but not checked against package bytes. |
| Source transport | HTTP or unencrypted Git produces a high severity finding. Full resolved URLs are omitted. |
| Install scripts | Whether the lockfile explicitly declares an install script; absence is not proof that no script exists. |

Missing or invalid remote integrity metadata produces a medium finding, SHA-1-only integrity produces a low finding, and an unknown source produces a low finding. Local dependencies, workspace links, and Git sources are not required to have tarball integrity. Workspaces are recorded without dereferencing links. Findings include stable fingerprints and remediation instructions.

## Use in GitHub Actions

After this change is merged, pin DevShield to the reviewed commit that contains the inventory CLI:

```yaml
permissions:
  contents: read
steps:
  - uses: actions/checkout@v7
  - uses: actions/setup-node@v7
    with:
      node-version: '24'
  - uses: actions/checkout@v7
    with:
      repository: mabrig1/mabrig-devshield-ai
      ref: '<reviewed-commit-containing-inventory>'
      path: .tools/devshield
  - name: Review npm dependency evidence
    run: node .tools/devshield/bin/inventory.mjs --fail-on high
```

The existing Action's GitHub dependency-review API integration remains available. This inventory is an additional CLI command and does not automatically run inside the Action entrypoint or join the source scanner's baseline, SARIF, policy, or Cloud reports.

## Limits and privacy

This command reads the **working-tree lockfile**, not the staged Git snapshot or installed modules. It does not fetch vulnerability advisories, verify registry signatures or publisher attestations, download packages, or check package bytes against integrity digests. It is a metadata inventory, not a complete SBOM or security certification. Zero findings must not be described as zero vulnerabilities.

Reports omit resolved URLs, including their credentials, query strings and fragments. They still contain private package names, versions, locations, and declared licenses; review them before sharing. Missing information remains unknown. The Markdown summary intentionally avoids rendering untrusted package text.

The parser follows the [npm package-lock format](https://docs.npmjs.com/cli/v11/configuring-npm/package-lock-json/). Grant eligibility and permitted AI assistance must be checked against each funder's current rules; producing an evidence report does not itself establish eligibility.
