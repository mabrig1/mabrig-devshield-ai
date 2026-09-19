#!/usr/bin/env bash
set -euo pipefail

ACTION_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

node --test "$ACTION_ROOT/test/agentic-engine.test.mjs"
node --test "$ACTION_ROOT/test/remediation-engine.test.mjs"
node --test "$ACTION_ROOT/test/inventory.test.mjs"
node --test "$ACTION_ROOT/test/dependency-agent.test.mjs"
node --test "$ACTION_ROOT/test/security-graph.test.mjs"
node --test "$ACTION_ROOT/test/control-plane.test.mjs"

run_scan() {
  local repo="$1"
  local out="$repo/out.txt"
  local summary="$repo/summary.md"
  : > "$out"
  : > "$summary"
  GITHUB_WORKSPACE="$repo" \
  GITHUB_OUTPUT="$out" \
  GITHUB_STEP_SUMMARY="$summary" \
  INPUT_FAIL_ON=none \
  INPUT_COMMENT=false \
  INPUT_MAX_FILES=120 \
  INPUT_SARIF=true \
  node "$ACTION_ROOT/src/index.mjs"
}

assert_output() {
  local out="$1"
  local key="$2"
  awk -F= -v k="$key" '$1==k{print $2}' "$out" | tail -1
}

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# 1) Core security findings + machine-readable reports.
REPO1="$TMP/core"
mkdir -p "$REPO1"
cd "$REPO1"
git init -q
git config user.email "devshield-test@example.invalid"
git config user.name "DevShield Test"
printf 'export const ok = true;\n' > safe.js
git add safe.js
git commit -qm "baseline"

cat > danger.js <<'JS'
export function risky(input) {
  return eval(input);
}
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
JS
cat > .env <<'ENV'
OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyz123456789
ENV
mkdir -p .github/workflows
cat > .github/workflows/unsafe.yml <<'YAML'
name: unsafe
on:
  pull_request_target:
permissions: write-all
jobs:
  danger:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@main
      - run: echo "${{ github.event.pull_request.title }}"
YAML
git add danger.js .env .github/workflows/unsafe.yml
git commit -qm "introduce risky code"

run_scan "$REPO1"
COUNT="$(assert_output "$REPO1/out.txt" findings-count)"
LEVEL="$(assert_output "$REPO1/out.txt" risk-level)"
REPORT="$(assert_output "$REPO1/out.txt" report-file)"
SARIF="$(assert_output "$REPO1/out.txt" sarif-file)"

if [[ -z "$COUNT" || "$COUNT" -lt 7 ]]; then
  echo "Expected at least 7 findings, got ${COUNT:-missing}" >&2
  cat "$REPO1/summary.md" >&2
  exit 1
fi
if [[ "$LEVEL" != "critical" ]]; then
  echo "Expected critical risk level, got $LEVEL" >&2
  exit 1
fi
node -e "JSON.parse(require('fs').readFileSync('$REPO1/$REPORT','utf8')); JSON.parse(require('fs').readFileSync('$REPO1/$SARIF','utf8'))"

# 2) Diff-aware default must not re-report legacy findings on untouched lines.
REPO2="$TMP/diffaware"
mkdir -p "$REPO2"
cd "$REPO2"
git init -q
git config user.email "devshield-test@example.invalid"
git config user.name "DevShield Test"
cat > app.js <<'JS'
export function legacy(input) {
  return eval(input);
}
export const version = 1;
JS
git add app.js
git commit -qm "legacy baseline"
python3 - <<'PY'
from pathlib import Path
p=Path("app.js")
p.write_text(p.read_text().replace("version = 1", "version = 2"))
PY
git add app.js
git commit -qm "safe unrelated edit"
run_scan "$REPO2"
COUNT2="$(assert_output "$REPO2/out.txt" findings-count)"
if [[ "$COUNT2" != "0" ]]; then
  echo "Expected changed-lines mode to ignore legacy untouched eval, got $COUNT2 findings" >&2
  cat "$REPO2/summary.md" >&2
  exit 1
fi

# 3) Inline suppressions work for non-critical findings, but critical findings remain unsuppressible.
REPO3="$TMP/suppressions"
mkdir -p "$REPO3"
cd "$REPO3"
git init -q
git config user.email "devshield-test@example.invalid"
git config user.name "DevShield Test"
printf 'export const ok = true;\n' > base.js
git add base.js
git commit -qm "baseline"
cat > app.js <<'JS'
// devshield:ignore shell-exec
exec("echo safe-controlled-command");
// devshield:ignore dangerous-eval
eval(userInput);
// devshield:ignore
const token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
JS
git add app.js
git commit -qm "suppression test"
run_scan "$REPO3"
COUNT3="$(assert_output "$REPO3/out.txt" findings-count)"
IGNORED3="$(assert_output "$REPO3/out.txt" ignored-findings)"
if [[ "$COUNT3" -ne 1 ]]; then
  echo "Expected only the critical token to remain visible, got $COUNT3" >&2
  cat "$REPO3/summary.md" >&2
  exit 1
fi
if [[ "$IGNORED3" -lt 2 ]]; then
  echo "Expected both non-critical findings to be suppressed" >&2
  exit 1
fi

# 4) Config policy overrides and secrets-only mode.
REPO4="$TMP/config"
mkdir -p "$REPO4"
cd "$REPO4"
git init -q
git config user.email "devshield-test@example.invalid"
git config user.name "DevShield Test"
printf 'export const ok = true;\n' > base.js
git add base.js
git commit -qm "baseline"
cat > .devshield.json <<'JSON'
{
  "policy": "secrets-only",
  "excludePaths": ["ignored/**"]
}
JSON
mkdir -p ignored
cat > app.js <<'JS'
eval(userInput);
const token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
JS
cat > ignored/key.js <<'JS'
const token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
JS
git add .
git commit -qm "config test"
run_scan "$REPO4"
COUNT4="$(assert_output "$REPO4/out.txt" findings-count)"
if [[ "$COUNT4" -ne 1 ]]; then
  echo "Expected secrets-only config to report only the hardcoded token, got $COUNT4" >&2
  cat "$REPO4/summary.md" >&2
  exit 1
fi

# Explicit config-driven secrets-only check (no INPUT_POLICY environment value).
: > "$REPO4/out.txt"
GITHUB_WORKSPACE="$REPO4" \
GITHUB_OUTPUT="$REPO4/out.txt" \
INPUT_FAIL_ON=none \
INPUT_COMMENT=false \
INPUT_CONFIG_FILE=.devshield.json \
INPUT_SCAN_SCOPE=changed-files \
node "$ACTION_ROOT/src/index.mjs" >/dev/null
COUNT4B="$(assert_output "$REPO4/out.txt" findings-count)"
if [[ "$COUNT4B" -lt 1 ]]; then
  echo "Expected secrets-only config to detect hardcoded password" >&2
  exit 1
fi

# 5) Baselines distinguish existing findings from new merge-gated findings.
REPO5="$TMP/baseline"
mkdir -p "$REPO5"
cd "$REPO5"
git init -q
git config user.email "devshield-test@example.invalid"
git config user.name "DevShield Test"
printf 'export const safe = 1;\n' > safe.js
git add safe.js
git commit -qm "baseline"
cat > app.js <<'JS'
export function legacyRisk(input) {
  return eval(input);
}
JS
git add app.js
git commit -qm "add legacy risk"

: > "$REPO5/out.txt"
GITHUB_WORKSPACE="$REPO5" \
GITHUB_OUTPUT="$REPO5/out.txt" \
INPUT_FAIL_ON=none \
INPUT_COMMENT=false \
INPUT_SCAN_SCOPE=repository \
node "$ACTION_ROOT/src/index.mjs" >/dev/null
BASELINE_CANDIDATE="$(assert_output "$REPO5/out.txt" baseline-output-file)"
cp "$REPO5/$BASELINE_CANDIDATE" "$REPO5/.devshield-baseline.json"

printf 'export const safe = 2;\n' > safe.js
git add safe.js
git commit -qm "safe follow-up"

: > "$REPO5/out.txt"
GITHUB_WORKSPACE="$REPO5" \
GITHUB_OUTPUT="$REPO5/out.txt" \
INPUT_FAIL_ON=none \
INPUT_COMMENT=false \
INPUT_SCAN_SCOPE=repository \
INPUT_BASELINE_FILE=.devshield-baseline.json \
INPUT_BASELINE_MODE=new-only \
node "$ACTION_ROOT/src/index.mjs" >/dev/null
BASE_NEW="$(assert_output "$REPO5/out.txt" new-findings)"
BASE_EXISTING="$(assert_output "$REPO5/out.txt" existing-findings)"
BASE_LEVEL="$(assert_output "$REPO5/out.txt" risk-level)"
if [[ "$BASE_NEW" != "0" || -z "$BASE_EXISTING" || "$BASE_EXISTING" -lt 1 ]]; then
  echo "Expected baseline to classify legacy finding as existing; new=$BASE_NEW existing=$BASE_EXISTING" >&2
  exit 1
fi
if [[ "$BASE_LEVEL" != "low" ]]; then
  echo "Expected no new merge-gated risk after baseline, got $BASE_LEVEL" >&2
  exit 1
fi

# 6) Dependency intelligence converts GitHub dependency review data into first-class findings.
REPO6="$TMP/dependencies"
mkdir -p "$REPO6"
cd "$REPO6"
git init -q
git config user.email "devshield-test@example.invalid"
git config user.name "DevShield Test"
printf '{}\n' > package.json
git add package.json
git commit -qm "baseline"
cat > package.json <<'JSON'
{
  "dependencies": {
    "example-risky-package": "1.0.0",
    "example-copyleft-package": "2.0.0"
  }
}
JSON
git add package.json
git commit -qm "dependency change"
cat > dependency-fixture.json <<'JSON'
[
  {
    "change_type": "added",
    "manifest": "package.json",
    "ecosystem": "npm",
    "name": "example-risky-package",
    "version": "1.0.0",
    "package_url": "pkg:npm/example-risky-package@1.0.0",
    "license": "MIT",
    "vulnerabilities": [
      {
        "severity": "critical",
        "advisory_ghsa_id": "GHSA-test-1234-5678",
        "advisory_summary": "Test critical vulnerability",
        "advisory_url": "https://github.com/advisories/GHSA-test-1234-5678"
      }
    ]
  },
  {
    "change_type": "added",
    "manifest": "package.json",
    "ecosystem": "npm",
    "name": "example-copyleft-package",
    "version": "2.0.0",
    "package_url": "pkg:npm/example-copyleft-package@2.0.0",
    "license": "GPL-3.0",
    "vulnerabilities": []
  }
]
JSON

: > "$REPO6/out.txt"
DEVSHIELD_DEPENDENCY_REVIEW_FIXTURE="$REPO6/dependency-fixture.json" \
GITHUB_WORKSPACE="$REPO6" \
GITHUB_OUTPUT="$REPO6/out.txt" \
INPUT_FAIL_ON=none \
INPUT_COMMENT=false \
INPUT_DEPENDENCY_REVIEW=true \
INPUT_DEPENDENCY_DENY_LICENSES=GPL-3.0 \
node "$ACTION_ROOT/src/index.mjs" >/dev/null
DEP_COUNT="$(assert_output "$REPO6/out.txt" dependency-findings)"
DEP_STATUS="$(assert_output "$REPO6/out.txt" dependency-review-status)"
DEP_LEVEL="$(assert_output "$REPO6/out.txt" risk-level)"
if [[ "$DEP_COUNT" -ne 2 || "$DEP_STATUS" != "fixture" ]]; then
  echo "Expected one vulnerable dependency plus one denied-license finding; count=$DEP_COUNT status=$DEP_STATUS" >&2
  exit 1
fi
if [[ "$DEP_LEVEL" != "critical" ]]; then
  echo "Expected critical dependency risk, got $DEP_LEVEL" >&2
  exit 1
fi

# 7) Local CLI scans staged Git index content and blocks risky commits.
REPO7="$TMP/cli"
mkdir -p "$REPO7"
cd "$REPO7"
git init -q
git config user.email "devshield-test@example.invalid"
git config user.name "DevShield Test"
printf 'export const safe = 1;\n' > app.js
git add app.js
git commit -qm "baseline"

cat > app.js <<'JS'
export function stagedRisk(input) {
  return eval(input);
}
JS
git add app.js

# Change the working tree after staging. The CLI must still inspect the risky staged snapshot.
printf 'export const safeWorkingTree = true;\n' > app.js

set +e
node "$ACTION_ROOT/bin/devshield.mjs" --staged --fail-on high --no-sarif >/dev/null 2>&1
CLI_RISKY_STATUS=$?
set -e
if [[ $CLI_RISKY_STATUS -eq 0 ]]; then
  echo "Expected local CLI to block risky staged content even when the working tree is later changed" >&2
  exit 1
fi

git reset -q HEAD app.js
printf 'export const safe = 2;\n' > app.js
git add app.js
node "$ACTION_ROOT/bin/devshield.mjs" --staged --fail-on high --no-sarif >/dev/null

# 8) Cloud export is opt-in, structured, and does not contain source snippets or the cloud token.
REPO8="$TMP/cloud"
mkdir -p "$REPO8"
cd "$REPO8"
git init -q
git config user.email "devshield-test@example.invalid"
git config user.name "DevShield Test"
printf 'export const safe = true;\n' > base.js
git add base.js
git commit -qm "baseline"
cat > risky.js <<'JS'
export function cloudRisk(userInput) {
  return eval(userInput /* CLOUD_SOURCE_MARKER */);
}
JS
git add risky.js
git commit -qm "cloud export fixture"

: > "$REPO8/out.txt"
DEVSHIELD_CLOUD_EXPORT_CAPTURE="$REPO8/cloud-payload.json" \
GITHUB_WORKSPACE="$REPO8" \
GITHUB_OUTPUT="$REPO8/out.txt" \
GITHUB_EVENT_PATH= \
GITHUB_REPOSITORY="example/private-repo" \
GITHUB_SHA="$(git rev-parse HEAD)" \
INPUT_FAIL_ON=none \
INPUT_COMMENT=false \
INPUT_CLOUD_API_URL=https://cloud.devshield.example/api/v1/scans \
INPUT_CLOUD_TOKEN=cloud-test-token \
node "$ACTION_ROOT/src/index.mjs" >/dev/null

CLOUD_STATUS="$(assert_output "$REPO8/out.txt" cloud-export-status)"
if [[ "$CLOUD_STATUS" != "fixture" ]]; then
  echo "Expected fixture Cloud export status, got $CLOUD_STATUS" >&2
  exit 1
fi
node - "$REPO8/cloud-payload.json" <<'NODE'
const fs = require('fs');
const file = process.argv[2];
const raw = fs.readFileSync(file, 'utf8');
const payload = JSON.parse(raw);
if (!Array.isArray(payload.findings) || payload.findings.length < 1) {
  throw new Error('Expected structured Cloud findings');
}
if (raw.includes('CLOUD_SOURCE_MARKER')) {
  throw new Error('Cloud payload leaked source text');
}
if (raw.includes('cloud-test-token')) {
  throw new Error('Cloud payload leaked authentication token');
}
if (raw.includes('UNTRUSTED_REDACTED_DIFF')) {
  throw new Error('Cloud payload leaked diff data');
}
if (payload.repository.fullName !== 'example/private-repo') {
  throw new Error('Expected repository metadata in Cloud payload');
}
NODE

# Cloud-required mode fails closed for invalid/non-HTTPS managed endpoints.
: > "$REPO8/out-required.txt"
set +e
GITHUB_WORKSPACE="$REPO8" \
GITHUB_OUTPUT="$REPO8/out-required.txt" \
INPUT_FAIL_ON=none \
INPUT_COMMENT=false \
INPUT_CLOUD_API_URL=http://insecure.example.invalid/api/v1/scans \
INPUT_CLOUD_TOKEN=cloud-test-token \
INPUT_CLOUD_REQUIRED=true \
node "$ACTION_ROOT/src/index.mjs" >/dev/null 2>&1
CLOUD_REQUIRED_STATUS=$?
set -e
if [[ $CLOUD_REQUIRED_STATUS -eq 0 ]]; then
  echo "Expected cloud-required mode to reject a non-HTTPS endpoint" >&2
  exit 1
fi

# 9) Fail threshold still blocks.
cd "$REPO1"
: > "$REPO1/out.txt"
set +e
GITHUB_WORKSPACE="$REPO1" \
GITHUB_OUTPUT="$REPO1/out.txt" \
INPUT_FAIL_ON=critical \
INPUT_COMMENT=false \
node "$ACTION_ROOT/src/index.mjs" >/dev/null 2>&1
STATUS=$?
set -e
if [[ $STATUS -eq 0 ]]; then
  echo "Expected fail-on=critical to block the risky change" >&2
  exit 1
fi

echo "DevShield v2.0 security control plane smoke tests passed."
