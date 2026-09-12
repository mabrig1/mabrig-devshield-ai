#!/usr/bin/env bash
set -euo pipefail

ACTION_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

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

# 5) Fail threshold still blocks.
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

echo "DevShield enhanced smoke tests passed."
