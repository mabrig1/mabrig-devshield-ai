#!/usr/bin/env bash
set -euo pipefail
ACTION_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
cd "$TMP"
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
git add danger.js .env
git commit -qm "introduce risky code"
OUT="$TMP/out.txt"
SUMMARY="$TMP/summary.md"
: > "$OUT"
: > "$SUMMARY"
set +e
GITHUB_WORKSPACE="$TMP" \
GITHUB_OUTPUT="$OUT" \
GITHUB_STEP_SUMMARY="$SUMMARY" \
INPUT_FAIL_ON=none \
INPUT_COMMENT=false \
INPUT_MAX_FILES=80 \
node "$ACTION_ROOT/src/index.mjs"
STATUS=$?
set -e
if [[ $STATUS -ne 0 ]]; then
  echo "Expected fail-on=none to exit 0, got $STATUS" >&2
  exit 1
fi
COUNT="$(awk -F= '$1=="findings-count"{print $2}' "$OUT" | tail -1)"
LEVEL="$(awk -F= '$1=="risk-level"{print $2}' "$OUT" | tail -1)"
SCORE="$(awk -F= '$1=="risk-score"{print $2}' "$OUT" | tail -1)"
if [[ -z "$COUNT" || "$COUNT" -lt 3 ]]; then
  echo "Expected at least 3 findings, got ${COUNT:-missing}" >&2
  cat "$SUMMARY" >&2
  exit 1
fi
if [[ "$LEVEL" != "critical" ]]; then
  echo "Expected critical risk level, got $LEVEL" >&2
  exit 1
fi
if [[ -z "$SCORE" || "$SCORE" -lt 45 ]]; then
  echo "Expected risk score >=45, got ${SCORE:-missing}" >&2
  exit 1
fi
: > "$OUT"
set +e
GITHUB_WORKSPACE="$TMP" \
GITHUB_OUTPUT="$OUT" \
INPUT_FAIL_ON=critical \
INPUT_COMMENT=false \
node "$ACTION_ROOT/src/index.mjs" >/dev/null 2>&1
STATUS=$?
set -e
if [[ $STATUS -eq 0 ]]; then
  echo "Expected fail-on=critical to block the risky change" >&2
  exit 1
fi
echo "DevShield smoke test passed: $COUNT findings, risk $LEVEL ($SCORE/100)."
