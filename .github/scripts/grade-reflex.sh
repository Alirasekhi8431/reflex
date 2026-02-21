#!/usr/bin/env bash
# Grade Reflex project - behavior-based + fallback heuristic
# Usage: run from repo root. Env: BUILD_OK, TEST_PASS, COVERAGE_PCT, LINT_PASS, STUDENT_ID, TEST_RESULT_JSON (path to go test -json output)
# Prefer scoring by passed tests (TEST_RESULT_JSON); fallback to code-keyword checks when no test result.

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
XRAY="${ROOT}/xray-core"
REFLEX="${XRAY}/proxy/reflex"

# --- Inputs ---
BUILD_OK="${BUILD_OK:-false}"
TEST_PASS="${TEST_PASS:-false}"
COVERAGE_PCT="${COVERAGE_PCT:-0}"
LINT_PASS="${LINT_PASS:-false}"
STUDENT_ID="${STUDENT_ID:-unknown}"
TEST_RESULT_JSON="${TEST_RESULT_JSON:-}"

# --- Helpers ---
min() { echo $(( $2 > $1 ? $1 : $2 )); }
has() { [ -d "$REFLEX" ] && grep -rqE "$1" "$REFLEX" 2>/dev/null; }

# Build list of passed test names from go test -json output (one JSON object per line).
# Sets PASSED_TESTS to space-separated list of test names that passed.
get_passed_tests() {
  PASSED_TESTS=""
  local f=""
  [ -n "$TEST_RESULT_JSON" ] && [ -f "$TEST_RESULT_JSON" ] && f="$TEST_RESULT_JSON"
  [ -z "$f" ] && [ -n "$TEST_RESULT_JSON" ] && [ -f "$ROOT/$TEST_RESULT_JSON" ] && f="$ROOT/$TEST_RESULT_JSON"
  [ -z "$f" ] && [ -f "$XRAY/test_result.json" ] && f="$XRAY/test_result.json"
  # Artifact may be extracted into test-result/ folder (structure or flat)
  [ -z "$f" ] && [ -f "test-result/xray-core/test_result.json" ] && f="test-result/xray-core/test_result.json"
  [ -z "$f" ] && [ -f "$ROOT/test-result/xray-core/test_result.json" ] && f="$ROOT/test-result/xray-core/test_result.json"
  [ -z "$f" ] && [ -f "test-result/test_result.json" ] && f="test-result/test_result.json"
  [ -z "$f" ] && return 0
  while IFS= read -r line; do
    [ -z "$line" ] && continue
    result=$(echo "$line" | jq -r 'select(.Action == "pass" or .Action == "fail") | select(.Test != null) | "\(.Action)|\(.Test)"' 2>/dev/null)
    [ -z "$result" ] && continue
    action="${result%%|*}"; testname="${result#*|}"
    [ "$action" = "pass" ] && PASSED_TESTS="$PASSED_TESTS $testname"
  done < "$f"
  PASSED_TESTS="${PASSED_TESTS# }"
}

# Check if any passed test name matches the given regex (extended).
# Usage: test_matches "Handshake|KeyExchange"
test_matches() {
  local pat="$1" t
  for t in $PASSED_TESTS; do
    echo "$t" | grep -qE "$pat" && return 0
  done
  return 1
}

# Count how many of the given patterns have at least one passed test.
# Usage: count_matching_tests "Handshake|KeyExchange" "Auth|UUID"
count_matching_tests() {
  local n=0 pat
  for pat in "$@"; do
    test_matches "$pat" && n=$((n+1))
  done
  echo "$n"
}

count_tests() {
  local n=0 f
  for f in "$XRAY/proxy/reflex"/*_test.go \
           "$XRAY/proxy/reflex"/inbound/*_test.go \
           "$XRAY/proxy/reflex"/outbound/*_test.go \
           "$XRAY/proxy/reflex"/codec/*_test.go \
           "$XRAY/proxy/reflex"/handshake/*_test.go \
           "$XRAY/proxy/reflex"/tunnel/*_test.go \
           "$XRAY/proxy/reflex"/grading/*_test.go \
           "$XRAY/tests"/*reflex*_test.go \
           "$XRAY/tests"/*Reflex*_test.go; do
    [ -f "$f" ] || continue
    c=$(grep -c '^func Test' "$f" 2>/dev/null) || c=0
    c=${c//[^0-9]/}; [ -z "$c" ] && c=0
    n=$((n + c))
  done
  echo "$n"
}

outbound_has_logic() {
  local f="$REFLEX/outbound/outbound.go"
  [ -f "$f" ] || return 1
  local body
  body=$(grep -A30 'func.*Process' "$f" 2>/dev/null | head -25)
  echo "$body" | grep -qE '\.Dial\(|Dispatch\(|io\.Copy|link\.(Reader|Writer|Read|Write)|conn\.(Write|Read)|WriteMultiBuffer|ReadMultiBuffer' && return 0
  return 1
}

# --- Collect passed tests (if jq and test result available) ---
PASSED_TESTS=""
if command -v jq >/dev/null 2>&1; then
  get_passed_tests
fi
USE_TEST_BASED=false
if [ -n "$PASSED_TESTS" ] && [ "$TEST_PASS" = "true" ]; then
  USE_TEST_BASED=true
fi

# --- Step 1: Structure (10 pts) ---
step1=0
[ -d "$REFLEX" ] && step1=$((step1 + 2))
[ -f "$REFLEX/config.proto" ] || [ -f "$REFLEX/config.pb.go" ] || [ -f "$REFLEX/config.go" ] && step1=$((step1 + 2))
[ -f "$REFLEX/inbound/inbound.go" ] && step1=$((step1 + 2))
[ -d "$REFLEX/outbound" ] && [ -n "$(find "$REFLEX/outbound" -name '*.go' 2>/dev/null | head -1)" ] && step1=$((step1 + 2))
[ "$BUILD_OK" = "true" ] && step1=$((step1 + 4))
step1=$(min 10 $step1)
if [ "$BUILD_OK" != "true" ]; then
  [ "$step1" -gt 8 ] && step1=8
elif ! outbound_has_logic; then
  [ "$step1" -gt 8 ] && step1=8
fi

# --- Step 2: Handshake (15 pts) ---
step2=0
if [ "$USE_TEST_BASED" = true ]; then
  # Behavior: at least one handshake/key exchange/auth test passed
  if test_matches "Handshake|KeyExchange|Auth|UUID|KeyDerive|Curve25519|HKDF"; then
    # Extra: multiple behavior aspects = full score
    cnt=$(count_matching_tests "Handshake|KeyExchange" "Auth|UUID" "HKDF|Derive|Curve25519")
    [ "$cnt" -ge 2 ] && step2=15 || step2=10
  fi
fi
if [ "$step2" -eq 0 ]; then
  has "curve25519|Curve25519" && step2=$((step2 + 5))
  has "HKDF|hkdf" && step2=$((step2 + 4))
  has "uuid|UUID" && step2=$((step2 + 3))
  has "authenticate|Authenticate" && step2=$((step2 + 3))
  step2=$(min 15 $step2)
fi

# --- Step 3: Encryption (15 pts) ---
step3=0
if [ "$USE_TEST_BASED" = true ]; then
  if test_matches "Encrypt|Frame|ChaCha|AEAD|Replay|ReadFrame|WriteFrame"; then
    cnt=$(count_matching_tests "Encrypt|ChaCha|AEAD" "Frame|ReadFrame|WriteFrame" "Replay")
    [ "$cnt" -ge 2 ] && step3=15 || step3=10
  fi
fi
if [ "$step3" -eq 0 ]; then
  has "chacha20poly1305|ChaCha20Poly1305" && step3=$((step3 + 5))
  has "FrameTypeData|FrameType" && step3=$((step3 + 3))
  has "ReadFrame|WriteFrame" && step3=$((step3 + 4))
  has "AEAD|aead" && step3=$((step3 + 3))
  step3=$(min 15 $step3)
fi

# --- Step 4: Fallback (15 pts) ---
step4=0
if [ "$USE_TEST_BASED" = true ]; then
  if test_matches "Fallback|Peek|NonReflex|ProxyDetect"; then
    step4=15
  fi
fi
if [ "$step4" -eq 0 ]; then
  has "Peek|peek" && step4=$((step4 + 5))
  has "fallback|Fallback" && step4=$((step4 + 5))
  has "bufio.Reader|bufio" && step4=$((step4 + 5))
  step4=$(min 15 $step4)
fi

# --- Step 5: Advanced (20 pts) ---
step5=0
if [ "$USE_TEST_BASED" = true ]; then
  if test_matches "Morph|Padding|Timing|Profile|TrafficProfile|GetPacketSize|GetDelay|AddPadding"; then
    cnt=$(count_matching_tests "Morph|Profile|TrafficProfile" "Padding|PADDING|TIMING" "GetPacketSize|GetDelay|AddPadding")
    [ "$cnt" -ge 2 ] && step5=20 || step5=12
  fi
fi
if [ "$step5" -eq 0 ]; then
  has "TrafficProfile|TrafficMorph|PacketSize|DelayDist" && step5=$((step5 + 8))
  has "PADDING_CTRL|TIMING_CTRL|FrameTypePadding|FrameTypeTiming" && step5=$((step5 + 6))
  has "GetPacketSize|GetDelay|AddPadding" && step5=$((step5 + 6))
  step5=$(min 20 $step5)
fi

# --- Unit tests (10 pts) ---
unitTest=0
test_count=$(count_tests)
test_count="${test_count//[^0-9]/}"
[ -z "$test_count" ] && test_count=0
if [ "$TEST_PASS" = "true" ]; then
  [ "$test_count" -ge 8 ] && unitTest=10
  [ "$test_count" -ge 5 ] && [ "$test_count" -lt 8 ] && unitTest=6
  [ "$test_count" -ge 3 ] && [ "$test_count" -lt 5 ] && unitTest=3
fi

# --- Integration (10 pts): require passed tests that cover handshake, fallback, replay ---
integration=0
if [ "$TEST_PASS" = "true" ]; then
  if [ "$USE_TEST_BASED" = true ]; then
    ih=0; if test_matches "Handshake|Integration.*Handshake"; then ih=1; fi
    if=0; if test_matches "Fallback|Integration.*Fallback"; then if=1; fi
    ir=0; if test_matches "Replay|Integration.*Replay"; then ir=1; fi
    integration=$(( (ih + if + ir) * 3 ))
    [ "$integration" -gt 10 ] && integration=10
  else
    for kw in "handshake|Handshake" "fallback|Fallback" "replay|Replay" "integration|Integration"; do
      ([ -d "$XRAY/tests" ] && grep -rqE "$kw" "$XRAY/tests" 2>/dev/null) || \
      ([ -d "$REFLEX" ] && grep -rqE "$kw" "$REFLEX" 2>/dev/null) && integration=$((integration + 3))
    done
    integration=$(min 10 $integration)
  fi
  cov="${COVERAGE_PCT:-0}"; cov="${cov//[^0-9]/}"; [ -z "$cov" ] && cov=0
  [ "$cov" -lt 20 ] 2>/dev/null && [ "$integration" -gt 5 ] && integration=5
  [ "$cov" -lt 40 ] 2>/dev/null && [ "$cov" -ge 20 ] && [ "$integration" -gt 7 ] && integration=7
fi

# --- Clean code (10 pts) ---
cleanCode=0
[ "$LINT_PASS" = "true" ] && cleanCode=$((cleanCode + 6))
[ -d "$REFLEX/inbound" ] && [ -d "$REFLEX/outbound" ] && cleanCode=$((cleanCode + 2))
[ -d "$REFLEX" ] && grep -rq "// \|/\*" "$REFLEX" 2>/dev/null && cleanCode=$((cleanCode + 2))
cleanCode=$(min 10 $cleanCode)

# --- Report (10 pts) ---
report=0
if [ -f "$ROOT/README.md" ]; then
  lines=$(wc -l < "$ROOT/README.md" 2>/dev/null || echo 0)
  [ "$lines" -ge 20 ] && report=$((report + 5))
  [ "$lines" -ge 10 ] && [ "$report" -eq 0 ] && report=3
  [ "$lines" -ge 5 ] && [ "$report" -eq 0 ] && report=1
fi
[ -f "$ROOT/config.example.json" ] && report=$((report + 3))
[ -f "$ROOT/SUBMISSION.md" ] || [ -f "$ROOT/docs/submission.md" ] && report=$((report + 2))
report=$(min 10 $report)

# --- Validation ---
[ "$TEST_PASS" != "true" ] && unitTest=0 && integration=0

# --- Total ---
total=$((step1 + step2 + step3 + step4 + step5 + unitTest + integration + cleanCode + report))
[ "$total" -gt 105 ] && total=105

# --- Output ---
build_json="$([ "$BUILD_OK" = "true" ] && echo "true" || echo "false")"
test_json="$([ "$TEST_PASS" = "true" ] && echo "true" || echo "false")"
lint_json="$([ "$LINT_PASS" = "true" ] && echo "true" || echo "false")"
grading_mode="$([ "$USE_TEST_BASED" = true ] && echo "test-based" || echo "fallback")"

cat << EOF
{
  "studentId": "$STUDENT_ID",
  "step1": $step1,
  "step2": $step2,
  "step3": $step3,
  "step4": $step4,
  "step5": $step5,
  "unitTest": $unitTest,
  "integration": $integration,
  "cleanCode": $cleanCode,
  "report": $report,
  "total": $total,
  "totalMax": 105,
  "buildOk": $build_json,
  "testsPass": $test_json,
  "lintPass": $lint_json,
  "coverage": ${COVERAGE_PCT:-0},
  "gradingMode": "$grading_mode"
}
EOF
