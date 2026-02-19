#!/usr/bin/env bash
# Grade Reflex project - outputs JSON for pipeline
# Usage: run from repo root; set BUILD_OK, TEST_PASS, COVERAGE_PCT, LINT_PASS, STUDENT_ID via env

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
XRAY="${ROOT}/xray-core"
REFLEX="${XRAY}/proxy/reflex"

# --- Inputs (from workflow env) ---
BUILD_OK="${BUILD_OK:-false}"
TEST_PASS="${TEST_PASS:-false}"
COVERAGE_PCT="${COVERAGE_PCT:-0}"
LINT_PASS="${LINT_PASS:-false}"
STUDENT_ID="${STUDENT_ID:-unknown}"

# --- Helpers ---
min() { echo $(( $2 > $1 ? $1 : $2 )); }
has() { [ -d "$REFLEX" ] && grep -rqE "$1" "$REFLEX" 2>/dev/null; }
count_tests() {
  local n=0 f
  for f in "$XRAY/proxy/reflex"/*_test.go \
           "$XRAY/proxy/reflex"/inbound/*_test.go \
           "$XRAY/proxy/reflex"/outbound/*_test.go \
           "$XRAY/proxy/reflex"/codec/*_test.go \
           "$XRAY/proxy/reflex"/handshake/*_test.go \
           "$XRAY/proxy/reflex"/tunnel/*_test.go \
           "$XRAY/tests"/*reflex*_test.go \
           "$XRAY/tests"/*Reflex*_test.go; do
    [ -f "$f" ] || continue
    c=$(grep -c '^func Test' "$f" 2>/dev/null) || c=0
    c=${c//[^0-9]/}
    [ -z "$c" ] && c=0
    n=$((n + c))
  done
  echo "$n"
}

# Outbound Process has real logic? (not just "return nil")
# Match calls/usage in body: Dial(, Dispatch(, io.Copy, link., conn. - not type names like *transport.Link
outbound_has_logic() {
  local f="$REFLEX/outbound/outbound.go"
  [ -f "$f" ] || return 1
  local body
  body=$(grep -A30 'func.*Process' "$f" 2>/dev/null | head -25)
  echo "$body" | grep -qE '\.Dial\(|Dispatch\(|io\.Copy|link\.(Reader|Writer|Read|Write)|conn\.(Write|Read)|WriteMultiBuffer|ReadMultiBuffer' && return 0
  return 1
}

# --- Step 1: Structure (10 pts) ---
step1=0
[ -d "$REFLEX" ] && step1=$((step1 + 2))
[ -f "$REFLEX/config.proto" ] || [ -f "$REFLEX/config.pb.go" ] && step1=$((step1 + 2))
[ -f "$REFLEX/inbound/inbound.go" ] && step1=$((step1 + 2))
[ -d "$REFLEX/outbound" ] && [ -n "$(find "$REFLEX/outbound" -name '*.go' 2>/dev/null | head -1)" ] && step1=$((step1 + 2))
[ "$BUILD_OK" = "true" ] && step1=$((step1 + 4))
step1=$(min 10 $step1)
# Cap if outbound is stub: max 8 for structure when Process has no real logic
if [ "$BUILD_OK" != "true" ]; then
  [ "$step1" -gt 8 ] && step1=8
elif ! outbound_has_logic; then
  [ "$step1" -gt 8 ] && step1=8
fi

# --- Step 2: Handshake (15 pts) ---
step2=0
has "curve25519|Curve25519" && step2=$((step2 + 5))
has "HKDF|hkdf" && step2=$((step2 + 4))
has "uuid|UUID" && step2=$((step2 + 3))
has "authenticate|Authenticate" && step2=$((step2 + 3))
step2=$(min 15 $step2)

# --- Step 3: Encryption (15 pts) ---
step3=0
has "chacha20poly1305|ChaCha20Poly1305" && step3=$((step3 + 5))
has "FrameTypeData|FrameType" && step3=$((step3 + 3))
has "ReadFrame|WriteFrame" && step3=$((step3 + 4))
has "AEAD|aead" && step3=$((step3 + 3))
step3=$(min 15 $step3)

# --- Step 4: Fallback (15 pts) ---
step4=0
has "Peek|peek" && step4=$((step4 + 5))
has "fallback|Fallback" && step4=$((step4 + 5))
has "bufio.Reader|bufio" && step4=$((step4 + 5))
step4=$(min 15 $step4)

# --- Step 5: Advanced (20 pts) ---
step5=0
has "TrafficProfile|TrafficMorph|PacketSize|DelayDist" && step5=$((step5 + 8))
has "PADDING_CTRL|TIMING_CTRL|FrameTypePadding|FrameTypeTiming" && step5=$((step5 + 6))
has "GetPacketSize|GetDelay|AddPadding" && step5=$((step5 + 6))
step5=$(min 20 $step5)

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

# --- Integration (10 pts) ---
integration=0
if [ "$TEST_PASS" = "true" ]; then
  for kw in "handshake|Handshake" "fallback|Fallback" "replay|Replay" "integration|Integration"; do
    ([ -d "$XRAY/tests" ] && grep -rqE "$kw" "$XRAY/tests" 2>/dev/null) || \
    ([ -d "$REFLEX" ] && grep -rqE "$kw" "$REFLEX" 2>/dev/null) && integration=$((integration + 3))
  done
  integration=$(min 10 $integration)
  # Coverage gate: <20% caps at 5; <40% caps at 7
  cov="${COVERAGE_PCT:-0}"
  cov="${cov//[^0-9]/}"
  [ -z "$cov" ] && cov=0
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
  "coverage": ${COVERAGE_PCT:-0}
}
EOF
