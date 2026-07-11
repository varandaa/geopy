#!/usr/bin/env bash
# scan_geopy.sh — runs semgrep, black, and mypy on the geopy codebase
# Usage: bash scan_geopy.sh [path/to/geopy]   (defaults to ./geopy)

set -euo pipefail

PASS=0
FAIL=0

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

banner() {
  echo ""
  echo -e "${CYAN}${BOLD}━━━  $1  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
}

pass() {
  echo -e "${GREEN}${BOLD}  ✔  $1: PASSED${RESET}"
  PASS=$((PASS + 1))
}

fail() {
  echo -e "${RED}${BOLD}  ✘  $1: FAILED${RESET}"
  FAIL=$((FAIL + 1))
}

warn() {
  echo -e "${YELLOW}${BOLD}  ⚠  $1: WARNINGS FOUND${RESET}"
  FAIL=$((FAIL + 1))
}


# ── 1. Run in-house policy checker ────────────────────────────────────────────────────────────────────
banner "[1/4] Static policy checking"

POLICY_CHECK_EXIT=0
./code_policies . || POLICY_CHECK_EXIT=$?

echo ""
if [ "$POLICY_CHECK_EXIT" -eq 0 ]; then
  pass "policy"
else
  fail "policy"
fi




# ── summary ────────────────────────────────────────────────────────────────────

TOTAL=$((PASS + FAIL))
echo ""
echo -e "${BOLD}═══════════════════════════════════════════════════${RESET}"
echo -e "${BOLD}  scan complete — ${PASS}/${TOTAL} checks passed${RESET}"
echo -e "${BOLD}═══════════════════════════════════════════════════${RESET}"
echo ""

