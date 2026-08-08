#!/usr/bin/env bash
# Copyright (c) 2026 Sentinel contributors. Licensed under the MIT License.
#
# evaluate-gates.sh - Constitution Gate 5: zero HIGH/CRITICAL dynamic findings.
#
# Inputs (artifacts dir):
#   artifacts/zap-report.json           (traditional-json)
#   artifacts/nuclei-unauth.txt, nuclei-auth.txt
#
# Risk model: ZAP .riskcode is a STRING "0".."3" (info..high); treat >= 3 as a
# blocker. Nuclei lines look like:  [high] http://...  with status "HIGH/CRITICAL".
set -euo pipefail

ARTIFACTS="${ARTIFACTS:-artifacts}"
ZAP_JSON="$ARTIFACTS/zap-report.json"

[ -f "$ZAP_JSON" ] || { echo "::error::missing $ZAP_JSON - active scan did not complete" >&2; exit 1; }

ZAP_HIGH=$(jq '[.site[]?.alerts[]? | select((.riskcode // "0" | tonumber) >= 3)] | length' "$ZAP_JSON")
ZAP_MED=$(jq  '[.site[]?.alerts[]? | select((.riskcode // "0" | tonumber) == 2)] | length' "$ZAP_JSON")

NUCLEI_CRIT=0
for f in "$ARTIFACTS"/nuclei-*.txt; do
  [ -f "$f" ] || continue
  n=$(grep -Eo '\[(critical|high)\]' "$f" | wc -l || true)
  NUCLEI_CRIT=$((NUCLEI_CRIT + n))
done

echo "Gate 5 report: ZAP high=${ZAP_HIGH} medium=${ZAP_MED} | Nuclei critical+high=${NUCLEI_CRIT}"

if [ "${ZAP_HIGH}" -gt 0 ] || [ "${NUCLEI_CRIT}" -gt 0 ]; then
  echo "::error::Gate 5 FAILED - release blocked by HIGH/CRITICAL dynamic findings" >&2
  exit 1
fi

echo "Gate 5 PASSED"
exit 0