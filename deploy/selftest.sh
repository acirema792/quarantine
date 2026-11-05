#!/usr/bin/env bash
# Runs every sample shipment through the live control plane and prints the verdicts,
# then the escape-artist red-team results. Usage: deploy/selftest.sh [base_url]
set -euo pipefail
BASE="${1:-http://127.0.0.1:8000}"
py() { python3 -c "$1"; }
for spec in fixture:escape-artist fixture:color-utils-pro fixture:mcp-weather-plus fixture:requestz fixture:turbo-build-cache fixture:left-padder; do
  id=$(curl -fsS -X POST "$BASE/api/runs" -H 'content-type: application/json' -d "{\"spec\":\"$spec\"}" | py 'import json,sys;print(json.load(sys.stdin)["id"])')
  until [ "$(curl -fsS "$BASE/api/runs/$id" | py 'import json,sys;print(json.load(sys.stdin)["status"])')" != "running" ] && \
        [ "$(curl -fsS "$BASE/api/runs/$id" | py 'import json,sys;print(json.load(sys.stdin)["status"])')" != "queued" ]; do sleep 2; done
  curl -fsS "$BASE/api/runs/$id" | py '
import json,sys
r=json.load(sys.stdin); rep=r.get("report") or {}
d=(rep.get("detonation") or [{}])[-1]; p=d.get("proof") or {}
print(f"{r[\"spec\"]:32} {r[\"status\"]:6} {str(r.get(\"verdict\")):11} score={r.get(\"score\")} runtime={p.get(\"runtime\")} teardown={d.get(\"teardown\",{}).get(\"verified\")}")
if rep.get("error"): print("   error:", rep["error"])'
  if [ "$spec" = "fixture:escape-artist" ]; then
    curl -fsS "$BASE/api/runs/$id/events" | grep -o '"line": "ESCAPE[^"]*"' | sed 's/"line": //' | sed 's/^/   /'
  fi
done
