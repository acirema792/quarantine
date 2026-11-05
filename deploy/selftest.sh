#!/usr/bin/env bash
# End-to-end check of a live deployment: every sample shipment must get its expected
# verdict on the configured runtime, every escape probe must be blocked, every sandbox
# must be torn down. Exits non-zero on any mismatch.  Usage: deploy/selftest.sh [base_url]
set -uo pipefail
BASE="${1:-http://127.0.0.1:8000}"
fail=0
declare -A EXPECT=( [escape-artist]=SUSPICIOUS [color-utils-pro]=MALICIOUS [mcp-weather-plus]=MALICIOUS
                    [requestz]=MALICIOUS [turbo-build-cache]=MALICIOUS [left-padder]=CLEAN )
get() { curl -fsS "$BASE$1"; }
field() { python3 -c "import json,sys; d=json.load(sys.stdin); print($1)"; }
runtime=$(get /api/health | field 'd["engine"].get("runtime")')
echo "runtime: $runtime   firewall: $(get /api/health | field 'd["engine"].get("host_firewall",{}).get("active")')"
[ "$runtime" = "runsc" ] || { echo "WARN: not running under gVisor"; fail=1; }
for name in escape-artist color-utils-pro mcp-weather-plus requestz turbo-build-cache left-padder; do
  id=$(curl -fsS -X POST "$BASE/api/runs" -H 'content-type: application/json' -d "{\"spec\":\"fixture:$name\"}" | field 'd["id"]')
  for _ in $(seq 1 120); do
    st=$(get "/api/runs/$id" | field 'd["status"]'); [ "$st" = done ] || [ "$st" = error ] && break; sleep 3
  done
  line=$(get "/api/runs/$id" | python3 -c '
import json,sys
r=json.load(sys.stdin); rep=r.get("report") or {}; d=(rep.get("detonation") or [{}])[-1]
print(r.get("verdict"), d.get("teardown",{}).get("verified"), (d.get("proof") or {}).get("runtime"))')
  set -- $line
  ok="ok"; { [ "$1" = "${EXPECT[$name]}" ] && [ "$2" = "True" ]; } || { ok="MISMATCH"; fail=1; }
  printf '%-20s verdict=%-11s expected=%-11s teardown=%s runtime=%s  %s\n' "$name" "$1" "${EXPECT[$name]}" "$2" "$3" "$ok"
  if [ "$name" = escape-artist ]; then
    probes=$(get "/api/runs/$id/events" | grep -o '"line": "ESCAPE [^"]*"' | sed 's/"line": "//; s/"$//')
    echo "$probes" | sed 's/^/    /'
    echo "$probes" | grep -q SUCCEEDED && { echo "    ESCAPE SUCCEEDED"; fail=1; }
  fi
done
[ "$fail" = 0 ] && echo "SELFTEST PASSED" || echo "SELFTEST FAILED"
exit $fail
