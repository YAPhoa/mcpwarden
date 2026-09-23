#!/usr/bin/env bash
set -euo pipefail

endpoint="${1:-http://127.0.0.1:8787/mcp}"
tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT
headers=(-H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream')
if [[ -n "${MCPWARDEN_TOKEN:-}" ]]; then headers+=(-H "Authorization: Bearer ${MCPWARDEN_TOKEN}"); fi

request() {
  local body="$1" out="$2"
  local session_header=()
  if [[ -s "$tmp_dir/session" ]]; then session_header=(-H "Mcp-Session-Id: $(cat "$tmp_dir/session")"); fi
  curl --fail-with-body -sS -D "$tmp_dir/headers" -o "$out" "${headers[@]}" "${session_header[@]}" -d "$body" "$endpoint"
  awk 'BEGIN{IGNORECASE=1} tolower($1)=="mcp-session-id:" {gsub("\r", "", $2); print $2}' "$tmp_dir/headers" > "$tmp_dir/new-session"
  if [[ -s "$tmp_dir/new-session" ]]; then cp "$tmp_dir/new-session" "$tmp_dir/session"; fi
}
decode() {
  python3 - "$1" <<'PY'
import json, pathlib, sys
body = pathlib.Path(sys.argv[1]).read_text()
if body.lstrip().startswith('event:') or body.lstrip().startswith('data:'):
    payloads = [line[5:].strip() for line in body.splitlines() if line.startswith('data:')]
    for payload in payloads:
        try:
            value = json.loads(payload)
            if 'result' in value or 'error' in value:
                print(json.dumps(value)); break
        except json.JSONDecodeError: pass
else:
    print(json.dumps(json.loads(body)))
PY
}

request '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"mcpwarden-smoke","version":"1"}}}' "$tmp_dir/init"
decode "$tmp_dir/init"
request '{"jsonrpc":"2.0","method":"notifications/initialized"}' "$tmp_dir/initialized"
request '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}' "$tmp_dir/list"
decode "$tmp_dir/list" | tee "$tmp_dir/list.json"
tool="${SMOKE_TOOL:-$(python3 - "$tmp_dir/list.json" <<'PY'
import json,sys
tools=json.load(open(sys.argv[1])).get('result',{}).get('tools',[])
print(tools[0]['name'] if tools else '')
PY
)}"
if [[ -z "$tool" ]]; then echo 'No tools available to call; set SMOKE_TOOL after an upstream becomes healthy.' >&2; exit 1; fi
args="${SMOKE_ARGS:-}"
if [[ -z "$args" ]]; then args='{}'; fi
body="$(python3 - "$tool" "$args" <<'PY'
import json,sys
print(json.dumps({'jsonrpc':'2.0','id':3,'method':'tools/call','params':{'name':sys.argv[1],'arguments':json.loads(sys.argv[2])}}))
PY
)"
request "$body" "$tmp_dir/call"
decode "$tmp_dir/call"
