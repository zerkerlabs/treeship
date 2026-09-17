#!/bin/sh
# Shared by the hooks: derive the Treeship agent instance name for the hook
# payload on stdin. The main Claude Code instance is "claude-code". A
# subagent (the payload carries agent_id and agent_type) is
# "<agent_type>#<first 8 of agent_id>", so its events in the timeline and
# the receipt's agent graph are attributable to that instance and not to
# the parent. Source this file; it defines json_field and agent_instance.

json_field() {
  # json_field "<json>" <top-level key>  -> string value or empty
  _in="$1"; _key="$2"; _out=""
  if command -v jq >/dev/null 2>&1; then
    _out=$(printf '%s' "$_in" | jq -r --arg k "$_key" '.[$k] // empty | if type=="string" then . else tojson end' 2>/dev/null)
  fi
  if [ -z "$_out" ] && command -v python3 >/dev/null 2>&1; then
    _out=$(printf '%s' "$_in" | python3 -c '
import json, sys
try:
    v = json.load(sys.stdin).get(sys.argv[1])
    print("" if v is None else (v if isinstance(v, str) else json.dumps(v)))
except Exception:
    pass
' "$_key" 2>/dev/null)
  fi
  if [ -z "$_out" ] && command -v node >/dev/null 2>&1; then
    _out=$(printf '%s' "$_in" | node -e '
let b=""; process.stdin.on("data",c=>b+=c); process.stdin.on("end",()=>{try{const v=JSON.parse(b)[process.argv[1]]; console.log(v==null?"":(typeof v==="string"?v:JSON.stringify(v)))}catch{console.log("")}});
' "$_key" 2>/dev/null)
  fi
  printf '%s' "$_out"
}

agent_instance() {
  _id=$(json_field "$1" agent_id)
  _type=$(json_field "$1" agent_type)
  if [ -n "$_id" ] && [ "$_id" != "null" ]; then
    [ -z "$_type" ] || [ "$_type" = "null" ] && _type="subagent"
    printf '%s#%s' "$(printf '%s' "$_type" | tr -c 'A-Za-z0-9_.:-' '_')" "$(printf '%s' "$_id" | cut -c1-8)"
  else
    printf 'claude-code'
  fi
}
