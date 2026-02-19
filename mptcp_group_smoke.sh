#!/usr/bin/env bash
set -euo pipefail

# Smoke test for fixed-port MPTCP group lifecycle:
# login -> create/save async -> poll job -> probe A->B->C->remote -> optional delete.

if ! command -v curl >/dev/null 2>&1; then
  echo "error: curl is required" >&2
  exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
  echo "error: python3 is required" >&2
  exit 1
fi

usage() {
  cat <<'EOF'
Usage:
  PANEL_URL=http://127.0.0.1:6080 \
  PANEL_USER=admin \
  PANEL_PASS=your_password \
  SENDER_NODE_ID=1 \
  MEMBER_NODE_IDS=2,3 \
  AGGREGATOR_NODE_ID=4 \
  REMOTES=203.0.113.10:443,198.51.100.8:443 \
  ./scripts/mptcp_group_smoke.sh

Required env:
  PANEL_URL            Panel base URL, e.g. http://127.0.0.1:6080
  PANEL_USER           Panel login username
  PANEL_PASS           Panel login password
  SENDER_NODE_ID       A node id
  MEMBER_NODE_IDS      B node ids (comma-separated, at least 2)
  AGGREGATOR_NODE_ID   C node id
  REMOTES              Final targets (comma or newline separated host:port)

Optional env:
  SYNC_ID              explicit sync id (default: smoke_<timestamp>)
  SCHEDULER            aggregate|backup|hybrid (default: aggregate)
  LISTEN               sender listen (default: 0.0.0.0:38443)
  AGGREGATOR_HOST      override C host
  AGGREGATOR_PORT      override C port
  FAILOVER_RTT_MS      non-negative int
  FAILOVER_JITTER_MS   non-negative int
  FAILOVER_LOSS_PCT    0-100 float
  DELETE_AFTER_PROBE   1 to delete group after probe (default: 0)
  TIMEOUT_SEC          job wait timeout (default: 240)
  POLL_INTERVAL_SEC    poll interval (default: 2)
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

req_env=(PANEL_URL PANEL_USER PANEL_PASS SENDER_NODE_ID MEMBER_NODE_IDS AGGREGATOR_NODE_ID REMOTES)
for k in "${req_env[@]}"; do
  if [[ -z "${!k:-}" ]]; then
    echo "error: missing env $k" >&2
    usage >&2
    exit 1
  fi
done

PANEL_URL="${PANEL_URL%/}"
SYNC_ID="${SYNC_ID:-smoke_$(date +%s)}"
SCHEDULER="${SCHEDULER:-aggregate}"
LISTEN="${LISTEN:-0.0.0.0:38443}"
DELETE_AFTER_PROBE="${DELETE_AFTER_PROBE:-0}"
TIMEOUT_SEC="${TIMEOUT_SEC:-240}"
POLL_INTERVAL_SEC="${POLL_INTERVAL_SEC:-2}"

cookie_jar="$(mktemp -t mptcp-smoke-cookie.XXXXXX)"
trap 'rm -f "$cookie_jar"' EXIT

request_json() {
  local method="$1"
  local path="$2"
  local body="${3:-}"
  local tmp
  tmp="$(mktemp -t mptcp-smoke-body.XXXXXX)"
  local code
  if [[ "$method" == "GET" ]]; then
    code="$(curl -sS -o "$tmp" -w "%{http_code}" -b "$cookie_jar" -c "$cookie_jar" "${PANEL_URL}${path}")"
  else
    code="$(curl -sS -o "$tmp" -w "%{http_code}" -b "$cookie_jar" -c "$cookie_jar" \
      -H "Content-Type: application/json" -X "$method" "${PANEL_URL}${path}" --data "$body")"
  fi
  local resp
  resp="$(cat "$tmp")"
  rm -f "$tmp"
  if [[ "$code" -lt 200 || "$code" -ge 300 ]]; then
    echo "error: HTTP $code ${method} ${path}" >&2
    echo "$resp" >&2
    return 1
  fi
  printf '%s' "$resp"
}

poll_job() {
  local job_id="$1"
  local start
  start="$(date +%s)"
  while true; do
    local now
    now="$(date +%s)"
    if (( now - start > TIMEOUT_SEC )); then
      echo "error: job ${job_id} timed out after ${TIMEOUT_SEC}s" >&2
      return 1
    fi

    local resp
    resp="$(request_json GET "/api/sync_jobs/${job_id}")"
    local line
    line="$(printf '%s' "$resp" | python3 -c 'import json,sys; d=json.load(sys.stdin); j=d.get("job") or {}; print("|".join([str(j.get("status","")), str(j.get("attempts",0)), str(j.get("max_attempts",0)), str(j.get("error",""))]))')"
    local status attempts max_attempts err
    status="${line%%|*}"
    local rest="${line#*|}"
    attempts="${rest%%|*}"
    rest="${rest#*|}"
    max_attempts="${rest%%|*}"
    err="${rest#*|}"
    echo "job=${job_id} status=${status} attempts=${attempts}/${max_attempts}"

    if [[ "$status" == "success" ]]; then
      printf '%s' "$resp"
      return 0
    fi
    if [[ "$status" == "error" ]]; then
      echo "error: job ${job_id} failed: ${err}" >&2
      echo "$resp" >&2
      return 1
    fi
    sleep "$POLL_INTERVAL_SEC"
  done
}

echo "[1/6] login ${PANEL_URL}"
curl -sS -L -o /dev/null -b "$cookie_jar" -c "$cookie_jar" \
  -X POST "${PANEL_URL}/login" \
  --data-urlencode "username=${PANEL_USER}" \
  --data-urlencode "password=${PANEL_PASS}"

nodes_resp="$(request_json GET "/api/nodes")"
nodes_ok="$(printf '%s' "$nodes_resp" | python3 -c 'import json,sys; d=json.load(sys.stdin); print("1" if d.get("ok") else "0")')"
if [[ "$nodes_ok" != "1" ]]; then
  echo "error: login/session validation failed" >&2
  echo "$nodes_resp" >&2
  exit 1
fi

create_payload="$(python3 <<'PY'
import json, os, sys

def parse_ids(raw):
    out = []
    seen = set()
    for x in str(raw or "").replace(";", ",").split(","):
        x = x.strip()
        if not x:
            continue
        try:
            n = int(x)
        except Exception:
            continue
        if n <= 0 or n in seen:
            continue
        seen.add(n)
        out.append(n)
    return out

def parse_remotes(raw):
    out = []
    seen = set()
    text = str(raw or "").replace(",", "\n")
    for row in text.splitlines():
        v = row.strip()
        if not v or v in seen:
            continue
        seen.add(v)
        out.append(v)
    return out

sender = int(os.environ["SENDER_NODE_ID"])
members = parse_ids(os.environ["MEMBER_NODE_IDS"])
aggregator = int(os.environ["AGGREGATOR_NODE_ID"])
remotes = parse_remotes(os.environ["REMOTES"])
if len(members) < 2:
    raise SystemExit("MEMBER_NODE_IDS must contain at least 2 ids")
if aggregator <= 0:
    raise SystemExit("AGGREGATOR_NODE_ID must be > 0")
if not remotes:
    raise SystemExit("REMOTES must contain at least 1 target")

payload = {
    "sender_node_id": sender,
    "member_node_ids": members,
    "aggregator_node_id": aggregator,
    "listen": os.environ.get("LISTEN", "0.0.0.0:38443"),
    "remotes": remotes,
    "scheduler": os.environ.get("SCHEDULER", "aggregate"),
    "protocol": "tcp",
    "balance": "roundrobin",
    "sync_id": os.environ.get("SYNC_ID", ""),
}

agg_host = str(os.environ.get("AGGREGATOR_HOST", "")).strip()
if agg_host:
    payload["aggregator_host"] = agg_host
agg_port = str(os.environ.get("AGGREGATOR_PORT", "")).strip()
if agg_port:
    payload["aggregator_port"] = int(agg_port)
rtt = str(os.environ.get("FAILOVER_RTT_MS", "")).strip()
if rtt:
    payload["failover_rtt_ms"] = int(rtt)
jitter = str(os.environ.get("FAILOVER_JITTER_MS", "")).strip()
if jitter:
    payload["failover_jitter_ms"] = int(jitter)
loss = str(os.environ.get("FAILOVER_LOSS_PCT", "")).strip()
if loss:
    payload["failover_loss_pct"] = float(loss)

print(json.dumps(payload, ensure_ascii=False))
PY
)"

echo "[2/6] submit mptcp save_async sync_id=${SYNC_ID}"
save_resp="$(request_json POST "/api/mptcp_tunnel/save_async" "$create_payload")"
save_job_id="$(printf '%s' "$save_resp" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(str(((d.get("job") or {}).get("job_id") or "")).strip())')"
if [[ -z "$save_job_id" ]]; then
  echo "error: save_async returned no job_id" >&2
  echo "$save_resp" >&2
  exit 1
fi

echo "[3/6] wait save job ${save_job_id}"
save_job_resp="$(poll_job "$save_job_id")"
echo "$save_job_resp" >/dev/null

probe_payload="$(python3 <<'PY'
import json, os
def parse_ids(raw):
    out, seen = [], set()
    for x in str(raw or "").replace(";", ",").split(","):
        x = x.strip()
        if not x:
            continue
        n = int(x)
        if n <= 0 or n in seen:
            continue
        seen.add(n)
        out.append(n)
    return out
payload = {
    "sync_id": os.environ["SYNC_ID"],
    "old_sender_node_id": int(os.environ["SENDER_NODE_ID"]),
    "sender_node_id": int(os.environ["SENDER_NODE_ID"]),
    "member_node_ids": parse_ids(os.environ["MEMBER_NODE_IDS"]),
    "aggregator_node_id": int(os.environ["AGGREGATOR_NODE_ID"]),
}
print(json.dumps(payload, ensure_ascii=False))
PY
)"

echo "[4/6] run group probe"
probe_resp="$(request_json POST "/api/mptcp_tunnel/group_probe" "$probe_payload")"
probe_ok="$(printf '%s' "$probe_resp" | python3 -c 'import json,sys; d=json.load(sys.stdin); print("1" if d.get("ok") else "0")')"
if [[ "$probe_ok" != "1" ]]; then
  echo "error: probe failed" >&2
  echo "$probe_resp" >&2
  exit 1
fi

echo "[5/6] probe summary"
printf '%s' "$probe_resp" | python3 -c '
import json,sys
d=json.load(sys.stdin)
s=(d.get("summary") or {})
print("overall:",
      "status="+str(s.get("status","")),
      "ok="+str(s.get("ok","")),
      "total="+str(s.get("total","")),
      "availability="+str(s.get("availability_pct",""))+"%")
for st in (d.get("stages") or []):
    ss=(st.get("summary") or {})
    print("stage:",
          str(st.get("stage","")),
          "status="+str(ss.get("status","")),
          "ok="+str(ss.get("ok",""))+"/"+str(ss.get("total","")),
          "avg_rtt="+str(ss.get("avg_rtt_ms","")))
'

if [[ "$DELETE_AFTER_PROBE" == "1" ]]; then
  delete_payload="$(python3 <<'PY'
import json, os
def parse_ids(raw):
    out, seen = [], set()
    for x in str(raw or "").replace(";", ",").split(","):
        x = x.strip()
        if not x:
            continue
        n = int(x)
        if n <= 0 or n in seen:
            continue
        seen.add(n)
        out.append(n)
    return out
payload = {
    "sync_id": os.environ["SYNC_ID"],
    "sender_node_id": int(os.environ["SENDER_NODE_ID"]),
    "member_node_ids": parse_ids(os.environ["MEMBER_NODE_IDS"]),
    "aggregator_node_id": int(os.environ["AGGREGATOR_NODE_ID"]),
    "receiver_node_id": int(os.environ["AGGREGATOR_NODE_ID"]),
}
print(json.dumps(payload, ensure_ascii=False))
PY
)"
  echo "[6/6] delete group after probe"
  del_resp="$(request_json POST "/api/mptcp_tunnel/delete_async" "$delete_payload")"
  del_job_id="$(printf '%s' "$del_resp" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(str(((d.get("job") or {}).get("job_id") or "")).strip())')"
  if [[ -z "$del_job_id" ]]; then
    echo "error: delete_async returned no job_id" >&2
    echo "$del_resp" >&2
    exit 1
  fi
  poll_job "$del_job_id" >/dev/null
  echo "done: create/probe/delete success sync_id=${SYNC_ID}"
else
  echo "[6/6] keep group (DELETE_AFTER_PROBE=0)"
  echo "done: create/probe success sync_id=${SYNC_ID}"
fi
