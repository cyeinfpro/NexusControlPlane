#!/usr/bin/env bash
set -euo pipefail

export PATH="/opt/homebrew/opt/openssl@3/bin:/usr/local/opt/openssl@3/bin:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:${PATH}"

VERSION="v1-macos"
REPO_ZIP_URL_DEFAULT="https://nexus.infpro.me/nexus/archive/refs/heads/main.zip"
REPO_ZIP_URL_FALLBACK="https://github.com/cyeinfpro/NexusControlPlane/archive/refs/heads/main.zip"
DEFAULT_PORT="18700"
DEFAULT_HOST="0.0.0.0"
BASE_DIR="/usr/local/realm-agent"
AGENT_LABEL="com.realm.agent"
REVTUNNEL_LABEL="com.realm.agent.revtunnel"

info(){ printf "[提示] %s\n" "$*"; }
ok(){ printf "[OK] %s\n" "$*"; }
err(){ printf "[错误] %s\n" "$*" >&2; }

command_exists(){
  command -v "$1" >/dev/null 2>&1
}

fix_owner_mode(){
  local path="$1"
  local mode="${2:-}"
  [[ -n "${path}" ]] || return 0
  if [[ -n "${mode}" ]]; then
    chmod "${mode}" "${path}" >/dev/null 2>&1 || true
  fi
  chown root:wheel "${path}" >/dev/null 2>&1 || true
}

prepare_log_paths(){
  local p
  for p in "$@"; do
    [[ -n "${p}" ]] || continue
    touch "${p}" >/dev/null 2>&1 || true
    chmod 644 "${p}" >/dev/null 2>&1 || true
    chown root:wheel "${p}" >/dev/null 2>&1 || true
  done
}

validate_plist_file(){
  local plist="$1"
  [[ -f "${plist}" ]] || { err "找不到 launchd plist：${plist}"; return 1; }
  if command_exists plutil; then
    if ! plutil -lint "${plist}" >/dev/null 2>&1; then
      err "launchd plist 格式错误：${plist}"
      plutil -lint "${plist}" >&2 || true
      return 1
    fi
  fi
  return 0
}

console_uid(){
  local uid=""
  uid="$(stat -f %u /dev/console 2>/dev/null || true)"
  if [[ "${uid}" =~ ^[0-9]+$ ]]; then
    echo "${uid}"
    return 0
  fi
  return 1
}

bootstrap_launchdaemon(){
  local label="$1"
  local plist="$2"
  local program_path="${3:-}"

  [[ -n "${label}" ]] || { err "launchd label 不能为空"; return 1; }
  [[ -n "${plist}" ]] || { err "launchd plist 路径不能为空"; return 1; }
  if ! command_exists launchctl; then
    err "系统缺少 launchctl，无法托管服务"
    return 1
  fi

  validate_plist_file "${plist}" || return 1
  if [[ -n "${program_path}" && ! -x "${program_path}" ]]; then
    err "启动程序不可执行：${program_path}"
    return 1
  fi

  local targets=("system/${label}" "${label}")
  local cuid=""
  cuid="$(console_uid || true)"
  if [[ -n "${cuid}" ]]; then
    targets+=("gui/${cuid}/${label}" "user/${cuid}/${label}")
  fi

  local t
  for t in "${targets[@]}"; do
    launchctl bootout "${t}" >/dev/null 2>&1 || true
  done
  launchctl enable "system/${label}" >/dev/null 2>&1 || true

  local out=""
  if ! out="$(launchctl bootstrap system "${plist}" 2>&1)"; then
    sleep 1
    if ! out="$(launchctl bootstrap system "${plist}" 2>&1)"; then
      err "launchctl bootstrap 失败（${label}）：${out}"
      launchctl print "system/${label}" >/dev/null 2>&1 || true
      return 1
    fi
  fi

  launchctl enable "system/${label}" >/dev/null 2>&1 || true
  if ! out="$(launchctl kickstart -k "system/${label}" 2>&1)"; then
    err "launchctl kickstart 失败（${label}）：${out}"
    launchctl print "system/${label}" >/dev/null 2>&1 || true
    return 1
  fi
  return 0
}

need_root(){
  if [[ "$(id -u)" -ne 0 ]]; then
    err "请使用 root 运行（sudo -i / su -）"
    exit 1
  fi
}

ensure_macos(){
  if [[ "$(uname -s)" != "Darwin" ]]; then
    err "该安装脚本仅支持 macOS"
    exit 1
  fi
}

find_brew(){
  if command_exists brew; then
    command -v brew
    return 0
  fi
  if [[ -x /opt/homebrew/bin/brew ]]; then
    echo "/opt/homebrew/bin/brew"
    return 0
  fi
  if [[ -x /usr/local/bin/brew ]]; then
    echo "/usr/local/bin/brew"
    return 0
  fi
  return 1
}

run_brew(){
  local brew_bin
  brew_bin="$(find_brew || true)"
  if [[ -z "${brew_bin}" ]]; then
    return 127
  fi
  local run_user="${SUDO_USER:-}"
  if [[ "$(id -u)" -eq 0 ]]; then
    if [[ -z "${run_user}" || "${run_user}" == "root" ]]; then
      run_user="$(stat -f %Su "${brew_bin}" 2>/dev/null || true)"
    fi
    if [[ -n "${run_user}" && "${run_user}" != "root" ]]; then
      if command_exists sudo; then
        sudo -u "${run_user}" -H "${brew_bin}" "$@"
        return $?
      fi
      err "当前为 root，且缺少 sudo，无法以普通用户执行 brew"
      return 126
    fi
    err "当前为 root，无法确定可用的 brew 用户（可设置 SUDO_USER）"
    return 126
  fi
  "${brew_bin}" "$@"
}

ensure_python_runtime(){
  if ! command_exists python3; then
    return 1
  fi
  python3 -c "import venv,ssl,json" >/dev/null 2>&1
}

ensure_deps(){
  local missing=()
  command_exists curl || missing+=("curl")
  command_exists unzip || missing+=("unzip")
  command_exists jq || missing+=("jq")
  command_exists rsync || missing+=("rsync")
  command_exists openssl || missing+=("openssl")
  ensure_python_runtime || missing+=("python")

  if [[ ${#missing[@]} -eq 0 ]]; then
    ok "依赖已满足，跳过安装"
    return 0
  fi

  if ! find_brew >/dev/null 2>&1; then
    err "缺少依赖：${missing[*]}"
    err "未检测到 Homebrew，请先安装 Homebrew 后重试。"
    exit 1
  fi

  local formulas=()
  local item
  for item in "${missing[@]}"; do
    case "$item" in
      jq) formulas+=("jq") ;;
      rsync) formulas+=("rsync") ;;
      openssl) formulas+=("openssl@3") ;;
      python) formulas+=("python") ;;
      curl) formulas+=("curl") ;;
      unzip) formulas+=("unzip") ;;
    esac
  done

  if [[ ${#formulas[@]} -gt 0 ]]; then
    info "通过 Homebrew 安装依赖：${formulas[*]}"
    run_brew install "${formulas[@]}"
  fi

  if ! ensure_python_runtime; then
    err "python3 运行环境异常（缺少 venv/ssl），请修复后重试"
    exit 1
  fi

  for c in curl unzip jq rsync openssl; do
    if ! command_exists "$c"; then
      err "依赖安装后仍缺少命令：$c"
      exit 1
    fi
  done
}

normalize_port(){
  local p="${1:-}"
  if [[ "$p" =~ ^[0-9]+$ ]] && (( p >= 1 && p <= 65535 )); then
    echo "$p"
  else
    echo "$DEFAULT_PORT"
  fi
}

download_file(){
  local url="$1"
  local out="$2"
  local tmp="${out}.tmp"

  if [[ "$url" == file://* ]]; then
    local src="${url#file://}"
    [[ -f "$src" ]] || return 1
    cp -f "$src" "$out"
    return 0
  fi

  if curl -fL --max-redirs 8 --silent --show-error --retry 4 --retry-delay 1 --connect-timeout 10 --max-time 600 "$url" -o "$tmp"; then
    mv -f "$tmp" "$out"
    return 0
  fi
  rm -f "$tmp" || true
  return 1
}

fetch_repo_zip(){
  local out="$1"
  local primary="${REALM_AGENT_REPO_ZIP_URL:-$REPO_ZIP_URL_DEFAULT}"
  local fallback="${REPO_ZIP_URL_FALLBACK}"

  info "下载仓库 ZIP：$primary"
  if download_file "$primary" "$out"; then
    return 0
  fi
  if [[ "$fallback" != "$primary" ]]; then
    info "主地址失败，尝试备用地址：$fallback"
    if download_file "$fallback" "$out"; then
      return 0
    fi
  fi
  return 1
}

find_agent_dir(){
  local base="$1"
  local agent_dir
  agent_dir="$(find "$base" -maxdepth 6 -type d -name agent -print -quit)"
  if [[ -z "$agent_dir" ]]; then
    err "找不到 agent 目录，请确认 ZIP 内容正确"
    exit 1
  fi
  echo "$agent_dir"
}

write_env_files(){
  local host="$1"
  local port="$2"

  install -d -m 700 /etc/realm-agent
  install -d -m 755 /etc/realm

  if [[ ! -s /etc/realm-agent/api.key ]]; then
    if command_exists openssl; then
      openssl rand -hex 16 > /etc/realm-agent/api.key
    else
      date +%s | shasum | awk '{print $1}' > /etc/realm-agent/api.key
    fi
    chmod 600 /etc/realm-agent/api.key 2>/dev/null || true
  fi

  cat > /etc/realm-agent/agent.env <<EOF_AGENT_ENV
REALM_AGENT_HOST=${host}
REALM_AGENT_PORT=${port}
REALM_AGENT_SERVICE=${AGENT_LABEL}
REALM_AGENT_LAUNCHD_LABEL=${AGENT_LABEL}
EOF_AGENT_ENV
  chmod 600 /etc/realm-agent/agent.env 2>/dev/null || true

  if [[ -n "${REALM_PANEL_URL:-}" || -n "${REALM_AGENT_ID:-}" ]]; then
    cat > /etc/realm-agent/panel.env <<EOF_PANEL_ENV
REALM_PANEL_URL=${REALM_PANEL_URL:-}
REALM_AGENT_ID=${REALM_AGENT_ID:-0}
REALM_AGENT_HEARTBEAT_INTERVAL=${REALM_AGENT_HEARTBEAT_INTERVAL:-3}
REALM_AGENT_REPORT_INSECURE_TLS=${REALM_AGENT_REPORT_INSECURE_TLS:-0}
REALM_AGENT_REPORT_CA_FILE=${REALM_AGENT_REPORT_CA_FILE:-}
EOF_PANEL_ENV
    chmod 600 /etc/realm-agent/panel.env 2>/dev/null || true
  fi
}

write_start_script(){
  install -d -m 755 "$BASE_DIR"
  cat > "$BASE_DIR/start.sh" <<'EOF_START'
#!/usr/bin/env bash
set -euo pipefail

BASE="/usr/local/realm-agent"
AGENT_DIR="$BASE/agent"

if [[ -f /etc/realm-agent/panel.env ]]; then
  set -a
  # shellcheck disable=SC1091
  source /etc/realm-agent/panel.env
  set +a
fi
if [[ -f /etc/realm-agent/agent.env ]]; then
  set -a
  # shellcheck disable=SC1091
  source /etc/realm-agent/agent.env
  set +a
fi

HOST="${REALM_AGENT_HOST:-0.0.0.0}"
PORT="${REALM_AGENT_PORT:-18700}"

cd "$AGENT_DIR"
exec "$BASE/venv/bin/python" -m uvicorn app.main:app --host "$HOST" --port "$PORT" --workers 1
EOF_START
  fix_owner_mode "$BASE_DIR/start.sh" 755
}

write_agent_launchd(){
  cat > "/Library/LaunchDaemons/${AGENT_LABEL}.plist" <<EOF_PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>${AGENT_LABEL}</string>
  <key>ProgramArguments</key>
  <array>
    <string>${BASE_DIR}/start.sh</string>
  </array>
  <key>WorkingDirectory</key>
  <string>${BASE_DIR}/agent</string>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardOutPath</key>
  <string>/var/log/realm-agent.log</string>
  <key>StandardErrorPath</key>
  <string>/var/log/realm-agent.error.log</string>
</dict>
</plist>
EOF_PLIST
  fix_owner_mode "/Library/LaunchDaemons/${AGENT_LABEL}.plist" 644
  prepare_log_paths /var/log/realm-agent.log /var/log/realm-agent.error.log
}

restart_agent_launchd(){
  bootstrap_launchdaemon "${AGENT_LABEL}" "/Library/LaunchDaemons/${AGENT_LABEL}.plist" "${BASE_DIR}/start.sh"
}

setup_revtunnel_launchd(){
  if [[ "${REALM_AGENT_SETUP_REVTUNNEL:-1}" != "1" ]]; then
    return 0
  fi
  if [[ ! -f /etc/realm-agent/revtunnel.env ]]; then
    return 0
  fi

  cat > "$BASE_DIR/revtunnel.sh" <<'EOF_RT'
#!/usr/bin/env bash
set -euo pipefail

if [[ -f /etc/realm-agent/revtunnel.env ]]; then
  set -a
  # shellcheck disable=SC1091
  source /etc/realm-agent/revtunnel.env
  set +a
fi

PANEL_SSH_HOST="${PANEL_SSH_HOST:-}"
PANEL_SSH_PORT="${PANEL_SSH_PORT:-22}"
PANEL_SSH_USER="${PANEL_SSH_USER:-nexus-tunnel}"
REMOTE_BIND="${REMOTE_BIND:-127.0.0.1}"
REMOTE_PORT="${REMOTE_PORT:-28700}"
LOCAL_HOST="${LOCAL_HOST:-127.0.0.1}"
LOCAL_PORT="${LOCAL_PORT:-18700}"
SSH_KEY_FILE="${SSH_KEY_FILE:-/etc/realm-agent/tunnel/id_ed25519}"
KNOWN_HOSTS_FILE="${KNOWN_HOSTS_FILE:-/etc/realm-agent/tunnel/known_hosts}"
STRICT_HOST_KEY_CHECKING="${STRICT_HOST_KEY_CHECKING:-yes}"

[[ -n "$PANEL_SSH_HOST" ]] || { echo "PANEL_SSH_HOST 不能为空" >&2; exit 2; }
[[ -r "$SSH_KEY_FILE" ]] || { echo "SSH_KEY_FILE 不可读：$SSH_KEY_FILE" >&2; exit 2; }

exec /usr/bin/ssh -NT \
  -o BatchMode=yes \
  -o ExitOnForwardFailure=yes \
  -o ServerAliveInterval=15 \
  -o ServerAliveCountMax=3 \
  -o StrictHostKeyChecking="${STRICT_HOST_KEY_CHECKING}" \
  -o UserKnownHostsFile="${KNOWN_HOSTS_FILE}" \
  -i "${SSH_KEY_FILE}" \
  -p "${PANEL_SSH_PORT}" \
  -R "${REMOTE_BIND}:${REMOTE_PORT}:${LOCAL_HOST}:${LOCAL_PORT}" \
  "${PANEL_SSH_USER}@${PANEL_SSH_HOST}"
EOF_RT
  fix_owner_mode "$BASE_DIR/revtunnel.sh" 700

  cat > "/Library/LaunchDaemons/${REVTUNNEL_LABEL}.plist" <<EOF_RT_PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>${REVTUNNEL_LABEL}</string>
  <key>ProgramArguments</key>
  <array>
    <string>${BASE_DIR}/revtunnel.sh</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardOutPath</key>
  <string>/var/log/realm-agent-revtunnel.log</string>
  <key>StandardErrorPath</key>
  <string>/var/log/realm-agent-revtunnel.error.log</string>
</dict>
</plist>
EOF_RT_PLIST
  fix_owner_mode "/Library/LaunchDaemons/${REVTUNNEL_LABEL}.plist" 644
  prepare_log_paths /var/log/realm-agent-revtunnel.log /var/log/realm-agent-revtunnel.error.log

  bootstrap_launchdaemon "${REVTUNNEL_LABEL}" "/Library/LaunchDaemons/${REVTUNNEL_LABEL}.plist" "${BASE_DIR}/revtunnel.sh"
  ok "已启用反向隧道服务（${REVTUNNEL_LABEL}）"
}

probe_base_urls(){
  local host="$1"
  local port="$2"
  local out=()
  out+=("http://127.0.0.1:${port}")
  out+=("http://localhost:${port}")
  out+=("http://[::1]:${port}")

  if [[ -n "${host}" && "${host}" != "0.0.0.0" && "${host}" != "::" ]]; then
    if [[ "${host}" == \[*\] ]]; then
      out+=("http://${host}:${port}")
    elif [[ "${host}" == *:* ]]; then
      out+=("http://[${host}]:${port}")
    else
      out+=("http://${host}:${port}")
    fi
  fi

  printf '%s\n' "${out[@]}"
}

agent_api_get(){
  local host="$1"
  local port="$2"
  local api_key="$3"
  local path="$4"
  local out_file="$5"

  local base_url
  while IFS= read -r base_url; do
    [[ -n "${base_url}" ]] || continue
    if curl -fsS --connect-timeout 2 --max-time 5 -H "x-api-key: ${api_key}" "${base_url}${path}" -o "${out_file}" >/dev/null 2>&1; then
      return 0
    fi
  done < <(probe_base_urls "${host}" "${port}")
  return 1
}

verify_agent_runtime(){
  local host="$1"
  local port="$2"

  local api_key
  api_key="$(cat /etc/realm-agent/api.key 2>/dev/null || true)"
  if [[ -z "${api_key}" ]]; then
    err "安装后检查失败：缺少 /etc/realm-agent/api.key"
    exit 1
  fi

  local tmp_sys tmp_cert tmp_status tmp_report
  tmp_sys="$(mktemp)"
  tmp_cert="$(mktemp)"
  tmp_status="$(mktemp)"
  tmp_report="$(mktemp)"

  cleanup_verify(){
    rm -f "${tmp_sys}" "${tmp_cert}" "${tmp_status}" "${tmp_report}" >/dev/null 2>&1 || true
  }

  local ready=0
  local i=1
  while (( i <= 30 )); do
    if agent_api_get "${host}" "${port}" "${api_key}" "/api/v1/sys" "${tmp_sys}"; then
      ready=1
      break
    fi
    sleep 1
    i=$((i + 1))
  done
  if [[ "${ready}" != "1" ]]; then
    cleanup_verify
    err "安装后检查失败：Agent API 未就绪（/api/v1/sys）"
    exit 1
  fi

  if ! jq -e '.ok == true and (.cpu | type == "object") and (.mem | type == "object") and (.net | type == "object")' "${tmp_sys}" >/dev/null 2>&1; then
    cat "${tmp_sys}" >&2 || true
    cleanup_verify
    err "安装后检查失败：节点监控数据异常（/api/v1/sys）"
    exit 1
  fi

  if ! agent_api_get "${host}" "${port}" "${api_key}" "/api/v1/intranet/cert" "${tmp_cert}"; then
    cleanup_verify
    err "安装后检查失败：内网穿透证书接口不可用（/api/v1/intranet/cert）"
    exit 1
  fi
  if ! jq -e '.ok == true and (.cert_pem | type == "string") and ((.cert_pem | length) > 0)' "${tmp_cert}" >/dev/null 2>&1; then
    cat "${tmp_cert}" >&2 || true
    cleanup_verify
    err "安装后检查失败：内网穿透 TLS 证书未就绪"
    exit 1
  fi

  if ! agent_api_get "${host}" "${port}" "${api_key}" "/api/v1/intranet/status" "${tmp_status}"; then
    cleanup_verify
    err "安装后检查失败：内网穿透状态接口不可用（/api/v1/intranet/status）"
    exit 1
  fi
  if ! jq -e '.ok == true and (.status.summary | type == "object")' "${tmp_status}" >/dev/null 2>&1; then
    cat "${tmp_status}" >&2 || true
    cleanup_verify
    err "安装后检查失败：内网穿透状态结构异常"
    exit 1
  fi

  local panel_url="" panel_id="0" report_insecure="0"
  local allow_no_panel="${REALM_AGENT_ALLOW_NO_PANEL:-0}"
  if [[ -f /etc/realm-agent/panel.env ]]; then
    panel_url="$(grep -E '^REALM_PANEL_URL=' /etc/realm-agent/panel.env 2>/dev/null | tail -n1 | cut -d= -f2-)"
    panel_id="$(grep -E '^REALM_AGENT_ID=' /etc/realm-agent/panel.env 2>/dev/null | tail -n1 | cut -d= -f2-)"
    report_insecure="$(grep -E '^REALM_AGENT_REPORT_INSECURE_TLS=' /etc/realm-agent/panel.env 2>/dev/null | tail -n1 | cut -d= -f2-)"
  fi
  panel_url="$(echo "${panel_url:-}" | tr -d '\r' | sed 's/[[:space:]]*$//' | sed 's#/*$##')"
  panel_id="$(echo "${panel_id:-0}" | tr -d '\r' | sed 's/[[:space:]]*$//')"
  report_insecure="$(echo "${report_insecure:-0}" | tr -d '\r' | sed 's/[[:space:]]*$//' | tr '[:upper:]' '[:lower:]')"

  if [[ -z "${panel_url}" || ! "${panel_id}" =~ ^[0-9]+$ || "${panel_id}" -le 0 ]]; then
    if [[ "${allow_no_panel}" != "1" ]]; then
      cleanup_verify
      err "安装后检查失败：未绑定面板（REALM_PANEL_URL / REALM_AGENT_ID 缺失）"
      err "请使用面板 Join 命令安装，或在 /etc/realm-agent/panel.env 正确填写后重试"
      exit 1
    fi
  else
    local payload now_s
    now_s="$(date '+%Y-%m-%d %H:%M:%S')"
    payload="$(printf '{"node_id":%s,"ack_version":0,"agent_version":"bootstrap-check","report":{"ok":true,"time":"%s","info":{"ok":true}}}' "${panel_id}" "${now_s}")"

    if [[ "${report_insecure}" == "1" || "${report_insecure}" == "true" || "${report_insecure}" == "yes" || "${report_insecure}" == "on" || "${report_insecure}" == "y" ]]; then
      if ! curl -k -fsS --location --post301 --post302 --post303 --connect-timeout 3 --max-time 10 -H "x-api-key: ${api_key}" -H "Content-Type: application/json" --data "${payload}" "${panel_url}/api/agent/report" -o "${tmp_report}" >/dev/null 2>&1; then
        cleanup_verify
        err "安装后检查失败：无法上报面板（${panel_url}/api/agent/report）"
        exit 1
      fi
    else
      if ! curl -fsS --location --post301 --post302 --post303 --connect-timeout 3 --max-time 10 -H "x-api-key: ${api_key}" -H "Content-Type: application/json" --data "${payload}" "${panel_url}/api/agent/report" -o "${tmp_report}" >/dev/null 2>&1; then
        cleanup_verify
        err "安装后检查失败：无法上报面板（${panel_url}/api/agent/report）"
        err "若面板为自签证书，请在 panel.env 设置 REALM_AGENT_REPORT_INSECURE_TLS=1"
        exit 1
      fi
    fi
    if ! jq -e '.ok == true' "${tmp_report}" >/dev/null 2>&1; then
      cat "${tmp_report}" >&2 || true
      cleanup_verify
      err "安装后检查失败：面板上报接口返回异常"
      exit 1
    fi
  fi

  cleanup_verify
  ok "安装后检查通过：节点监控、内网穿透、面板上报可用"
}

install_agent_files(){
  local host="$1"
  local port="$2"
  local tmpdir
  tmpdir="$(mktemp -d)"

  cleanup(){
    local d="${tmpdir:-}"
    [[ -n "$d" ]] || return 0
    rm -rf "$d" >/dev/null 2>&1 || true
  }
  trap cleanup EXIT

  local repo_zip="$tmpdir/repo.zip"
  if ! fetch_repo_zip "$repo_zip"; then
    err "仓库 ZIP 下载失败"
    exit 1
  fi

  unzip -q "$repo_zip" -d "$tmpdir/extract"

  local agent_dir
  agent_dir="$(find_agent_dir "$tmpdir/extract")"
  info "发现 agent 目录：$agent_dir"

  install -d -m 755 "$BASE_DIR"
  rsync -a --delete "$agent_dir/" "$BASE_DIR/agent/"

  if [[ ! -x "$BASE_DIR/venv/bin/python" ]]; then
    python3 -m venv "$BASE_DIR/venv"
  fi

  "$BASE_DIR/venv/bin/python" -m pip install --upgrade pip setuptools wheel >/dev/null 2>&1 || true
  "$BASE_DIR/venv/bin/pip" install -r "$BASE_DIR/agent/requirements.txt"

  install -d -m 755 /etc/realm
  if [[ -f "$BASE_DIR/agent/pool_to_run.jq" ]]; then
    cp -f "$BASE_DIR/agent/pool_to_run.jq" /etc/realm/pool_to_run.jq
  fi

  write_env_files "$host" "$port"
  write_start_script
  write_agent_launchd
  restart_agent_launchd
  setup_revtunnel_launchd
}

get_ipv4(){
  python3 - <<'PY' 2>/dev/null || true
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
try:
    s.connect(("8.8.8.8", 80))
    print(s.getsockname()[0])
except Exception:
    pass
finally:
    s.close()
PY
}

main(){
  ensure_macos
  need_root

  echo "Realm Agent Installer (macOS) ${VERSION}"
  echo "------------------------------------------------------------"

  local host port
  host="${REALM_AGENT_HOST:-$DEFAULT_HOST}"
  port="$(normalize_port "${REALM_AGENT_PORT:-$DEFAULT_PORT}")"

  info "检查依赖..."
  ensure_deps

  info "安装/更新 Agent（macOS launchd 模式）..."
  install_agent_files "$host" "$port"
  info "执行安装后检查（节点监控 + 内网穿透）..."
  verify_agent_runtime "$host" "$port"

  local api_key ip
  api_key="$(cat /etc/realm-agent/api.key 2>/dev/null || true)"
  ip="$(get_ipv4)"
  if [[ -z "$ip" ]]; then
    ip="127.0.0.1"
  fi

  ok "Agent 已安装并启动"
  echo "- Agent URL:   http://${ip}:${port}"
  echo "- API Key:     ${api_key}"
  echo "- Service:     launchctl print system/${AGENT_LABEL}"
}

main "$@"
