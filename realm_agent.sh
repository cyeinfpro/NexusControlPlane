#!/usr/bin/env bash
set -Eeuo pipefail

# Realm Pro Agent Installer (v22)
# Fixes vs v21:
# - cleanup trap safe with set -u
# - ensure root & basic dependency checks

red(){ echo -e "\033[31m$*\033[0m"; }
green(){ echo -e "\033[32m$*\033[0m"; }
yellow(){ echo -e "\033[33m$*\033[0m"; }
blue(){ echo -e "\033[36m$*\033[0m"; }

REPO_OWNER="cyeinfpro"
REPO_NAME="Realm"
REPO_BRANCH="main"
ARCHIVE_URL="https://github.com/${REPO_OWNER}/${REPO_NAME}/archive/refs/heads/${REPO_BRANCH}.tar.gz"

AGENT_DIR="/opt/realm-agent"
ENV_FILE="/etc/realm-agent/env"
SERVICE_FILE="/etc/systemd/system/realm-agent.service"
AGENT_PORT_DEFAULT=18700

TMP_WORKDIR=""
cleanup(){
  if [[ -n "${TMP_WORKDIR:-}" && -d "${TMP_WORKDIR:-}" ]]; then
    rm -rf "${TMP_WORKDIR}" || true
  fi
}
trap cleanup EXIT

need_cmd(){ command -v "$1" >/dev/null 2>&1 || { red "[ERR] 缺少依赖命令: $1"; exit 1; }; }
ensure_root(){ if [[ ${EUID:-$(id -u)} -ne 0 ]]; then red "[ERR] 请使用 root 运行"; exit 1; fi; }

ask(){
  local prompt="$1" default="$2" ans
  read -r -p "$prompt (默认 $default): " ans || true
  ans=${ans:-$default}
  echo "$ans"
}

extract_from_archive(){
  local archive="$1" dest="$2"
  tar -xzf "$archive" -C "$dest"
}

find_agent_dir(){
  local root="$1"
  local req
  req=$(find "$root" -maxdepth 6 -type f -path "*/agent/requirements.txt" -print -quit 2>/dev/null || true)
  if [[ -n "$req" ]]; then
    dirname "$req"
    return 0
  fi
  local d
  d=$(find "$root" -maxdepth 6 -type d -name agent -print -quit 2>/dev/null || true)
  if [[ -n "$d" ]]; then
    echo "$d"
    return 0
  fi
  return 1
}

main(){
  ensure_root
  need_cmd curl
  need_cmd tar
  need_cmd python3

  blue "Realm Pro Agent Installer v22"
  echo "------------------------------------------------------------"

  TMP_WORKDIR=$(mktemp -d)
  local tmp="$TMP_WORKDIR"

  local archive="$tmp/repo.tar.gz"
  yellow "[提示] 正在下载仓库..." >&2
  if ! curl -fsSL -L "$ARCHIVE_URL" -o "$archive"; then
    red "[ERR] 下载失败：$ARCHIVE_URL"
    exit 1
  fi

  yellow "[提示] 解压中..." >&2
  extract_from_archive "$archive" "$tmp"

  local adir
  if ! adir=$(find_agent_dir "$tmp"); then
    red "[ERR] 找不到 agent 目录。请确认仓库里包含 agent/"
    exit 1
  fi
  green "[OK] agent 目录：$adir"

  local agent_port
  agent_port=$(ask "Agent 监听端口" "$AGENT_PORT_DEFAULT")

  yellow "[提示] 安装依赖..." >&2
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y >/dev/null 2>&1 || true
  apt-get install -y python3-venv python3-pip ca-certificates >/dev/null 2>&1 || true

  yellow "[提示] 部署到 $AGENT_DIR ..." >&2
  rm -rf "$AGENT_DIR"
  mkdir -p "$AGENT_DIR"
  cp -a "$adir"/* "$AGENT_DIR"/

  yellow "[提示] 创建虚拟环境..." >&2
  python3 -m venv "$AGENT_DIR/venv"
  "$AGENT_DIR/venv/bin/pip" install -U pip >/dev/null
  "$AGENT_DIR/venv/bin/pip" install -r "$AGENT_DIR/requirements.txt" >/dev/null

  local token
  token=$(python3 - <<'PY'
import secrets
print(secrets.token_urlsafe(24))
PY
)

  mkdir -p "$(dirname "$ENV_FILE")"
  umask 077
  cat > "$ENV_FILE" <<EENV
AGENT_PORT=$agent_port
AGENT_TOKEN=$token
REALM_CONFIG=/etc/realm/config.json
EENV

  cat > "$SERVICE_FILE" <<EOFUNIT
[Unit]
Description=Realm Agent API Service
After=network.target

[Service]
Type=simple
WorkingDirectory=$AGENT_DIR
EnvironmentFile=$ENV_FILE
ExecStart=$AGENT_DIR/venv/bin/uvicorn app.main:app --host 0.0.0.0 --port $agent_port
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
EOFUNIT

  systemctl daemon-reload
  systemctl enable --now realm-agent.service

  green "[OK] Agent 已启动"
  echo "------------------------------------------------------------"
  echo "Agent URL: http://$(hostname -I 2>/dev/null | awk '{print $1}' || echo 'SERVER_IP'):$agent_port"
  echo "Agent Token: $token"
  echo "------------------------------------------------------------"
  echo
  systemctl status realm-agent --no-pager || true
}

main "$@"
