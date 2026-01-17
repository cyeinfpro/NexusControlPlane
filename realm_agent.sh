#!/usr/bin/env bash
set -euo pipefail

# Realm Pro Agent Installer (v19)
# Agent provides HTTP API for managing local realm rules.
#
# 如果你 fork 了仓库：只需要改下面 3 个变量即可。
REPO_OWNER="cyeinfpro"
REPO_NAME="Realm"
REPO_BRANCH="main"

ARCHIVE_URL="https://github.com/${REPO_OWNER}/${REPO_NAME}/archive/refs/heads/${REPO_BRANCH}.tar.gz"
GIT_URL="https://github.com/${REPO_OWNER}/${REPO_NAME}.git"

AGENT_HOME="/opt/realm-agent"
ETC_DIR="/etc/realm-agent"
SERVICE_FILE="/etc/systemd/system/realm-agent.service"

# ---- log helpers (ALL logs -> STDERR) ----
_red(){ echo -e "\033[31m$*\033[0m" >&2; }
_green(){ echo -e "\033[32m$*\033[0m" >&2; }
_yellow(){ echo -e "\033[33m$*\033[0m" >&2; }

need_root(){
  if [[ ${EUID} -ne 0 ]]; then
    _red "[ERR] 请用 root 运行：sudo bash realm_agent.sh"
    exit 1
  fi
}

have_cmd(){ command -v "$1" >/dev/null 2>&1; }

apt_install(){
  DEBIAN_FRONTEND=noninteractive apt-get update -y >/dev/null 2>&1 || true
  DEBIAN_FRONTEND=noninteractive apt-get install -y "$@" >/dev/null 2>&1 || true
}

ensure_tools(){
  local miss=()
  for c in curl tar python3; do
    have_cmd "$c" || miss+=("$c")
  done

  if (( ${#miss[@]} > 0 )); then
    _yellow "[i] 缺少依赖：${miss[*]}，尝试自动安装..."
    apt_install curl ca-certificates tar python3 python3-venv python3-pip
  fi

  for c in curl tar python3; do
    if ! have_cmd "$c"; then
      _red "[ERR] 仍缺少命令：$c，请手动安装后重试"
      exit 1
    fi
  done
}

find_repo_root(){
  local base="$1"
  local p
  p="$(find "$base" -maxdepth 6 -type f -path '*/agent/requirements.txt' -print -quit 2>/dev/null || true)"
  if [[ -n "$p" ]]; then
    echo "${p%/agent/requirements.txt}"
    return 0
  fi

  p="$(find "$base" -maxdepth 6 -type f -path '*/agent/app/main.py' -print -quit 2>/dev/null || true)"
  if [[ -n "$p" ]]; then
    echo "${p%/agent/app/main.py}"
    return 0
  fi

  return 1
}

pick_source(){
  local tmpdir
  tmpdir="$(mktemp -d)"

  cleanup(){ rm -rf "$tmpdir"; }
  trap cleanup EXIT

  _yellow "[1/5] 下载 Agent 文件..."

  local tgz="$tmpdir/src.tgz"
  local root=""

  if curl -fsSL "$ARCHIVE_URL" -o "$tgz" >/dev/null 2>&1; then
    if tar -xzf "$tgz" -C "$tmpdir" >/dev/null 2>&1; then
      root="$(find_repo_root "$tmpdir" || true)"
    fi
  fi

  if [[ -z "$root" ]]; then
    _yellow "[i] archive 未找到 agent/，尝试 git clone..."
    apt_install git
    rm -rf "$tmpdir/repo" >/dev/null 2>&1 || true
    if git clone --depth 1 --branch "$REPO_BRANCH" "$GIT_URL" "$tmpdir/repo" >/dev/null 2>&1; then
      root="$(find_repo_root "$tmpdir/repo" || true)"
    fi
  fi

  if [[ -z "$root" ]]; then
    _red "[ERR] 找不到 agent 目录。请确认仓库里包含 agent/requirements.txt"
    exit 1
  fi

  if [[ ! -d "$root/agent" ]]; then
    _red "[ERR] 预期 agent 目录不存在：$root/agent"
    exit 1
  fi

  echo "$root"
}

install_agent(){
  local root="$1"

  _yellow "[2/5] 拷贝 Agent 文件到 ${AGENT_HOME} ..."
  rm -rf "$AGENT_HOME" >/dev/null 2>&1 || true
  mkdir -p "$AGENT_HOME"
  cp -a "$root/agent" "$AGENT_HOME/agent"

  # venv
  _yellow "[3/5] 安装依赖 ..."
  python3 -m venv "$AGENT_HOME/venv"
  "$AGENT_HOME/venv/bin/pip" install -U pip >/dev/null 2>&1 || true
  "$AGENT_HOME/venv/bin/pip" install -r "$AGENT_HOME/agent/requirements.txt"
}

write_config_and_service(){
  _yellow "[4/5] 配置 Agent & systemd ..."
  mkdir -p "$ETC_DIR"

  local token public_host port

  token="$(python3 - <<'PY'
import secrets
print(secrets.token_hex(16))
PY
)"

  read -r -p "Public Host (面板展示用，回车=自动) > " public_host || true
  public_host="${public_host:-}"

  read -r -p "Agent API 端口 (回车=18700) > " port || true
  port="${port:-18700}"

  cat > "$ETC_DIR/config.json" <<JSON
{
  "token": "${token}",
  "public_host": "${public_host}"
}
JSON

  cat > "$ETC_DIR/env" <<ENV
AGENT_PORT=${port}
REALM_AGENT_ETC=${ETC_DIR}
REALM_SERVICE=realm.service
ENV

  cat > "$SERVICE_FILE" <<UNIT
[Unit]
Description=Realm Agent API Service
After=network.target

[Service]
Type=simple
WorkingDirectory=${AGENT_HOME}/agent
EnvironmentFile=${ETC_DIR}/env
ExecStart=/bin/bash -lc '${AGENT_HOME}/venv/bin/uvicorn app.main:app --host 0.0.0.0 --port ${AGENT_PORT}'
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
UNIT

  systemctl daemon-reload
  systemctl enable realm-agent >/dev/null 2>&1 || true
  systemctl restart realm-agent

  _green "[OK] Agent Token：${token}"
  _yellow "     (添加节点时需要填到 Panel 的 token 字段)"
}

show_done(){
  _yellow "[5/5] 完成"

  local ip
  ip="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"
  ip="${ip:-127.0.0.1}"

  local port
  port="$(grep -E '^AGENT_PORT=' "$ETC_DIR/env" 2>/dev/null | cut -d= -f2 || true)"
  port="${port:-18700}"

  _green "[OK] Agent 已启动：http://${ip}:${port}"
  _green "[OK] 查看状态：systemctl status realm-agent --no-pager"
  _green "[OK] 查看日志：journalctl -u realm-agent -n 200 --no-pager"
}

main(){
  need_root
  ensure_tools

  local src_root
  src_root="$(pick_source)"
  install_agent "$src_root"
  write_config_and_service
  show_done
}

main "$@"
