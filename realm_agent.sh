#!/usr/bin/env bash
set -euo pipefail

# Realm Pro Agent Installer v15
# Repo raw base (change this to your own repo):
REPO_RAW_BASE="https://raw.githubusercontent.com/cyeinfpro/Realm/refs/heads/main"
# Repo archive (faster & fewer requests):
REPO_ARCHIVE_URL="https://github.com/cyeinfpro/Realm/archive/refs/heads/main.tar.gz"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

info(){ echo -e "${GREEN}[INFO]${NC} $*"; }
warn(){ echo -e "${YELLOW}[WARN]${NC} $*"; }
err(){ echo -e "${RED}[ERR ]${NC} $*"; }

need_root(){
  if [[ "$(id -u)" -ne 0 ]]; then
    err "请使用 root 运行：sudo bash $0"
    exit 1
  fi
}

apt_install(){
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y --no-install-recommends \
    ca-certificates curl git python3 python3-venv python3-pip \
    jq iproute2
}

fetch_repo(){
  local tmpdir
  tmpdir="$(mktemp -d)"
  info "拉取仓库源码（归档下载）..."
  curl -fsSL "$REPO_ARCHIVE_URL" -o "$tmpdir/repo.tar.gz"
  tar -xzf "$tmpdir/repo.tar.gz" -C "$tmpdir"
  local root
  root="$(find "$tmpdir" -maxdepth 1 -type d -name 'Realm-*' | head -n 1)"
  if [[ -z "$root" ]]; then
    err "解压仓库失败"
    exit 1
  fi
  echo "$root"
}

rand_token(){
  python3 - <<'PY'
import secrets
print(secrets.token_urlsafe(24))
PY
}

main(){
  need_root
  info "Realm Pro Agent v15 安装开始"
  apt_install

  read -r -p "Agent API 监听端口 (默认 6080): " AGENT_PORT
  AGENT_PORT="${AGENT_PORT:-6080}"

  read -r -p "Agent Token (回车自动生成): " AGENT_TOKEN
  if [[ -z "$AGENT_TOKEN" ]]; then
    AGENT_TOKEN="$(rand_token)"
  fi

  local repo_root
  repo_root="$(fetch_repo)"

  if [[ ! -d "$repo_root/realm-pro-suite-v15/agent" ]]; then
    err "找不到 realm-pro-suite-v15/agent 目录。请确认你已将 v15 文件包上传到仓库。"
    err "预期路径：仓库根目录/realm-pro-suite-v15/agent"
    exit 1
  fi

  info "写入 Agent 文件到 /opt/realm-agent"
  rm -rf /opt/realm-agent
  mkdir -p /opt/realm-agent
  cp -r "$repo_root/realm-pro-suite-v15/agent"/* /opt/realm-agent/

  info "创建环境文件 /etc/realm-agent/agent.env"
  mkdir -p /etc/realm-agent
  cat > /etc/realm-agent/agent.env <<ENV
REALM_AGENT_HOST=0.0.0.0
REALM_AGENT_PORT=$AGENT_PORT
REALM_AGENT_TOKEN=$AGENT_TOKEN
# realm 配置位置（默认与旧脚本兼容）
REALM_RULES_PATH=/etc/realm/rules.json
REALM_TOML_PATH=/etc/realm/config.toml
ENV

  info "创建 Python venv"
  python3 -m venv /opt/realm-agent/venv
  /opt/realm-agent/venv/bin/pip install -U pip
  /opt/realm-agent/venv/bin/pip install -r /opt/realm-agent/requirements.txt

  info "安装 systemd 服务"
  cp /opt/realm-agent/systemd/realm-agent.service /etc/systemd/system/realm-agent.service
  systemctl daemon-reload
  systemctl enable realm-agent.service
  systemctl restart realm-agent.service

  echo
  echo -e "${GREEN}✅ Agent 安装完成${NC}"
  echo "- Agent API:  http://$(hostname -I | awk '{print $1}'):${AGENT_PORT}"
  echo "- Token:      ${AGENT_TOKEN}"
  echo "- 查看状态:   systemctl status realm-agent --no-pager"
  echo
  echo "下一步：到 Panel -> 添加节点，把上面的 API 地址 + Token 填进去即可。"
}

main "$@"
