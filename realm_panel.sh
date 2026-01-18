#!/usr/bin/env bash
set -Eeuo pipefail

# Realm Pro Panel Installer (v21)
# - Online: download GitHub tarball
# - Offline: use local zip/tar.gz placed next to this script

red(){ echo -e "\033[31m$*\033[0m"; }
green(){ echo -e "\033[32m$*\033[0m"; }
yellow(){ echo -e "\033[33m$*\033[0m"; }
blue(){ echo -e "\033[36m$*\033[0m"; }

REPO_OWNER="cyeinfpro"
REPO_NAME="Realm"
REPO_BRANCH="main"
ARCHIVE_URL="https://github.com/${REPO_OWNER}/${REPO_NAME}/archive/refs/heads/${REPO_BRANCH}.tar.gz"

PANEL_DIR="/opt/realm-panel"
ENV_FILE="/etc/realm-panel/env"
SERVICE_FILE="/etc/systemd/system/realm-panel.service"
PANEL_PORT_DEFAULT=6080

need_cmd(){ command -v "$1" >/dev/null 2>&1 || { red "[ERR] 缺少依赖命令: $1"; exit 1; }; }

ensure_root(){ if [[ ${EUID:-$(id -u)} -ne 0 ]]; then red "[ERR] 请使用 root 运行"; exit 1; fi; }

ask(){
  local prompt="$1"; local def="${2:-}"; local var
  if [[ -n "$def" ]]; then
    read -r -p "$prompt (默认 $def): " var || true
    echo "${var:-$def}"
  else
    read -r -p "$prompt: " var || true
    echo "$var"
  fi
}

ask_password(){
  local prompt="$1"; local var
  while true; do
    read -r -s -p "$prompt (必填): " var || true
    echo
    if [[ -n "$var" ]]; then
      echo "$var"; return 0
    fi
    yellow "[提示] 密码不能为空，请重试"
  done
}

extract_from_archive(){
  local src="$1"
  local tmp="$2"
  tar -xzf "$src" -C "$tmp"
}

find_panel_dir(){
  local root="$1"
  local req
  req=$(find "$root" -maxdepth 5 -type f -path "*/panel/requirements.txt" -print -quit || true)
  if [[ -n "$req" ]]; then
    dirname "$req"
    return 0
  fi
  local pdir
  pdir=$(find "$root" -maxdepth 5 -type d -name panel -print -quit || true)
  if [[ -n "$pdir" ]]; then
    echo "$pdir"
    return 0
  fi
  return 1
}

main(){
  ensure_root
  need_cmd curl
  need_cmd tar
  need_cmd python3

  clear || true
  blue "Realm Pro Panel Installer v21"
  echo "------------------------------------------------------------"

  local mode
  echo "1) 在线安装（推荐）"
  echo "2) 离线安装（手动下载）"
  read -r -p "请选择安装模式 [1-2] (默认 1): " mode || true
  mode=${mode:-1}

  local tmp
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' EXIT

  local archive="$tmp/repo.tar.gz"

  if [[ "$mode" == "2" ]]; then
    yellow "[离线模式] 你需要先手动下载仓库压缩包："
    echo "  - ${ARCHIVE_URL}"
    echo
    echo "然后把它保存为：/root/${REPO_NAME}.tar.gz"
    echo "保存完成后再继续。"
    read -r -p "按回车键继续..." _ || true

    if [[ ! -f "/root/${REPO_NAME}.tar.gz" ]]; then
      red "[ERR] 未找到 /root/${REPO_NAME}.tar.gz"
      exit 1
    fi
    cp -f "/root/${REPO_NAME}.tar.gz" "$archive"
  else
    yellow "[提示] 正在下载仓库..."
    if ! curl -fsSL -L "$ARCHIVE_URL" -o "$archive"; then
      red "[ERR] 下载失败：$ARCHIVE_URL"
      red "[ERR] 若你的机器无法访问 github.com，请使用离线模式"
      exit 1
    fi
  fi

  yellow "[提示] 解压中..."
  extract_from_archive "$archive" "$tmp"

  local pdir
  if ! pdir=$(find_panel_dir "$tmp"); then
    red "[ERR] 找不到 panel 目录。请确认仓库里包含 panel/"
    yellow "[调试] 解压后的目录结构："
    find "$tmp" -maxdepth 3 -type d -print | sed 's#^#  - #' || true
    exit 1
  fi

  green "[OK] panel 目录：$pdir"

  # Ask credentials
  local admin_user admin_pass panel_port
  admin_user=$(ask "设置面板登录用户名" "admin")
  admin_pass=$(ask_password "设置面板登录密码")
  panel_port=$(ask "面板端口" "$PANEL_PORT_DEFAULT")

  # Install system deps
  yellow "[提示] 安装依赖..."
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y >/dev/null 2>&1 || true
  apt-get install -y python3-venv python3-pip ca-certificates >/dev/null 2>&1 || true

  # Deploy
  yellow "[提示] 部署到 $PANEL_DIR ..."
  rm -rf "$PANEL_DIR"
  mkdir -p "$PANEL_DIR"
  cp -a "$pdir"/* "$PANEL_DIR"/

  # Venv
  yellow "[提示] 创建虚拟环境..."
  python3 -m venv "$PANEL_DIR/venv"
  "$PANEL_DIR/venv/bin/pip" install -U pip >/dev/null
  "$PANEL_DIR/venv/bin/pip" install -r "$PANEL_DIR/requirements.txt" >/dev/null

  # Generate password hash
  local pass_hash
  pass_hash=$(
    "$PANEL_DIR/venv/bin/python" - <<PY
from passlib.context import CryptContext
ctx = CryptContext(schemes=['bcrypt'], deprecated='auto')
print(ctx.hash(${admin_pass@Q}))
PY
  )

  # Env
  mkdir -p "$(dirname "$ENV_FILE")"
  cat > "$ENV_FILE" <<EENV
PANEL_PORT=$panel_port
ADMIN_USER=$admin_user
ADMIN_PASS_HASH=$pass_hash
SESSION_SECRET=$(python3 - <<'PY'
import secrets
print(secrets.token_urlsafe(32))
PY
)
DB_PATH=/opt/realm-panel/data/panel.db
EENV

  # systemd
  cat > "$SERVICE_FILE" <<EOFUNIT
[Unit]
Description=Realm Panel Web UI
After=network.target

[Service]
Type=simple
WorkingDirectory=$PANEL_DIR
EnvironmentFile=$ENV_FILE
ExecStart=$PANEL_DIR/venv/bin/uvicorn app.main:app --host 0.0.0.0 --port $panel_port
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
EOFUNIT

  systemctl daemon-reload
  systemctl enable --now realm-panel.service

  green "[OK] 面板已启动"
  echo "------------------------------------------------------------"
  echo "访问地址： http://$(hostname -I 2>/dev/null | awk '{print $1}' || echo 'SERVER_IP'):$panel_port"
  echo "用户名：$admin_user"
  echo "------------------------------------------------------------"
  echo
  systemctl status realm-panel --no-pager || true
}

main "$@"
