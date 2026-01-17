#!/usr/bin/env bash
set -euo pipefail

# Realm Pro Panel Installer (v19)
# Web Panel to manage Realm Agent nodes.
#
# 如果你 fork 了仓库：只需要改下面 3 个变量即可。
REPO_OWNER="cyeinfpro"
REPO_NAME="Realm"
REPO_BRANCH="main"

ARCHIVE_URL="https://github.com/${REPO_OWNER}/${REPO_NAME}/archive/refs/heads/${REPO_BRANCH}.tar.gz"
GIT_URL="https://github.com/${REPO_OWNER}/${REPO_NAME}.git"

PANEL_HOME="/opt/realm-panel"
ETC_DIR="/etc/realm-panel"
SERVICE_FILE="/etc/systemd/system/realm-panel.service"

# ---- log helpers (ALL logs -> STDERR) ----
_red(){ echo -e "\033[31m$*\033[0m" >&2; }
_green(){ echo -e "\033[32m$*\033[0m" >&2; }
_yellow(){ echo -e "\033[33m$*\033[0m" >&2; }

need_root(){
  if [[ ${EUID} -ne 0 ]]; then
    _red "[ERR] 请用 root 运行：sudo bash realm_panel.sh"
    exit 1
  fi
}

have_cmd(){ command -v "$1" >/dev/null 2>&1; }

apt_install(){
  # best effort
  DEBIAN_FRONTEND=noninteractive apt-get update -y >/dev/null 2>&1 || true
  DEBIAN_FRONTEND=noninteractive apt-get install -y "$@" >/dev/null 2>&1 || true
}

ensure_tools(){
  local miss=()
  for c in curl tar python3; do
    have_cmd "$c" || miss+=("$c")
  done
  if ((${#miss[@]})); then
    _yellow "[INFO] 缺少工具：${miss[*]}，尝试自动安装..."
    apt_install curl ca-certificates tar python3 python3-venv python3-pip
  fi
  for c in curl tar python3; do
    have_cmd "$c" || { _red "[ERR] 缺少命令：$c（无法继续）"; exit 1; }
  done
}

TMPDIR_INSTALL=""
cleanup(){
  if [[ -n "${TMPDIR_INSTALL}" && -d "${TMPDIR_INSTALL}" ]]; then
    rm -rf "${TMPDIR_INSTALL}" || true
  fi
}
trap cleanup EXIT

find_root(){
  # Find extracted repo root that contains panel
  local base="$1"
  local hit
  hit="$(find "$base" -maxdepth 6 -type f -path '*/panel/requirements.txt' -print -quit 2>/dev/null || true)"
  if [[ -n "$hit" ]]; then
    echo "${hit%/panel/requirements.txt}"
    return 0
  fi
  hit="$(find "$base" -maxdepth 6 -type f -path '*/panel/app/main.py' -print -quit 2>/dev/null || true)"
  if [[ -n "$hit" ]]; then
    echo "${hit%/panel/app/main.py}"
    return 0
  fi
  return 1
}

download_by_archive(){
  local outdir="$1"
  local tgz="$outdir/src.tgz"
  curl -fsSL "$ARCHIVE_URL" -o "$tgz"
  tar -xzf "$tgz" -C "$outdir"
}

download_by_git(){
  local outdir="$1"
  have_cmd git || apt_install git
  have_cmd git || { _red "[ERR] git 不存在且安装失败，无法 fallback"; return 1; }
  git clone --depth 1 --branch "$REPO_BRANCH" "$GIT_URL" "$outdir/repo" >/dev/null 2>&1
}

pick_source(){
  TMPDIR_INSTALL="$(mktemp -d)"

  _yellow "[1/5] 下载面板文件..."

  local root=""
  # Try GitHub archive first (fast)
  if download_by_archive "$TMPDIR_INSTALL" >/dev/null 2>&1; then
    root="$(find_root "$TMPDIR_INSTALL" || true)"
  fi

  # Fallback: git clone (more reliable when archive is incomplete)
  if [[ -z "$root" ]]; then
    _yellow "[INFO] Archive 未找到 panel，尝试 git clone 方式..."
    rm -rf "$TMPDIR_INSTALL"/* || true
    if download_by_git "$TMPDIR_INSTALL" >/dev/null 2>&1; then
      root="$(find_root "$TMPDIR_INSTALL/repo" || true)"
    fi
  fi

  if [[ -z "$root" || ! -d "$root/panel" ]]; then
    _red "[ERR] 找不到 panel 目录。请确认仓库里包含 panel/requirements.txt"
    _red "[ERR] 期待路径：仓库根目录/panel"
    _red "[ERR] 当前仓库：${GIT_URL}  (branch: ${REPO_BRANCH})"
    exit 1
  fi

  echo "$root"
}

hash_password(){
  local pw="$1"
  python3 - <<PY
import base64, os, hashlib
pw = """$pw""".encode('utf-8')
it = 200000
salt = os.urandom(16)
dk = hashlib.pbkdf2_hmac('sha256', pw, salt, it)
print('pbkdf2_sha256$%d$%s$%s' % (
  it,
  base64.urlsafe_b64encode(salt).decode().rstrip('='),
  base64.urlsafe_b64encode(dk).decode().rstrip('='),
))
PY
}

install_panel(){
  local src_root="$1"

  mkdir -p "$PANEL_HOME" "$ETC_DIR" /var/log/realm-panel "$PANEL_HOME/data"

  _yellow "[2/5] 拷贝面板文件到 $PANEL_HOME ..."
  rm -rf "$PANEL_HOME/panel"
  cp -a "$src_root/panel" "$PANEL_HOME/panel"

  _yellow "[3/5] 创建 Python 虚拟环境并安装依赖..."
  apt_install python3-venv python3-pip ca-certificates curl

  python3 -m venv "$PANEL_HOME/venv"
  "$PANEL_HOME/venv/bin/pip" -q install --upgrade pip
  "$PANEL_HOME/venv/bin/pip" -q install -r "$PANEL_HOME/panel/requirements.txt"
}

write_config_and_service(){
  _yellow "[4/5] 写入配置 & Systemd 服务..."
  chmod 700 "$ETC_DIR"

  local port user pw hash secret
  read -rp "面板端口 (默认 6080) > " port
  port="${port:-6080}"

  while true; do
    read -rp "面板登录用户名 (默认 admin) > " user
    user="${user:-admin}"
    [[ -n "$user" ]] && break
  done

  while true; do
    read -rsp "面板登录密码（不会回显）> " pw
    echo
    [[ -n "$pw" ]] && break
    _red "密码不能为空"
  done

  hash="$(hash_password "$pw")"
  secret="$(python3 - <<'PY'
import secrets
print(secrets.token_hex(32))
PY
)"

  cat > "$ETC_DIR/env" <<ENV
PANEL_PORT=${port}
PANEL_USER=${user}
PANEL_PASS_HASH=${hash}
PANEL_SECRET=${secret}
ENV
  chmod 600 "$ETC_DIR/env"

  cat > "$SERVICE_FILE" <<'UNIT'
[Unit]
Description=Realm Panel Web Service
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/realm-panel/panel
EnvironmentFile=/etc/realm-panel/env
ExecStart=/bin/bash -lc '/opt/realm-panel/venv/bin/uvicorn app.main:app --host 0.0.0.0 --port ${PANEL_PORT}'
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
UNIT

  systemctl daemon-reload
  systemctl enable realm-panel >/dev/null 2>&1 || true
  systemctl restart realm-panel
}

show_done(){
  _yellow "[5/5] 完成"

  local ip
  ip="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"
  ip="${ip:-127.0.0.1}"

  local port
  port="$(grep -E '^PANEL_PORT=' "$ETC_DIR/env" 2>/dev/null | cut -d= -f2 || true)"
  port="${port:-6080}"

  _green "[OK] 面板已启动：http://${ip}:${port}"
  _green "[OK] 查看状态：systemctl status realm-panel --no-pager"
  _green "[OK] 查看日志：journalctl -u realm-panel -n 200 --no-pager"
}

main(){
  need_root
  ensure_tools

  local src_root
  src_root="$(pick_source)"
  install_panel "$src_root"
  write_config_and_service
  show_done
}

main "$@"
