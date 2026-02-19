from __future__ import annotations

import base64
import hashlib
import json
import os
import re
from datetime import datetime
from typing import Any, Dict, List, Optional
from urllib.parse import quote, urlencode, urlparse, urlsplit

from fastapi import APIRouter, Depends, File, Form, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
try:
    from cryptography.fernet import Fernet, InvalidToken
except Exception:
    Fernet = None
    InvalidToken = Exception

from ..auth import filter_nodes_for_user
from ..core.deps import require_login_page, require_role_page
from ..core.flash import flash, set_flash
from ..core.settings import DEFAULT_AGENT_PORT
from ..core.share import require_login_or_share_view_page, require_login_or_share_wall_page
from ..core.templates import templates
from ..clients.agent import AgentError, agent_get, agent_get_raw_stream, agent_post
from ..db import (
    add_task,
    add_audit_log,
    add_node,
    add_site,
    delete_node,
    delete_site,
    get_site,
    get_group_orders,
    get_node,
    get_panel_setting,
    list_tasks,
    list_sites,
    list_nodes,
    normalize_node_system_type,
    set_panel_setting,
    update_task,
    update_site,
)
from ..services.assets import (
    panel_asset_source,
    panel_bootstrap_base_url,
    panel_bootstrap_insecure_tls,
    panel_public_base_url,
)
from ..services.apply import node_verify_tls
from ..services.node_fetch import node_info_fetch_order, normalize_node_info_fetch_order
try:
    from ..services.panel_config import parse_bool_loose, setting_float, setting_int
except Exception:
    _TRUE_SET = {"1", "true", "yes", "on", "y"}
    _FALSE_SET = {"0", "false", "no", "off", "n"}

    def _cfg_env(names: Optional[list[str]]) -> str:
        for n in (names or []):
            name = str(n or "").strip()
            if not name:
                continue
            v = str(os.getenv(name) or "").strip()
            if v:
                return v
        return ""

    def parse_bool_loose(raw: Any, default: bool = False) -> bool:
        if raw is None:
            return bool(default)
        s = str(raw).strip().lower()
        if not s:
            return bool(default)
        if s in _TRUE_SET:
            return True
        if s in _FALSE_SET:
            return False
        return bool(default)

    def setting_int(
        key: str,
        default: int,
        lo: int,
        hi: int,
        env_names: Optional[list[str]] = None,
    ) -> int:
        raw = get_panel_setting(str(key or "").strip())
        v_raw: Any = raw
        if raw is None or str(raw).strip() == "":
            env_v = _cfg_env(env_names)
            v_raw = env_v if env_v else default
        try:
            v = int(float(str(v_raw).strip() or default))
        except Exception:
            v = int(default)
        if v < int(lo):
            v = int(lo)
        if v > int(hi):
            v = int(hi)
        return int(v)

    def setting_float(
        key: str,
        default: float,
        lo: float,
        hi: float,
        env_names: Optional[list[str]] = None,
    ) -> float:
        raw = get_panel_setting(str(key or "").strip())
        v_raw: Any = raw
        if raw is None or str(raw).strip() == "":
            env_v = _cfg_env(env_names)
            v_raw = env_v if env_v else default
        try:
            v = float(str(v_raw).strip() or default)
        except Exception:
            v = float(default)
        if v < float(lo):
            v = float(lo)
        if v > float(hi):
            v = float(hi)
        return float(v)
from ..services.node_status import is_report_fresh
from ..utils.crypto import generate_api_key
from ..utils.normalize import extract_ip_for_display, format_host_for_url, split_host_and_port

router = APIRouter()
_TZ_NAME_RE = re.compile(r"^[A-Za-z0-9._+\-/]{1,128}$")
_REMOTE_STORAGE_SETTING_KEY = "remote_storage_profiles"
_REMOTE_STORAGE_PROTOCOLS = {"smb", "nfs", "ftp", "sftp", "webdav", "rclone"}
_REMOTE_STORAGE_PLATFORMS = {"auto", "linux", "macos", "windows"}
_REMOTE_STORAGE_MACOS_MOUNT_ROOT = "/Users/Shared/realm-mount"
_REMOTE_STORAGE_MACOS_MOUNT_ROOT_LEGACY = "/private/var/realm-mount"
_DRIVE_LETTERS = {chr(i) for i in range(ord("A"), ord("Z") + 1)}
_WIN_ABS_PATH_RE = re.compile(r"^[A-Za-z]:[\\/].*")
_REMOTE_PROFILE_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_REMOTE_STORAGE_SITE_DOMAIN_PREFIX = "__remote_storage__:"
_REMOTE_STORAGE_UPLOAD_MAX_BYTES = 100 * 1024 * 1024
_REMOTE_STORAGE_MOUNT_STATUSES = {"unknown", "mounted", "unmounted", "error"}
_REMOTE_STORAGE_MOUNT_HTTP_TIMEOUT_SEC = 150.0
_REMOTE_STORAGE_PASSWORD_KEY_SETTING = "remote_storage_password_key"
_REMOTE_STORAGE_PASSWORD_ENV_KEYS = (
    "REALM_REMOTE_STORAGE_PASSWORD_KEY",
    "REALM_PANEL_SECRET_KEY",
)
_REMOTE_STORAGE_PASSWORD_ENC_PREFIX = "enc:v1:"


def _request_source_ip(request: Optional[Request]) -> str:
    req = request if isinstance(request, Request) else None
    if req is None:
        return ""
    try:
        xff = str(req.headers.get("x-forwarded-for") or "").strip()
        if xff:
            first = str(xff.split(",")[0] or "").strip()
            if first:
                return first[:255]
    except Exception:
        pass
    try:
        xr = str(req.headers.get("x-real-ip") or "").strip()
        if xr:
            return xr[:255]
    except Exception:
        pass
    try:
        host = str((req.client.host if req.client else "") or "").strip()
        if host:
            return host[:255]
    except Exception:
        pass
    return ""


def _audit_log_node_action(
    request: Optional[Request],
    user: str,
    action: str,
    node_id: int,
    node_name: str = "",
    detail: Optional[Dict[str, Any]] = None,
) -> None:
    try:
        add_audit_log(
            action=str(action or "").strip() or "unknown",
            actor=str(user or "").strip(),
            node_id=int(node_id or 0),
            node_name=str(node_name or "").strip(),
            detail=detail if isinstance(detail, dict) else {},
            source_ip=_request_source_ip(request),
        )
    except Exception:
        pass


def _as_bool(raw: Optional[str], default: bool = False) -> bool:
    if raw is None:
        return bool(default)
    s = str(raw).strip().lower()
    if not s:
        return bool(default)
    return s in ("1", "true", "yes", "on", "y")


def _clamp_int_text(raw: Any, lo: int, hi: int) -> str:
    s = str(raw or "").strip()
    if not s:
        return ""
    try:
        v = int(float(s))
    except Exception:
        return ""
    if v < int(lo):
        v = int(lo)
    if v > int(hi):
        v = int(hi)
    return str(int(v))


def _safe_int(raw: Any, default: int = 0) -> int:
    try:
        return int(raw)
    except Exception:
        try:
            return int(float(str(raw).strip()))
        except Exception:
            return int(default)


def _safe_float(raw: Any, default: float = 0.0) -> float:
    try:
        return float(raw)
    except Exception:
        try:
            return float(str(raw).strip())
        except Exception:
            return float(default)


def _clamp_float_text(raw: Any, lo: float, hi: float) -> str:
    s = str(raw or "").strip()
    if not s:
        return ""
    try:
        v = float(s)
    except Exception:
        return ""
    if v < float(lo):
        v = float(lo)
    if v > float(hi):
        v = float(hi)
    return f"{float(v):g}"


def _normalize_timezone_name(raw: Any, default: str = "Asia/Shanghai") -> str:
    s = str(raw or "").strip()
    if not s:
        return str(default or "Asia/Shanghai")
    if len(s) > 128:
        return str(default or "Asia/Shanghai")
    if not _TZ_NAME_RE.match(s):
        return str(default or "Asia/Shanghai")
    return s


def _safe_text(raw: Any, max_len: int = 255) -> str:
    s = str(raw or "").replace("\r", " ").replace("\n", " ").strip()
    if len(s) > int(max_len):
        s = s[: int(max_len)].strip()
    return s


def _normalize_remote_storage_key(raw: Any) -> str:
    text = str(raw or "").strip()
    if not text:
        return ""
    try:
        key_bytes = base64.urlsafe_b64decode(text.encode("ascii"))
        if len(key_bytes) == 32:
            return text
    except Exception:
        pass
    digest = hashlib.sha256(text.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii")


def _remote_storage_password_key() -> str:
    for env_name in _REMOTE_STORAGE_PASSWORD_ENV_KEYS:
        val = str(os.getenv(env_name) or "").strip()
        if val:
            return _normalize_remote_storage_key(val)
    raw = str(get_panel_setting(_REMOTE_STORAGE_PASSWORD_KEY_SETTING, "") or "").strip()
    if raw:
        return _normalize_remote_storage_key(raw)
    if Fernet is None:
        return ""
    try:
        key = Fernet.generate_key().decode("ascii")
        set_panel_setting(_REMOTE_STORAGE_PASSWORD_KEY_SETTING, key)
        return str(key)
    except Exception:
        return ""


def _remote_storage_password_encryptable() -> bool:
    if Fernet is None:
        return False
    return bool(_remote_storage_password_key())


def _remote_storage_encrypt_password(raw: Any) -> str:
    text = _safe_text(raw, max_len=128)
    if not text:
        return ""
    if Fernet is None:
        return ""
    key = _remote_storage_password_key()
    if not key:
        return ""
    try:
        token = Fernet(key.encode("ascii")).encrypt(text.encode("utf-8")).decode("ascii")
    except Exception:
        return ""
    return f"{_REMOTE_STORAGE_PASSWORD_ENC_PREFIX}{token}"


def _remote_storage_decrypt_password(raw: Any) -> str:
    text = _safe_text(raw, max_len=4096)
    if not text:
        return ""
    if text.startswith(_REMOTE_STORAGE_PASSWORD_ENC_PREFIX):
        text = text[len(_REMOTE_STORAGE_PASSWORD_ENC_PREFIX) :]
    if not text:
        return ""
    if Fernet is None:
        return ""
    key = _remote_storage_password_key()
    if not key:
        return ""
    try:
        plain = Fernet(key.encode("ascii")).decrypt(text.encode("ascii")).decode("utf-8", errors="ignore")
    except InvalidToken:
        return ""
    except Exception:
        return ""
    return _safe_text(plain, max_len=128)


def _normalize_remote_mount_status(raw: Any, default: str = "unknown") -> str:
    s = _safe_text(raw, max_len=16).lower()
    if s in _REMOTE_STORAGE_MOUNT_STATUSES:
        return s
    return str(default or "unknown")


def _remote_mount_status_label(raw: Any) -> str:
    s = _normalize_remote_mount_status(raw, default="unknown")
    if s == "mounted":
        return "已挂载"
    if s == "unmounted":
        return "未挂载"
    if s == "error":
        return "挂载异常"
    return "未知"


def _remote_mount_status_class(raw: Any) -> str:
    s = _normalize_remote_mount_status(raw, default="unknown")
    if s == "mounted":
        return "ok"
    if s == "error":
        return "bad"
    if s == "unmounted":
        return "warn"
    return "ghost"


def _normalize_remote_profile_id(raw: Any, default: str = "") -> str:
    s = _safe_text(raw, max_len=64)
    if not s:
        return str(default or "")
    if not _REMOTE_PROFILE_ID_RE.match(s):
        return str(default or "")
    return s


def _safe_path(raw: Any, max_len: int = 255) -> str:
    s = str(raw or "").strip()
    if not s:
        return ""
    s = s.replace("\r", "").replace("\n", "")
    if len(s) > int(max_len):
        s = s[: int(max_len)].strip()
    return s


def _remote_storage_path_leaf(raw: Any) -> str:
    text = _safe_path(raw, max_len=255).replace("\\", "/")
    if not text:
        return ""
    segs = [str(seg or "").strip() for seg in text.split("/") if str(seg or "").strip() not in ("", ".", "..")]
    if not segs:
        return ""
    return _safe_text(segs[-1], max_len=120)


def _remote_storage_mount_leaf_name(
    protocol: Any,
    share_path: Any,
    remote_path: Any,
    rclone_remote: Any,
    fallback: Any = "remote-storage",
) -> str:
    proto = _safe_text(protocol, max_len=24).lower()
    share_leaf = _remote_storage_path_leaf(share_path)
    remote_leaf = _remote_storage_path_leaf(remote_path)
    candidate = ""
    if proto in ("smb", "nfs") and share_leaf:
        candidate = share_leaf
    elif remote_leaf:
        candidate = remote_leaf
    elif share_leaf:
        candidate = share_leaf
    elif proto == "rclone":
        candidate = _safe_text(rclone_remote, max_len=96).split(":", 1)[0].strip()
    if not candidate:
        candidate = _safe_text(fallback, max_len=64) or "remote-storage"
    name = (
        _safe_text(candidate, max_len=120)
        .replace("/", "_")
        .replace("\\", "_")
        .replace(":", "_")
        .strip()
        .strip(".")
    )
    name = re.sub(r"[\x00-\x1f]+", "", name)
    name = re.sub(r"\s+", "-", name)
    name = re.sub(r"-{2,}", "-", name).strip("-")
    if len(name) > 120:
        name = name[:120].strip("-")
    if not name or name in (".", ".."):
        return "remote-storage"
    return name


def _remote_storage_default_macos_mount_point(
    protocol: Any,
    share_path: Any,
    remote_path: Any,
    rclone_remote: Any,
    fallback: Any = "remote-storage",
) -> str:
    leaf = _remote_storage_mount_leaf_name(
        protocol=protocol,
        share_path=share_path,
        remote_path=remote_path,
        rclone_remote=rclone_remote,
        fallback=fallback,
    )
    return f"{_REMOTE_STORAGE_MACOS_MOUNT_ROOT}/{leaf}"


def _remote_storage_profile_is_macos(profile: Dict[str, Any]) -> bool:
    p = profile if isinstance(profile, dict) else {}
    platform_pref = _safe_text(p.get("platform"), max_len=16).lower()
    if platform_pref == "macos":
        return True
    if platform_pref not in ("", "auto"):
        return False
    nid = max(0, _safe_int(p.get("target_node_id"), 0))
    if nid <= 0:
        return False
    try:
        node = get_node(int(nid))
    except Exception:
        node = None
    if not isinstance(node, dict):
        return False
    node_system = normalize_node_system_type((node or {}).get("system_type"), default="auto")
    return node_system == "macos"


def _remote_storage_effective_mount_point(profile: Dict[str, Any]) -> str:
    p = profile if isinstance(profile, dict) else {}
    mount_raw = _safe_path(p.get("mount_point"), max_len=255)
    if _remote_storage_profile_is_macos(p):
        return _remote_storage_default_macos_mount_point(
            protocol=p.get("protocol"),
            share_path=p.get("share_path"),
            remote_path=p.get("remote_path"),
            rclone_remote=p.get("rclone_remote"),
            fallback=p.get("name"),
        )
    legacy_root = f"{_REMOTE_STORAGE_MACOS_MOUNT_ROOT_LEGACY}/"
    if mount_raw.startswith(legacy_root):
        leaf = _safe_text(mount_raw[len(legacy_root) :], max_len=120)
        leaf = leaf.split("/", 1)[0].strip() or _remote_storage_mount_leaf_name(
            protocol=p.get("protocol"),
            share_path=p.get("share_path"),
            remote_path=p.get("remote_path"),
            rclone_remote=p.get("rclone_remote"),
            fallback=p.get("name"),
        )
        return f"{_REMOTE_STORAGE_MACOS_MOUNT_ROOT}/{leaf}"
    return mount_raw


def _normalize_backup_target_path(raw: Any) -> str:
    return _safe_path(raw, max_len=255)


def _is_abs_backup_target_path(raw: Any) -> bool:
    p = _normalize_backup_target_path(raw)
    if not p:
        return False
    if p.startswith("/"):
        return True
    if _WIN_ABS_PATH_RE.match(p):
        return True
    return False


def _format_ts_text(ts: Any) -> str:
    v = _safe_float(ts, 0.0)
    if v <= 0.0:
        return ""
    try:
        return datetime.fromtimestamp(v).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return ""


def _safe_shell_quote(raw: Any) -> str:
    s = str(raw or "")
    return "'" + s.replace("'", "'\"'\"'") + "'"


def _safe_ps_quote(raw: Any) -> str:
    s = str(raw or "").replace("'", "''")
    return f"'{s}'"


def _remote_proto_label(proto: Any) -> str:
    p = str(proto or "").strip().lower()
    labels = {
        "smb": "SMB/CIFS",
        "nfs": "NFS",
        "ftp": "FTP",
        "sftp": "SFTP/SSHFS",
        "webdav": "WebDAV",
        "rclone": "网盘/Rclone",
    }
    return labels.get(p, p or "-")


def _remote_platform_label(platform: Any) -> str:
    p = str(platform or "").strip().lower()
    labels = {
        "auto": "自动",
        "linux": "Linux",
        "macos": "macOS",
        "windows": "Windows",
    }
    return labels.get(p, p or "自动")


def _normalize_drive_letter(raw: Any, default: str = "Z") -> str:
    s = _safe_text(raw, max_len=4).replace(":", "").upper()
    if not s:
        s = str(default or "Z").strip().replace(":", "").upper()
    if not s:
        s = "Z"
    ch = s[0]
    if ch not in _DRIVE_LETTERS:
        ch = "Z"
    return ch


def _normalize_port(raw: Any) -> int:
    s = str(raw or "").strip()
    if not s:
        return 0
    try:
        v = int(float(s))
    except Exception:
        return -1
    if v < 0 or v > 65535:
        return -1
    return int(v)


def _load_remote_storage_profiles() -> List[Dict[str, Any]]:
    raw = str(get_panel_setting(_REMOTE_STORAGE_SETTING_KEY, "") or "").strip()
    if not raw:
        return []
    try:
        data = json.loads(raw)
    except Exception:
        return []
    if not isinstance(data, list):
        return []

    out: List[Dict[str, Any]] = []
    seen: set[str] = set()
    need_migrate_legacy_plain = False
    need_strip_legacy_site_id = False
    need_fill_macos_mount_point = False
    need_upgrade_macos_mount_root = False
    for item in data:
        if not isinstance(item, dict):
            continue
        pid = _normalize_remote_profile_id(item.get("id"))
        if not pid or pid in seen:
            continue
        seen.add(pid)
        proto = _safe_text(item.get("protocol"), max_len=32).lower()
        if proto not in _REMOTE_STORAGE_PROTOCOLS:
            continue
        port_v = _normalize_port(item.get("port"))
        if port_v < 0:
            port_v = 0
        platform = _safe_text(item.get("platform"), max_len=16).lower()
        if platform not in _REMOTE_STORAGE_PLATFORMS:
            platform = "auto"
        save_password = bool(item.get("save_password"))
        legacy_plain = _safe_text(item.get("password"), max_len=128) if save_password else ""
        password_enc = _safe_text(item.get("password_enc"), max_len=4096)
        mount_status = _normalize_remote_mount_status(item.get("mount_status"), default="unknown")
        mount_message = _safe_text(item.get("mount_message"), max_len=280)
        mounted_at = _safe_text(item.get("mounted_at"), max_len=32)
        password_text = ""
        if save_password and password_enc:
            password_text = _remote_storage_decrypt_password(password_enc)
        if save_password and not password_text and legacy_plain:
            password_text = legacy_plain
            if _remote_storage_password_encryptable():
                password_enc = _remote_storage_encrypt_password(password_text)
                if password_enc:
                    need_migrate_legacy_plain = True
        if "site_id" in item:
            need_strip_legacy_site_id = True
        mount_point = _safe_path(item.get("mount_point"), max_len=255)
        if platform == "macos" and not mount_point:
            mount_point = _remote_storage_default_macos_mount_point(
                protocol=proto,
                share_path=item.get("share_path"),
                remote_path=item.get("remote_path"),
                rclone_remote=item.get("rclone_remote"),
                fallback=item.get("name"),
            )
            need_fill_macos_mount_point = True
        legacy_root = f"{_REMOTE_STORAGE_MACOS_MOUNT_ROOT_LEGACY}/"
        if mount_point.startswith(legacy_root):
            leaf = _safe_text(mount_point[len(legacy_root) :], max_len=120).split("/", 1)[0].strip()
            if not leaf:
                leaf = _remote_storage_mount_leaf_name(
                    protocol=proto,
                    share_path=item.get("share_path"),
                    remote_path=item.get("remote_path"),
                    rclone_remote=item.get("rclone_remote"),
                    fallback=item.get("name"),
            )
            mount_point = f"{_REMOTE_STORAGE_MACOS_MOUNT_ROOT}/{leaf}"
            need_upgrade_macos_mount_root = True
            mount_status = "unmounted"
            mounted_at = ""
            mount_message = "挂载点已迁移至 /Users/Shared/realm-mount，请重新挂载"
        out.append(
            {
                "id": pid,
                "name": _safe_text(item.get("name"), max_len=64),
                "protocol": proto,
                "host": _safe_text(item.get("host"), max_len=128),
                "port": int(port_v),
                "share_path": _safe_path(item.get("share_path"), max_len=255),
                "mount_point": mount_point,
                "username": _safe_text(item.get("username"), max_len=64),
                "options": _safe_text(item.get("options"), max_len=240),
                "rclone_remote": _safe_text(item.get("rclone_remote"), max_len=96),
                "remote_path": _safe_path(item.get("remote_path"), max_len=255),
                "drive_letter": _normalize_drive_letter(item.get("drive_letter"), default="Z"),
                "password": password_text,
                "password_enc": password_enc,
                "save_password": bool(save_password and bool(password_text or password_enc)),
                "read_only": bool(item.get("read_only")),
                "auto_mount": bool(item.get("auto_mount")),
                "macos_desktop_link": False,
                "platform": platform,
                "target_node_id": max(0, _safe_int(item.get("target_node_id"), 0)),
                "note": _safe_text(item.get("note"), max_len=280),
                "mount_status": mount_status,
                "mount_message": mount_message,
                "mounted_at": mounted_at,
                "last_sync_at": _safe_text(item.get("last_sync_at"), max_len=32),
                "updated_at": _safe_text(item.get("updated_at"), max_len=32),
            }
        )
    out.sort(key=lambda x: str(x.get("updated_at") or ""), reverse=True)
    if (
        need_migrate_legacy_plain
        or need_strip_legacy_site_id
        or need_fill_macos_mount_point
        or need_upgrade_macos_mount_root
    ):
        try:
            _save_remote_storage_profiles(out)
        except Exception:
            pass
    return out


def _save_remote_storage_profiles(profiles: List[Dict[str, Any]]) -> None:
    rows = profiles if isinstance(profiles, list) else []
    clean_rows: List[Dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        item = dict(row)
        save_password = bool(item.get("save_password"))
        pwd_plain = _safe_text(item.get("password"), max_len=128) if save_password else ""
        pwd_enc = _safe_text(item.get("password_enc"), max_len=4096)
        item.pop("password", None)
        item.pop("password_enc", None)
        item.pop("site_id", None)
        if save_password:
            if pwd_plain:
                enc_new = _remote_storage_encrypt_password(pwd_plain)
                if enc_new:
                    pwd_enc = enc_new
            if pwd_enc:
                item["save_password"] = True
                item["password_enc"] = pwd_enc
            else:
                item["save_password"] = False
        else:
            item["save_password"] = False
        clean_rows.append(item)
    payload = json.dumps(clean_rows, ensure_ascii=False, separators=(",", ":"))
    set_panel_setting(_REMOTE_STORAGE_SETTING_KEY, payload)


def _build_remote_mount_commands(profile: Dict[str, Any]) -> Dict[str, str]:
    p = profile if isinstance(profile, dict) else {}
    proto = str(p.get("protocol") or "").strip().lower()
    host = _safe_text(p.get("host"), max_len=128)
    port = _normalize_port(p.get("port"))
    if port < 0:
        port = 0
    share_path = _safe_path(p.get("share_path"), max_len=255)
    remote_path = _safe_path(p.get("remote_path"), max_len=255)
    platform_pref = _safe_text(p.get("platform"), max_len=16).lower()
    mount_point = _safe_path(p.get("mount_point"), max_len=255)
    if not mount_point:
        if platform_pref == "macos":
            mount_point = _remote_storage_default_macos_mount_point(
                protocol=proto,
                share_path=share_path,
                remote_path=remote_path,
                rclone_remote=p.get("rclone_remote"),
                fallback=p.get("name"),
            )
        else:
            mount_point = "/mnt/remote"
    username = _safe_text(p.get("username"), max_len=64)
    options = _safe_text(p.get("options"), max_len=240)
    rclone_remote = _safe_text(p.get("rclone_remote"), max_len=96)
    drive_letter = _normalize_drive_letter(p.get("drive_letter"), default="Z")
    read_only = bool(p.get("read_only"))
    host_with_port = host if not host or port <= 0 else f"{host}:{int(port)}"
    path_with_lead = remote_path if remote_path.startswith("/") else ("/" + remote_path if remote_path else "/")
    share_clean = share_path.strip().strip("/").strip("\\")
    nfs_export = share_path.strip() or "/"
    if not nfs_export.startswith("/"):
        nfs_export = "/" + nfs_export

    linux_mount = ""
    linux_unmount = f"sudo umount {_safe_shell_quote(mount_point)}"
    mac_mount = ""
    mac_unmount = f"umount {_safe_shell_quote(mount_point)}"
    win_mount = ""
    win_unmount = f"Remove-PSDrive -Name {_safe_ps_quote(drive_letter)} -Force"

    if proto == "smb":
        smb_target = f"//{host}/{share_clean}" if host and share_clean else "//server/share"
        smb_opts = []
        if username:
            smb_opts.append(f"username={username}")
        smb_opts.append("password=$SMB_PASSWORD")
        smb_opts.append("iocharset=utf8")
        smb_opts.append("vers=3.0")
        if port > 0:
            smb_opts.append(f"port={port}")
        if read_only:
            smb_opts.append("ro")
        if options:
            smb_opts.append(options)
        linux_mount = (
            f"sudo mkdir -p {_safe_shell_quote(mount_point)} && "
            f"sudo mount -t cifs {_safe_shell_quote(smb_target)} {_safe_shell_quote(mount_point)} "
            f"-o {','.join(smb_opts)}"
        )
        user_part = f"{username}@" if username else ""
        mac_mount = (
            f"sudo umount -f {_safe_shell_quote(mount_point)} 2>/dev/null || true; "
            f"sudo diskutil unmount force {_safe_shell_quote(mount_point)} 2>/dev/null || true; "
            f"sudo mkdir -p {_safe_shell_quote(mount_point)} && "
            f"sudo chown \"$USER\":staff {_safe_shell_quote(mount_point)} && "
            f"mount_smbfs {_safe_shell_quote(f'//{user_part}{host_with_port}/{share_clean}')} "
            f"{_safe_shell_quote(mount_point)} && "
            f"ls -la {_safe_shell_quote(mount_point)}"
        )
        win_root = f"\\\\{host}\\{share_clean}" if host and share_clean else "\\\\server\\share"
        if username:
            win_mount = (
                f"$cred = Get-Credential -UserName {_safe_ps_quote(username)} -Message '输入 SMB 密码'; "
                f"New-PSDrive -Name {_safe_ps_quote(drive_letter)} -PSProvider FileSystem "
                f"-Root {_safe_ps_quote(win_root)} -Credential $cred -Persist"
            )
        else:
            win_mount = (
                f"New-PSDrive -Name {_safe_ps_quote(drive_letter)} -PSProvider FileSystem "
                f"-Root {_safe_ps_quote(win_root)} -Persist"
            )
    elif proto == "nfs":
        nfs_target = f"{host}:{nfs_export}" if host else "server:/export/path"
        nfs_opts = []
        if read_only:
            nfs_opts.append("ro")
        if options:
            nfs_opts.append(options)
        nfs_opt_text = f" -o {','.join(nfs_opts)}" if nfs_opts else ""
        linux_mount = (
            f"sudo mkdir -p {_safe_shell_quote(mount_point)} && "
            f"sudo mount -t nfs{nfs_opt_text} {_safe_shell_quote(nfs_target)} {_safe_shell_quote(mount_point)}"
        )
        mac_mount = (
            f"mkdir -p {_safe_shell_quote(mount_point)} && "
            f"mount -t nfs{nfs_opt_text} {_safe_shell_quote(nfs_target)} {_safe_shell_quote(mount_point)}"
        )
        share_win = nfs_export.strip("/").replace("/", "\\")
        win_mount = (
            f"mount -o anon \\\\{host}\\{share_win} {drive_letter}:"
            if host and share_win
            else "mount -o anon \\\\server\\export Z:"
        )
    elif proto == "ftp":
        ftp_url = f"ftp://{host_with_port}{path_with_lead}" if host_with_port else "ftp://server/path"
        user_opt = f"{username}:$FTP_PASSWORD" if username else "anonymous:"
        ftp_opts = [f"user={user_opt}"]
        if read_only:
            ftp_opts.append("ro")
        if options:
            ftp_opts.append(options)
        linux_mount = (
            f"sudo mkdir -p {_safe_shell_quote(mount_point)} && "
            f"curlftpfs {_safe_shell_quote(ftp_url)} {_safe_shell_quote(mount_point)} -o {','.join(ftp_opts)}"
        )
        mac_mount = (
            f"mkdir -p {_safe_shell_quote(mount_point)} && "
            f"curlftpfs {_safe_shell_quote(ftp_url)} {_safe_shell_quote(mount_point)} -o {','.join(ftp_opts)}"
        )
        win_mount = (
            "Windows 不建议直接挂载 FTP。建议先配置 rclone remote，"
            f"再执行：rclone mount remote:{path_with_lead} {drive_letter}: --network-mode"
        )
    elif proto == "sftp":
        sftp_target = f"{username + '@' if username else ''}{host}:{path_with_lead}" if host else "user@server:/path"
        sftp_opts = ["reconnect"]
        if port > 0:
            sftp_opts.append(f"port={port}")
        if read_only:
            sftp_opts.append("ro")
        if options:
            sftp_opts.append(options)
        linux_mount = (
            f"mkdir -p {_safe_shell_quote(mount_point)} && "
            f"sshfs {_safe_shell_quote(sftp_target)} {_safe_shell_quote(mount_point)} -o {','.join(sftp_opts)}"
        )
        mac_mount = (
            f"mkdir -p {_safe_shell_quote(mount_point)} && "
            f"sshfs {_safe_shell_quote(sftp_target)} {_safe_shell_quote(mount_point)} -o {','.join(sftp_opts)}"
        )
        win_mount = (
            "Windows 建议安装 WinFsp + SSHFS-Win 或直接使用 rclone："
            f"rclone mount remote:{path_with_lead} {drive_letter}: --network-mode"
        )
    elif proto == "webdav":
        scheme = "https" if port in (0, 443) else "http"
        webdav_url = f"{scheme}://{host_with_port}{path_with_lead}" if host_with_port else "https://server/webdav"
        linux_mount = (
            f"sudo mkdir -p {_safe_shell_quote(mount_point)} && "
            f"sudo mount -t davfs {_safe_shell_quote(webdav_url)} {_safe_shell_quote(mount_point)}"
        )
        mac_mount = (
            f"mkdir -p {_safe_shell_quote(mount_point)} && "
            f"mount_webdav {_safe_shell_quote(webdav_url)} {_safe_shell_quote(mount_point)}"
        )
        user_arg = f" /user:{username} *" if username else ""
        win_mount = f"net use {drive_letter}: {webdav_url}{user_arg}"
    else:
        remote = rclone_remote or "remote"
        remote_full = f"{remote}:{path_with_lead}"
        base_opts = ["--vfs-cache-mode", "writes"]
        if read_only:
            base_opts.append("--read-only")
        if options:
            base_opts.extend(options.split())
        linux_mount = f"rclone mount {remote_full} {_safe_shell_quote(mount_point)} {' '.join(base_opts)} --daemon"
        mac_mount = f"rclone mount {remote_full} {_safe_shell_quote(mount_point)} {' '.join(base_opts)} --daemon"
        win_mount = f"rclone mount {remote_full} {drive_letter}: {' '.join(base_opts)} --network-mode"
        linux_unmount = f"fusermount -u {_safe_shell_quote(mount_point)} || umount {_safe_shell_quote(mount_point)}"
        mac_unmount = f"umount {_safe_shell_quote(mount_point)}"
        win_unmount = (
            "Stop-Process -Name rclone -ErrorAction SilentlyContinue; "
            f"Remove-PSDrive -Name {_safe_ps_quote(drive_letter)} -Force -ErrorAction SilentlyContinue"
        )

    return {
        "linux_mount": linux_mount.strip(),
        "linux_unmount": linux_unmount.strip(),
        "macos_mount": mac_mount.strip(),
        "macos_unmount": mac_unmount.strip(),
        "windows_mount": win_mount.strip(),
        "windows_unmount": win_unmount.strip(),
    }


def _node_direct_tunnel_cfg(node: Dict[str, Any]) -> Dict[str, Any]:
    dt = (node or {}).get("direct_tunnel")
    if not isinstance(dt, dict):
        return {}
    listen_port = _safe_int(dt.get("listen_port"), 0)
    if listen_port < 1 or listen_port > 65535:
        listen_port = 0
    relay_node_id = max(0, _safe_int(dt.get("relay_node_id"), 0))
    scheme = str(dt.get("scheme") or "").strip().lower()
    if scheme not in ("http", "https"):
        scheme = ""
    return {
        "enabled": bool(dt.get("enabled")),
        "relay_node_id": int(relay_node_id),
        "listen_port": int(listen_port),
        "public_host": _safe_text(dt.get("public_host"), max_len=128),
        "scheme": scheme,
        "verify_tls": bool(dt.get("verify_tls")),
    }


def _direct_agent_request_target(node: Dict[str, Any]) -> tuple[str, bool]:
    dt = _node_direct_tunnel_cfg(node)
    if bool(dt.get("enabled")):
        relay_id = _safe_int(dt.get("relay_node_id"), 0)
        listen_port = _safe_int(dt.get("listen_port"), 0)
        if relay_id > 0 and 1 <= listen_port <= 65535:
            host = _safe_text(dt.get("public_host"), max_len=128)
            if not host:
                relay = get_node(relay_id)
                if isinstance(relay, dict):
                    relay_raw = str(relay.get("base_url") or "").strip()
                    if relay_raw:
                        if "://" not in relay_raw:
                            relay_raw = f"http://{relay_raw}"
                        try:
                            host = str(urlsplit(relay_raw).hostname or "").strip()
                        except Exception:
                            host = ""
            if host:
                scheme = str(dt.get("scheme") or "").strip().lower()
                if scheme not in ("http", "https"):
                    node_raw = str((node or {}).get("base_url") or "").strip()
                    if "://" not in node_raw:
                        node_raw = f"http://{node_raw}" if node_raw else "http://"
                    try:
                        scheme = str(urlsplit(node_raw).scheme or "http").strip().lower()
                    except Exception:
                        scheme = "http"
                    if scheme not in ("http", "https"):
                        scheme = "http"
                return (
                    f"{scheme}://{format_host_for_url(host)}:{int(listen_port)}",
                    bool(dt.get("verify_tls")),
                )
    return str((node or {}).get("base_url") or "").strip(), bool(node_verify_tls(node))


def _normalize_rel_path(raw: Any) -> str:
    s = str(raw or "").replace("\\", "/").strip().lstrip("/")
    if not s:
        return ""
    segs: List[str] = []
    for part in s.split("/"):
        p = str(part or "").strip()
        if not p or p == ".":
            continue
        if p == "..":
            raise ValueError("invalid path")
        segs.append(p)
    return "/".join(segs)


def _remote_profile_site_domain(profile_id: str) -> str:
    return f"{_REMOTE_STORAGE_SITE_DOMAIN_PREFIX}{_normalize_remote_profile_id(profile_id)}"


def _remote_profile_files_url_by_site(site_id: int, path: str = "") -> str:
    sid = max(0, _safe_int(site_id, 0))
    if sid <= 0:
        return "/remote-storage"
    base = f"/websites/{sid}/files"
    rel = ""
    if path:
        try:
            rel = _normalize_rel_path(path)
        except Exception:
            rel = ""
    if not rel:
        return base
    return f"{base}?{urlencode({'path': rel})}"


def _remote_profile_sites(profile_id: str) -> List[Dict[str, Any]]:
    pid = _normalize_remote_profile_id(profile_id)
    marker = _remote_profile_site_domain(pid)
    if not marker:
        return []
    out: List[Dict[str, Any]] = []
    try:
        rows = list_sites()
    except Exception:
        rows = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        if str(row.get("type") or "").strip().lower() != "storage_mount":
            continue
        domains = row.get("domains") if isinstance(row.get("domains"), list) else []
        if not any(str(d or "").strip() == marker for d in domains):
            continue
        out.append(row)
    out.sort(key=lambda x: _safe_int((x or {}).get("id"), 0), reverse=True)
    return out


def _ensure_remote_profile_site(profile: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    p = profile if isinstance(profile, dict) else {}
    pid = _normalize_remote_profile_id(p.get("id"))
    if not pid:
        return None
    node_id = max(0, _safe_int(p.get("target_node_id"), 0))
    if node_id <= 0:
        return None
    root_path = _remote_storage_profile_root_path(p)
    if not root_path:
        return None
    site_name = _safe_text(p.get("name"), max_len=64) or f"远程挂载-{pid[:8]}"
    marker = _remote_profile_site_domain(pid)
    if not marker:
        return None

    matched = _remote_profile_sites(pid)
    primary = matched[0] if matched else None
    for extra in matched[1:]:
        sid = max(0, _safe_int((extra or {}).get("id"), 0))
        if sid <= 0:
            continue
        try:
            delete_site(int(sid))
        except Exception:
            pass

    primary_id = max(0, _safe_int((primary or {}).get("id"), 0))
    primary_node_id = max(0, _safe_int((primary or {}).get("node_id"), 0))
    if primary_id > 0 and primary_node_id > 0 and primary_node_id != node_id:
        try:
            delete_site(int(primary_id))
        except Exception:
            pass
        primary_id = 0
        primary = None

    if primary_id > 0:
        try:
            update_site(
                int(primary_id),
                name=site_name,
                domains=[marker],
                root_path=root_path,
                proxy_target="",
                site_type="storage_mount",
                web_server="nginx",
                https_redirect=False,
                gzip_enabled=True,
                status="running",
            )
        except Exception:
            pass
        refreshed = get_site(int(primary_id))
        if isinstance(refreshed, dict):
            return refreshed
        return primary if isinstance(primary, dict) else None

    try:
        sid = add_site(
            node_id=int(node_id),
            name=site_name,
            domains=[marker],
            root_path=root_path,
            proxy_target="",
            site_type="storage_mount",
            web_server="nginx",
            nginx_tpl="",
            https_redirect=False,
            gzip_enabled=True,
            status="running",
        )
    except Exception:
        return None
    site = get_site(int(sid))
    return site if isinstance(site, dict) else None


def _purge_legacy_remote_profile_sites(profile_id: str = "") -> int:
    marker = _remote_profile_site_domain(profile_id) if _normalize_remote_profile_id(profile_id) else ""
    removed = 0
    try:
        rows = list_sites()
    except Exception:
        rows = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        if str(row.get("type") or "").strip().lower() != "storage_mount":
            continue
        domains = row.get("domains") if isinstance(row.get("domains"), list) else []
        matched = False
        for domain in domains:
            d = str(domain or "").strip()
            if not d.startswith(_REMOTE_STORAGE_SITE_DOMAIN_PREFIX):
                continue
            if marker and d != marker:
                continue
            matched = True
            break
        if not matched:
            continue
        sid = max(0, _safe_int(row.get("id"), 0))
        if sid <= 0:
            continue
        try:
            delete_site(int(sid))
            removed += 1
        except Exception:
            pass
    return int(removed)


def _request_has_nodes_write_permission(request: Optional[Request]) -> bool:
    req = request if isinstance(request, Request) else None
    perms = (req.session.get("user_permissions") if req and req.session else []) or []
    return ("*" in perms) or ("nodes.write" in perms) or ("nodes.*" in perms)


def _remote_storage_profile_root_path(profile: Dict[str, Any]) -> str:
    mount_root = _remote_storage_effective_mount_point(profile)
    if not mount_root:
        return ""
    if mount_root.startswith("/") or _WIN_ABS_PATH_RE.match(mount_root):
        return mount_root
    return ""


def _remote_storage_files_view_url(profile_id: str, path: str = "") -> str:
    pid = _normalize_remote_profile_id(profile_id)
    base = f"/remote-storage/profiles/{pid}/files/view" if pid else "/remote-storage"
    rel = ""
    if path:
        try:
            rel = _normalize_rel_path(path)
        except Exception:
            rel = ""
    if not rel:
        return base
    return f"{base}?{urlencode({'path': rel})}"


def _remote_storage_parent_path(path: str) -> str:
    rel = ""
    try:
        rel = _normalize_rel_path(path)
    except Exception:
        rel = ""
    if not rel:
        return ""
    segs = [s for s in rel.split("/") if s]
    if len(segs) <= 1:
        return ""
    return "/".join(segs[:-1])


def _format_bytes_h(num: Any) -> str:
    try:
        n = float(num)
    except Exception:
        return "-"
    if n < 1024:
        return f"{int(max(0.0, n))} B"
    for unit in ("KB", "MB", "GB", "TB"):
        n /= 1024.0
        if n < 1024:
            return f"{n:.1f} {unit}"
    return f"{n:.1f} PB"


def _download_content_disposition(filename: str) -> str:
    raw = str(filename or "download.bin").replace("\r", "").replace("\n", "").replace('"', "")
    if not raw:
        raw = "download.bin"
    ascii_name = "".join(
        ch if (("0" <= ch <= "9") or ("a" <= ch <= "z") or ("A" <= ch <= "Z") or ch in ("-", "_", "."))
        else "_"
        for ch in raw
    ).strip("._")
    if not ascii_name:
        ascii_name = "download.bin"
    return f"attachment; filename=\"{ascii_name}\"; filename*=UTF-8''{quote(raw, safe='')}"


def _download_response_headers(filename: str, content_length: Any = "") -> Dict[str, str]:
    headers = {
        "Content-Disposition": _download_content_disposition(filename),
        "Content-Encoding": "identity",
        "Cache-Control": "private, no-transform",
        "X-Accel-Buffering": "no",
        "Vary": "Accept-Encoding",
    }
    clen = str(content_length or "").strip()
    if clen.isdigit():
        headers["Content-Length"] = clen
    return headers


def _remote_mount_action_label(action: str) -> str:
    return "卸载" if str(action or "").strip().lower() == "unmount" else "挂载"


def _remote_mount_error_text(exc: Exception, action: str, timeout_sec: float) -> str:
    raw = str(exc or "").strip()
    if not raw:
        raw = str((exc or "").__class__.__name__ or "").strip() or "未知异常"
    low = raw.lower()
    cls = str((exc or "").__class__.__name__ or "").strip().lower()
    action_text = _remote_mount_action_label(action)
    timeout_hint = int(max(1.0, float(timeout_sec or _REMOTE_STORAGE_MOUNT_HTTP_TIMEOUT_SEC)))
    if ("timeout" in cls) or ("timed out" in low) or ("超时" in raw):
        return f"{action_text}超时（>{timeout_hint}s）：{raw}"
    if "connection" in low or "connect" in low or "nodename nor servname" in low:
        return f"{action_text}失败：节点连接异常（{raw}）"
    if isinstance(exc, AgentError):
        return raw
    return f"{action_text}失败：{raw}"


async def _apply_remote_profile_mount(
    profile: Dict[str, Any],
    node: Dict[str, Any],
    action: str = "mount",
    timeout_sec: float = _REMOTE_STORAGE_MOUNT_HTTP_TIMEOUT_SEC,
) -> tuple[bool, str]:
    if not isinstance(profile, dict) or not isinstance(node, dict):
        return False, "挂载参数无效"
    act = str(action or "mount").strip().lower()
    if act not in ("mount", "unmount"):
        return False, "不支持的操作"

    base_url, verify_tls = _direct_agent_request_target(node)
    if not base_url:
        return False, "节点地址为空"

    port_raw = _normalize_port(profile.get("port"))
    timeout_v = max(10.0, float(timeout_sec or _REMOTE_STORAGE_MOUNT_HTTP_TIMEOUT_SEC))
    payload: Dict[str, Any] = {
        "protocol": str(profile.get("protocol") or "").strip().lower(),
        "host": str(profile.get("host") or "").strip(),
        "port": int(port_raw if port_raw >= 0 else 0),
        "share_path": str(profile.get("share_path") or "").strip(),
        "remote_path": str(profile.get("remote_path") or "").strip(),
        "mount_point": str(profile.get("mount_point") or "").strip(),
        "username": str(profile.get("username") or "").strip(),
        "password": str(profile.get("password") or "").strip(),
        "options": str(profile.get("options") or "").strip(),
        "rclone_remote": str(profile.get("rclone_remote") or "").strip(),
        "read_only": bool(profile.get("read_only")),
    }
    endpoint = "/api/v1/storage/mount" if act == "mount" else "/api/v1/storage/unmount"

    try:
        data = await agent_post(
            base_url,
            str(node.get("api_key") or ""),
            endpoint,
            payload,
            verify_tls,
            timeout=timeout_v,
        )
    except Exception as exc:
        return False, _remote_mount_error_text(exc, act, timeout_v)

    if not isinstance(data, dict):
        return False, "节点返回异常"
    if not bool(data.get("ok")):
        action_text = _remote_mount_action_label(act)
        err_text = str(data.get("error") or "").strip()
        if not err_text:
            err_text = str(data.get("msg") or "").strip()
        if not err_text:
            err_text = f"{action_text}失败"
        return False, err_text
    return True, str(data.get("msg") or (f"{_remote_mount_action_label(act)}成功"))


def _attach_remote_profile_runtime(profile: Dict[str, Any], node_name_map: Dict[int, str]) -> None:
    p = profile if isinstance(profile, dict) else {}
    effective_mount = _remote_storage_effective_mount_point(p)
    if effective_mount:
        p["mount_point"] = effective_mount
    p["protocol_label"] = _remote_proto_label(p.get("protocol"))
    p["platform_label"] = _remote_platform_label(p.get("platform"))
    nid = _safe_int(p.get("target_node_id"), 0)
    p["target_node_name"] = node_name_map.get(nid, "") if nid > 0 else ""
    p["has_saved_password"] = bool(
        p.get("save_password")
        and (str(p.get("password") or "").strip() or str(p.get("password_enc") or "").strip())
    )
    p["mount_status"] = _normalize_remote_mount_status(p.get("mount_status"), default="unknown")
    p["mount_status_label"] = _remote_mount_status_label(p.get("mount_status"))
    p["mount_status_class"] = _remote_mount_status_class(p.get("mount_status"))
    p["commands"] = _build_remote_mount_commands(p)


def _find_remote_storage_profile(rows: List[Dict[str, Any]], profile_id: str) -> tuple[int, Optional[Dict[str, Any]]]:
    pid = _normalize_remote_profile_id(profile_id)
    if not pid:
        return -1, None
    for idx, row in enumerate(rows):
        if str((row or {}).get("id") or "") == pid:
            return idx, row if isinstance(row, dict) else None
    return -1, None


def _remote_profile_exec_with_password(profile: Dict[str, Any], password_override: Any = "") -> Dict[str, Any]:
    p = dict(profile if isinstance(profile, dict) else {})
    pwd = _safe_text(password_override, max_len=128)
    if not pwd:
        pwd = _safe_text(p.get("password"), max_len=128)
    if not pwd:
        pwd = _remote_storage_decrypt_password(p.get("password_enc"))
    p["password"] = pwd
    return p


def _update_remote_profile_mount_pending(profile_id: str, action: str, task_id: int) -> None:
    pid = _normalize_remote_profile_id(profile_id)
    if not pid:
        return
    rows = _load_remote_storage_profiles()
    idx, profile = _find_remote_storage_profile(rows, pid)
    if idx < 0 or not isinstance(profile, dict):
        return
    now_text = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    profile["last_sync_at"] = now_text
    profile["updated_at"] = now_text
    profile["mount_message"] = _safe_text(
        f"队列任务 #{int(task_id)} 已提交，等待节点上报后执行{_remote_mount_action_label(action)}…",
        max_len=280,
    )
    rows[idx] = profile
    rows.sort(key=lambda x: str(x.get("updated_at") or ""), reverse=True)
    _save_remote_storage_profiles(rows)


def _update_remote_profile_mount_result(profile_id: str, action: str, ok: bool, message: str) -> None:
    pid = _normalize_remote_profile_id(profile_id)
    if not pid:
        return
    rows = _load_remote_storage_profiles()
    idx, profile = _find_remote_storage_profile(rows, pid)
    if idx < 0 or not isinstance(profile, dict):
        return
    act = str(action or "mount").strip().lower()
    now_text = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    profile["last_sync_at"] = now_text
    profile["updated_at"] = now_text
    profile["mount_message"] = _safe_text(message, max_len=280)
    if bool(ok):
        if act == "unmount":
            profile["mount_status"] = "unmounted"
            profile["mounted_at"] = ""
        else:
            profile["mount_status"] = "mounted"
            profile["mounted_at"] = now_text
    else:
        profile["mount_status"] = "error"
    rows[idx] = profile
    rows.sort(key=lambda x: str(x.get("updated_at") or ""), reverse=True)
    _save_remote_storage_profiles(rows)


def _remote_profile_mount_request_payload(profile: Dict[str, Any], password_override: str = "") -> Dict[str, Any]:
    exec_profile = _remote_profile_exec_with_password(profile, password_override=password_override)
    port_raw = _normalize_port(exec_profile.get("port"))
    platform_pref = _safe_text(exec_profile.get("platform"), max_len=16).lower()
    mount_point = _remote_storage_effective_mount_point(exec_profile)
    pwd = str(exec_profile.get("password") or "").strip()
    pwd_enc = _remote_storage_encrypt_password(pwd) if pwd else ""
    pwd_plain = pwd if (pwd and not pwd_enc) else ""
    return {
        "protocol": str(exec_profile.get("protocol") or "").strip().lower(),
        "platform": platform_pref,
        "host": str(exec_profile.get("host") or "").strip(),
        "port": int(port_raw if port_raw >= 0 else 0),
        "share_path": str(exec_profile.get("share_path") or "").strip(),
        "remote_path": str(exec_profile.get("remote_path") or "").strip(),
        "mount_point": mount_point,
        "username": str(exec_profile.get("username") or "").strip(),
        "password": pwd_plain,
        "password_enc": pwd_enc,
        "options": str(exec_profile.get("options") or "").strip(),
        "rclone_remote": str(exec_profile.get("rclone_remote") or "").strip(),
        "read_only": bool(exec_profile.get("read_only")),
        "macos_desktop_link": False,
    }


def _enqueue_remote_profile_mount_task(
    profile_id: str,
    node_id: int,
    action: str = "mount",
    actor: str = "",
    password_override: str = "",
) -> tuple[int, bool, str]:
    pid = _normalize_remote_profile_id(profile_id)
    act = str(action or "mount").strip().lower()
    if not pid:
        return 0, False, "挂载方案不存在"
    if act not in ("mount", "unmount"):
        return 0, False, "不支持的操作"
    rows = _load_remote_storage_profiles()
    idx, profile = _find_remote_storage_profile(rows, pid)
    if idx < 0 or not isinstance(profile, dict):
        return 0, False, "挂载方案不存在或已删除"
    node_id_profile = _safe_int(profile.get("target_node_id"), 0)
    node_id_final = int(node_id_profile if node_id_profile > 0 else _safe_int(node_id, 0))
    if node_id_final <= 0:
        return 0, False, "目标节点无效"

    # Keep only the latest mount/unmount task for the same profile on the same node.
    # Otherwise old queued/retrying tasks may be dispatched after the user clicks again.
    try:
        old_rows = list_tasks(node_id=int(node_id_final), limit=400)
    except Exception:
        old_rows = []
    superseded = 0
    now_text = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    for row in old_rows:
        if not isinstance(row, dict):
            continue
        tid = _safe_int(row.get("id"), 0)
        if tid <= 0:
            continue
        t = str(row.get("type") or "").strip().lower()
        if t not in ("remote_storage_mount", "remote_storage_unmount"):
            continue
        st = str(row.get("status") or "").strip().lower()
        if st not in ("queued", "running"):
            continue
        p = row.get("payload") if isinstance(row.get("payload"), dict) else {}
        if _normalize_remote_profile_id(p.get("profile_id")) != pid:
            continue
        result_payload = row.get("result") if isinstance(row.get("result"), dict) else {}
        result_payload = dict(result_payload)
        result_payload.update(
            {
                "superseded": True,
                "superseded_at": now_text,
                "superseded_actor": str(actor or ""),
                "superseded_by_action": str(act),
                "superseded_profile_id": str(pid),
            }
        )
        try:
            update_task(
                int(tid),
                status="failed",
                progress=100,
                error="已被新的挂载/卸载请求替代",
                result=result_payload,
            )
            superseded += 1
        except Exception:
            continue

    request_payload = _remote_profile_mount_request_payload(profile, password_override=str(password_override or ""))
    op = f"remote_storage_{act}"
    task_id = int(
        add_task(
            node_id=int(node_id_final),
            task_type=op,
            payload={
                "profile_id": pid,
                "node_id": int(node_id_final),
                "action": act,
                "actor": str(actor or ""),
                "request": request_payload,
            },
            status="queued",
            progress=0,
            result={
                "op": op,
                "action": act,
                "profile_id": pid,
                "queued": True,
                "mode": "push_report",
                "superseded_prev": int(superseded),
            },
        )
    )
    _update_remote_profile_mount_pending(pid, act, task_id)
    return int(task_id), True, ""


@router.get("/", response_class=HTMLResponse)
async def index(request: Request, user: str = Depends(require_login_page)):
    nodes = filter_nodes_for_user(user, list_nodes())

    group_orders = get_group_orders()

    def _gk(name: str) -> tuple[int, str]:
        """Group sort key: user-defined sort_order (smaller first), then name."""
        n = (name or "").strip() or "默认分组"
        try:
            order = int(group_orders.get(n, 1000))
        except Exception:
            order = 1000
        return (order, n)

    def _gn(x: dict) -> str:
        g = str(x.get("group_name") or "").strip()
        return g or "默认分组"

    for n in nodes:
        n["display_ip"] = extract_ip_for_display(n.get("base_url", ""))
        n["online"] = is_report_fresh(n)
        # 分组名为空时统一归入“默认分组”
        n["group_name"] = _gn(n)
        # For UI display
        if "agent_version" not in n:
            n["agent_version"] = str(n.get("agent_reported_version") or "").strip()

    # 控制台卡片：按分组聚合展示
    # - 组内排序：在线优先，其次按 id 倒序
    nodes_sorted = sorted(
        nodes,
        key=lambda x: (
            _gk(_gn(x)),
            0 if bool(x.get("online")) else 1,
            -_safe_int(x.get("id"), 0),
        ),
    )

    dashboard_groups = []
    cur = None
    buf = []
    for n in nodes_sorted:
        g = _gn(n)
        if cur is None:
            cur = g
        if g != cur:
            dashboard_groups.append(
                {
                    "name": cur,
                    "sort_order": _gk(cur)[0],
                    "nodes": buf,
                    "online": sum(1 for i in buf if i.get("online")),
                    "total": len(buf),
                }
            )
            cur = g
            buf = []
        buf.append(n)

    if cur is not None:
        dashboard_groups.append(
            {
                "name": cur,
                "sort_order": _gk(cur)[0],
                "nodes": buf,
                "online": sum(1 for i in buf if i.get("online")),
                "total": len(buf),
            }
        )

    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "user": (user or None),
            "nodes": nodes,
            "dashboard_groups": dashboard_groups,
            "flash": flash(request),
            "title": "控制台",
        },
    )


@router.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request, user: str = Depends(require_role_page("users.manage"))):
    configured_url = str(get_panel_setting("agent_bootstrap_url", "") or "").strip()
    configured_insecure_raw = get_panel_setting("agent_bootstrap_insecure_tls")
    insecure_tls = (
        _as_bool(configured_insecure_raw, default=True)
        if configured_insecure_raw is not None and str(configured_insecure_raw).strip() != ""
        else panel_bootstrap_insecure_tls(default=True)
    )
    configured_public_url = str(get_panel_setting("panel_public_url", "") or "").strip()
    configured_asset_source = str(get_panel_setting("panel_asset_source", "") or "").strip().lower()
    if configured_asset_source not in ("panel", "github"):
        configured_asset_source = ""
    configured_agent_sh_url = str(get_panel_setting("panel_agent_sh_url", "") or "").strip()
    configured_agent_zip_url = str(get_panel_setting("panel_agent_zip_url", "") or "").strip()
    configured_bootstrap_scheme = str(get_panel_setting("agent_bootstrap_default_scheme", "") or "").strip().lower()
    if configured_bootstrap_scheme not in ("http", "https"):
        configured_bootstrap_scheme = ""
    configured_panel_ip_fallback_port = str(get_panel_setting("agent_panel_ip_fallback_port", "") or "").strip()
    configured_node_info_fetch_order = normalize_node_info_fetch_order(
        get_panel_setting("node_info_fetch_order", "push_first"),
        "push_first",
    )

    configured_ssl_direct_first = parse_bool_loose(get_panel_setting("ssl_direct_first"), default=True)
    configured_ssl_direct_timeout = _clamp_float_text(get_panel_setting("ssl_direct_timeout_sec", ""), 30.0, 1200.0)
    configured_ssl_direct_max_attempts = _clamp_int_text(get_panel_setting("ssl_direct_max_attempts", ""), 1, 30)
    configured_ssl_fallback_to_queue = parse_bool_loose(get_panel_setting("ssl_fallback_to_queue"), default=True)

    configured_save_precheck_enabled = parse_bool_loose(get_panel_setting("save_precheck_enabled"), default=True)
    configured_save_precheck_http_timeout = _clamp_float_text(
        get_panel_setting("save_precheck_http_timeout", ""),
        2.0,
        20.0,
    )
    configured_save_precheck_probe_timeout = _clamp_float_text(
        get_panel_setting("save_precheck_probe_timeout", ""),
        0.2,
        6.0,
    )
    configured_save_precheck_max_issues = _clamp_int_text(
        get_panel_setting("save_precheck_max_issues", ""),
        5,
        120,
    )

    configured_sync_precheck_enabled = parse_bool_loose(get_panel_setting("sync_precheck_enabled"), default=True)
    configured_sync_precheck_http_timeout = _clamp_float_text(
        get_panel_setting("sync_precheck_http_timeout", ""),
        2.0,
        20.0,
    )
    configured_sync_precheck_probe_timeout = _clamp_float_text(
        get_panel_setting("sync_precheck_probe_timeout", ""),
        0.2,
        6.0,
    )
    configured_sync_apply_timeout = _clamp_float_text(
        get_panel_setting("sync_apply_timeout", ""),
        0.5,
        20.0,
    )
    configured_time_sync_enabled = parse_bool_loose(get_panel_setting("agent_time_sync_enabled"), default=False)
    configured_time_sync_timezone = _normalize_timezone_name(
        get_panel_setting("agent_time_sync_timezone", "Asia/Shanghai"),
        default="Asia/Shanghai",
    )
    configured_time_sync_set_timezone = parse_bool_loose(get_panel_setting("agent_time_sync_set_timezone"), default=True)
    configured_time_sync_enable_ntp = parse_bool_loose(get_panel_setting("agent_time_sync_enable_ntp"), default=True)
    configured_time_sync_set_clock = parse_bool_loose(get_panel_setting("agent_time_sync_set_clock"), default=False)
    effective_time_sync_version = setting_int("agent_time_sync_version", default=0, lo=0, hi=2147483647)

    effective_bootstrap_url = panel_bootstrap_base_url(request)
    effective_public_url = panel_public_base_url(request)
    effective_asset_source = panel_asset_source()
    effective_ssl_direct_timeout = setting_float("ssl_direct_timeout_sec", default=240.0, lo=30.0, hi=1200.0)
    effective_ssl_direct_max_attempts = setting_int("ssl_direct_max_attempts", default=1, lo=1, hi=30)
    effective_panel_ip_fallback_port = setting_int(
        "agent_panel_ip_fallback_port",
        default=6080,
        lo=1,
        hi=65535,
        env_names=["REALM_PANEL_IP_FALLBACK_PORT"],
    )
    effective_node_info_fetch_order = node_info_fetch_order()

    backup_nodes = filter_nodes_for_user(user, list_nodes())
    for n in backup_nodes:
        n["display_ip"] = extract_ip_for_display(n.get("base_url", ""))

    configured_auto_backup_enabled = parse_bool_loose(get_panel_setting("auto_backup_enabled"), default=False)
    configured_auto_backup_target_node_id = _safe_int(get_panel_setting("auto_backup_target_node_id"), 0)
    configured_auto_backup_target_path = _normalize_backup_target_path(get_panel_setting("auto_backup_target_path", ""))
    if configured_auto_backup_target_path and not _is_abs_backup_target_path(configured_auto_backup_target_path):
        configured_auto_backup_target_path = ""
    configured_auto_backup_interval_hours = _safe_int(get_panel_setting("auto_backup_interval_hours"), 24)
    if configured_auto_backup_interval_hours < 1:
        configured_auto_backup_interval_hours = 1
    if configured_auto_backup_interval_hours > 24 * 30:
        configured_auto_backup_interval_hours = 24 * 30
    configured_auto_backup_retention_days = _safe_int(get_panel_setting("auto_backup_retention_days"), 30)
    if configured_auto_backup_retention_days < 0:
        configured_auto_backup_retention_days = 0
    if configured_auto_backup_retention_days > 3650:
        configured_auto_backup_retention_days = 3650
    configured_auto_backup_keep_count = _safe_int(get_panel_setting("auto_backup_keep_count"), 30)
    if configured_auto_backup_keep_count < 0:
        configured_auto_backup_keep_count = 0
    if configured_auto_backup_keep_count > 2000:
        configured_auto_backup_keep_count = 2000

    auto_backup_last_trigger_ts = _safe_float(get_panel_setting("auto_backup_last_trigger_ts"), 0.0)
    auto_backup_last_success_ts = _safe_float(get_panel_setting("auto_backup_last_success_ts"), 0.0)
    auto_backup_last_status = str(get_panel_setting("auto_backup_last_status", "") or "").strip().lower()
    if auto_backup_last_status not in ("success", "failed"):
        auto_backup_last_status = ""
    auto_backup_last_message = _safe_text(get_panel_setting("auto_backup_last_message", ""), max_len=300)
    auto_backup_last_filename = _safe_text(get_panel_setting("auto_backup_last_filename", ""), max_len=200)
    auto_backup_last_size_bytes = _safe_int(get_panel_setting("auto_backup_last_size_bytes"), 0)
    if auto_backup_last_size_bytes < 0:
        auto_backup_last_size_bytes = 0
    auto_backup_next_run_at = ""
    if (
        bool(configured_auto_backup_enabled)
        and int(configured_auto_backup_target_node_id) > 0
        and bool(configured_auto_backup_target_path)
    ):
        if auto_backup_last_trigger_ts > 0:
            auto_backup_next_run_at = _format_ts_text(
                auto_backup_last_trigger_ts + float(configured_auto_backup_interval_hours * 3600)
            )
        else:
            auto_backup_next_run_at = "首次保存后将自动触发"
    node_name_map = {
        int(_safe_int(n.get("id"), 0)): str(n.get("name") or "").strip()
        for n in backup_nodes
        if _safe_int(n.get("id"), 0) > 0
    }
    auto_backup_target_node_name = node_name_map.get(int(configured_auto_backup_target_node_id), "")
    return templates.TemplateResponse(
        "settings.html",
        {
            "request": request,
            "user": user,
            "flash": flash(request),
            "title": "面板设置",
            "agent_bootstrap_url": configured_url,
            "agent_bootstrap_insecure_tls": bool(insecure_tls),
            "effective_bootstrap_url": effective_bootstrap_url,
            "panel_public_url": configured_public_url,
            "panel_asset_source": configured_asset_source,
            "panel_agent_sh_url": configured_agent_sh_url,
            "panel_agent_zip_url": configured_agent_zip_url,
            "agent_bootstrap_default_scheme": configured_bootstrap_scheme,
            "agent_panel_ip_fallback_port": configured_panel_ip_fallback_port,
            "node_info_fetch_order": configured_node_info_fetch_order,
            "ssl_direct_first": bool(configured_ssl_direct_first),
            "ssl_direct_timeout_sec": configured_ssl_direct_timeout,
            "ssl_direct_max_attempts": configured_ssl_direct_max_attempts,
            "ssl_fallback_to_queue": bool(configured_ssl_fallback_to_queue),
            "save_precheck_enabled": bool(configured_save_precheck_enabled),
            "save_precheck_http_timeout": configured_save_precheck_http_timeout,
            "save_precheck_probe_timeout": configured_save_precheck_probe_timeout,
            "save_precheck_max_issues": configured_save_precheck_max_issues,
            "sync_precheck_enabled": bool(configured_sync_precheck_enabled),
            "sync_precheck_http_timeout": configured_sync_precheck_http_timeout,
            "sync_precheck_probe_timeout": configured_sync_precheck_probe_timeout,
            "sync_apply_timeout": configured_sync_apply_timeout,
            "agent_time_sync_enabled": bool(configured_time_sync_enabled),
            "agent_time_sync_timezone": configured_time_sync_timezone,
            "agent_time_sync_set_timezone": bool(configured_time_sync_set_timezone),
            "agent_time_sync_enable_ntp": bool(configured_time_sync_enable_ntp),
            "agent_time_sync_set_clock": bool(configured_time_sync_set_clock),
            "agent_time_sync_version": int(effective_time_sync_version),
            "effective_public_url": effective_public_url,
            "effective_asset_source": effective_asset_source,
            "effective_ssl_direct_timeout": f"{float(effective_ssl_direct_timeout):g}",
            "effective_ssl_direct_max_attempts": int(effective_ssl_direct_max_attempts),
            "effective_panel_ip_fallback_port": int(effective_panel_ip_fallback_port),
            "effective_node_info_fetch_order": effective_node_info_fetch_order,
            "backup_nodes": backup_nodes,
            "auto_backup_enabled": bool(configured_auto_backup_enabled),
            "auto_backup_target_node_id": int(configured_auto_backup_target_node_id),
            "auto_backup_target_path": configured_auto_backup_target_path,
            "auto_backup_interval_hours": int(configured_auto_backup_interval_hours),
            "auto_backup_retention_days": int(configured_auto_backup_retention_days),
            "auto_backup_keep_count": int(configured_auto_backup_keep_count),
            "auto_backup_last_trigger_at": _format_ts_text(auto_backup_last_trigger_ts),
            "auto_backup_last_success_at": _format_ts_text(auto_backup_last_success_ts),
            "auto_backup_last_status": auto_backup_last_status,
            "auto_backup_last_message": auto_backup_last_message,
            "auto_backup_last_filename": auto_backup_last_filename,
            "auto_backup_last_size_bytes": int(auto_backup_last_size_bytes),
            "auto_backup_next_run_at": auto_backup_next_run_at,
            "auto_backup_target_node_name": auto_backup_target_node_name,
        },
    )


@router.post("/settings")
async def settings_save(
    request: Request,
    user: str = Depends(require_role_page("users.manage")),
    agent_bootstrap_url: str = Form(""),
    agent_bootstrap_insecure_tls: Optional[str] = Form(None),
    panel_public_url: str = Form(""),
    panel_asset_source: str = Form("panel"),
    panel_agent_sh_url: str = Form(""),
    panel_agent_zip_url: str = Form(""),
    agent_bootstrap_default_scheme: str = Form(""),
    agent_panel_ip_fallback_port: str = Form(""),
    node_info_fetch_order: str = Form("push_first"),
    ssl_direct_first: Optional[str] = Form(None),
    ssl_direct_timeout_sec: str = Form(""),
    ssl_direct_max_attempts: str = Form(""),
    ssl_fallback_to_queue: Optional[str] = Form(None),
    save_precheck_enabled: Optional[str] = Form(None),
    save_precheck_http_timeout: str = Form(""),
    save_precheck_probe_timeout: str = Form(""),
    save_precheck_max_issues: str = Form(""),
    sync_precheck_enabled: Optional[str] = Form(None),
    sync_precheck_http_timeout: str = Form(""),
    sync_precheck_probe_timeout: str = Form(""),
    sync_apply_timeout: str = Form(""),
    auto_backup_enabled: Optional[str] = Form(None),
    auto_backup_target_node_id: str = Form(""),
    auto_backup_target_path: str = Form(""),
    auto_backup_interval_hours: str = Form(""),
    auto_backup_retention_days: str = Form(""),
    auto_backup_keep_count: str = Form(""),
    agent_time_sync_enabled: Optional[str] = Form(None),
    agent_time_sync_timezone: str = Form(""),
    agent_time_sync_set_timezone: Optional[str] = Form(None),
    agent_time_sync_enable_ntp: Optional[str] = Form(None),
    agent_time_sync_set_clock: Optional[str] = Form(None),
):
    _ = user
    set_panel_setting("agent_bootstrap_url", str(agent_bootstrap_url or "").strip())
    set_panel_setting("agent_bootstrap_insecure_tls", "1" if _as_bool(agent_bootstrap_insecure_tls, default=False) else "0")
    set_panel_setting("panel_public_url", str(panel_public_url or "").strip())

    asset_src = str(panel_asset_source or "").strip().lower()
    if asset_src not in ("panel", "github"):
        asset_src = "panel"
    set_panel_setting("panel_asset_source", asset_src)
    set_panel_setting("panel_agent_sh_url", str(panel_agent_sh_url or "").strip())
    set_panel_setting("panel_agent_zip_url", str(panel_agent_zip_url or "").strip())

    bootstrap_scheme = str(agent_bootstrap_default_scheme or "").strip().lower()
    if bootstrap_scheme not in ("http", "https"):
        bootstrap_scheme = ""
    set_panel_setting("agent_bootstrap_default_scheme", bootstrap_scheme)
    set_panel_setting("agent_panel_ip_fallback_port", _clamp_int_text(agent_panel_ip_fallback_port, 1, 65535))
    set_panel_setting("node_info_fetch_order", normalize_node_info_fetch_order(node_info_fetch_order, "push_first"))

    set_panel_setting("ssl_direct_first", "1" if _as_bool(ssl_direct_first, default=False) else "0")
    set_panel_setting("ssl_direct_timeout_sec", _clamp_float_text(ssl_direct_timeout_sec, 30.0, 1200.0))
    set_panel_setting("ssl_direct_max_attempts", _clamp_int_text(ssl_direct_max_attempts, 1, 30))
    set_panel_setting("ssl_fallback_to_queue", "1" if _as_bool(ssl_fallback_to_queue, default=False) else "0")

    set_panel_setting("save_precheck_enabled", "1" if _as_bool(save_precheck_enabled, default=False) else "0")
    set_panel_setting("save_precheck_http_timeout", _clamp_float_text(save_precheck_http_timeout, 2.0, 20.0))
    set_panel_setting("save_precheck_probe_timeout", _clamp_float_text(save_precheck_probe_timeout, 0.2, 6.0))
    set_panel_setting("save_precheck_max_issues", _clamp_int_text(save_precheck_max_issues, 5, 120))

    set_panel_setting("sync_precheck_enabled", "1" if _as_bool(sync_precheck_enabled, default=False) else "0")
    set_panel_setting("sync_precheck_http_timeout", _clamp_float_text(sync_precheck_http_timeout, 2.0, 20.0))
    set_panel_setting("sync_precheck_probe_timeout", _clamp_float_text(sync_precheck_probe_timeout, 0.2, 6.0))
    set_panel_setting("sync_apply_timeout", _clamp_float_text(sync_apply_timeout, 0.5, 20.0))

    prev_auto_backup_enabled = parse_bool_loose(get_panel_setting("auto_backup_enabled"), default=False)
    prev_auto_backup_target_node_id = _safe_int(get_panel_setting("auto_backup_target_node_id"), 0)
    prev_auto_backup_target_path = _normalize_backup_target_path(get_panel_setting("auto_backup_target_path", ""))
    prev_auto_backup_interval_hours = _safe_int(get_panel_setting("auto_backup_interval_hours"), 24)
    if prev_auto_backup_interval_hours < 1:
        prev_auto_backup_interval_hours = 1
    if prev_auto_backup_interval_hours > 24 * 30:
        prev_auto_backup_interval_hours = 24 * 30

    warn_items: List[str] = []
    new_auto_backup_enabled = _as_bool(auto_backup_enabled, default=False)
    raw_auto_backup_target_node_id = _safe_int(auto_backup_target_node_id, 0)
    new_auto_backup_target_node_id = raw_auto_backup_target_node_id
    if new_auto_backup_target_node_id > 0 and not get_node(new_auto_backup_target_node_id):
        new_auto_backup_target_node_id = 0
        warn_items.append("自动备份目标节点不存在，已清空")

    raw_auto_backup_target_path = _normalize_backup_target_path(auto_backup_target_path)
    new_auto_backup_target_path = raw_auto_backup_target_path
    if raw_auto_backup_target_path and not _is_abs_backup_target_path(raw_auto_backup_target_path):
        new_auto_backup_target_path = ""
        warn_items.append("自动备份路径必须为绝对路径，已清空")

    new_auto_backup_interval_hours = _safe_int(auto_backup_interval_hours, 24)
    if new_auto_backup_interval_hours < 1:
        new_auto_backup_interval_hours = 1
    if new_auto_backup_interval_hours > 24 * 30:
        new_auto_backup_interval_hours = 24 * 30

    new_auto_backup_retention_days = _safe_int(auto_backup_retention_days, 30)
    if new_auto_backup_retention_days < 0:
        new_auto_backup_retention_days = 0
    if new_auto_backup_retention_days > 3650:
        new_auto_backup_retention_days = 3650

    new_auto_backup_keep_count = _safe_int(auto_backup_keep_count, 30)
    if new_auto_backup_keep_count < 0:
        new_auto_backup_keep_count = 0
    if new_auto_backup_keep_count > 2000:
        new_auto_backup_keep_count = 2000

    set_panel_setting("auto_backup_enabled", "1" if new_auto_backup_enabled else "0")
    set_panel_setting("auto_backup_target_node_id", str(int(new_auto_backup_target_node_id)))
    set_panel_setting("auto_backup_target_path", new_auto_backup_target_path)
    set_panel_setting("auto_backup_interval_hours", str(int(new_auto_backup_interval_hours)))
    set_panel_setting("auto_backup_retention_days", str(int(new_auto_backup_retention_days)))
    set_panel_setting("auto_backup_keep_count", str(int(new_auto_backup_keep_count)))

    if new_auto_backup_enabled and (new_auto_backup_target_node_id <= 0 or not new_auto_backup_target_path):
        warn_items.append("自动备份已启用，但目标节点或路径未配置完整")

    if (
        prev_auto_backup_enabled != new_auto_backup_enabled
        or int(prev_auto_backup_target_node_id) != int(new_auto_backup_target_node_id)
        or str(prev_auto_backup_target_path or "") != str(new_auto_backup_target_path or "")
        or int(prev_auto_backup_interval_hours) != int(new_auto_backup_interval_hours)
    ):
        # Reset trigger so scheduler can re-evaluate immediately after config changes.
        set_panel_setting("auto_backup_last_trigger_ts", "")

    prev_time_sync_enabled = parse_bool_loose(get_panel_setting("agent_time_sync_enabled"), default=False)
    prev_time_sync_timezone = _normalize_timezone_name(
        get_panel_setting("agent_time_sync_timezone", "Asia/Shanghai"),
        default="Asia/Shanghai",
    )
    prev_time_sync_set_timezone = parse_bool_loose(get_panel_setting("agent_time_sync_set_timezone"), default=True)
    prev_time_sync_enable_ntp = parse_bool_loose(get_panel_setting("agent_time_sync_enable_ntp"), default=True)
    prev_time_sync_set_clock = parse_bool_loose(get_panel_setting("agent_time_sync_set_clock"), default=False)

    new_time_sync_enabled = _as_bool(agent_time_sync_enabled, default=False)
    new_time_sync_timezone = _normalize_timezone_name(agent_time_sync_timezone, default="Asia/Shanghai")
    new_time_sync_set_timezone = _as_bool(agent_time_sync_set_timezone, default=False)
    new_time_sync_enable_ntp = _as_bool(agent_time_sync_enable_ntp, default=False)
    new_time_sync_set_clock = _as_bool(agent_time_sync_set_clock, default=False)

    set_panel_setting("agent_time_sync_enabled", "1" if new_time_sync_enabled else "0")
    set_panel_setting("agent_time_sync_timezone", new_time_sync_timezone)
    set_panel_setting("agent_time_sync_set_timezone", "1" if new_time_sync_set_timezone else "0")
    set_panel_setting("agent_time_sync_enable_ntp", "1" if new_time_sync_enable_ntp else "0")
    set_panel_setting("agent_time_sync_set_clock", "1" if new_time_sync_set_clock else "0")

    if (
        prev_time_sync_enabled != new_time_sync_enabled
        or prev_time_sync_timezone != new_time_sync_timezone
        or prev_time_sync_set_timezone != new_time_sync_set_timezone
        or prev_time_sync_enable_ntp != new_time_sync_enable_ntp
        or prev_time_sync_set_clock != new_time_sync_set_clock
    ):
        cur_ver = setting_int("agent_time_sync_version", default=0, lo=0, hi=2147483647)
        next_ver = int(cur_ver) + 1 if int(cur_ver) < 2147483647 else 2147483647
        set_panel_setting("agent_time_sync_version", str(int(next_ver)))

    flash_msg = "面板设置已保存"
    if warn_items:
        flash_msg = f"{flash_msg}（{'；'.join(warn_items[:3])}）"
    set_flash(request, flash_msg)
    return RedirectResponse(url="/settings", status_code=303)


@router.get("/netmon", response_class=HTMLResponse)
async def netmon_page(request: Request, user: str = Depends(require_login_page)):
    """Network fluctuation monitoring page."""
    nodes = filter_nodes_for_user(user, list_nodes())

    group_orders = get_group_orders()

    def _gk(name: str) -> tuple[int, str]:
        n = (name or "").strip() or "默认分组"
        try:
            order = int(group_orders.get(n, 1000))
        except Exception:
            order = 1000
        return (order, n)

    def _gn(x: Dict[str, Any]) -> str:
        g = str(x.get("group_name") or "").strip()
        return g or "默认分组"

    for n in nodes:
        n["display_ip"] = extract_ip_for_display(n.get("base_url", ""))
        # 用更宽松的阈值显示在线状态（避免轻微抖动导致频繁显示离线）
        n["online"] = is_report_fresh(n, max_age_sec=90)
        n["group_name"] = _gn(n)

    nodes_sorted = sorted(
        nodes,
        key=lambda x: (
            _gk(_gn(x)),
            0 if bool(x.get("online")) else 1,
            -_safe_int(x.get("id"), 0),
        ),
    )

    node_groups: List[Dict[str, Any]] = []
    cur = None
    buf: List[Dict[str, Any]] = []
    for n in nodes_sorted:
        g = _gn(n)
        if cur is None:
            cur = g
        if g != cur:
            node_groups.append(
                {
                    "name": cur,
                    "sort_order": _gk(cur)[0],
                    "nodes": buf,
                    "online": sum(1 for i in buf if i.get("online")),
                    "total": len(buf),
                }
            )
            cur = g
            buf = []
        buf.append(n)

    if cur is not None:
        node_groups.append(
            {
                "name": cur,
                "sort_order": _gk(cur)[0],
                "nodes": buf,
                "online": sum(1 for i in buf if i.get("online")),
                "total": len(buf),
            }
        )

    return templates.TemplateResponse(
        "netmon.html",
        {
            "request": request,
            "user": (user or None),
            "node_groups": node_groups,
            "flash": flash(request),
            "title": "网络波动监控",
        },
    )


@router.get("/netmon/view", response_class=HTMLResponse)
async def netmon_view_page(request: Request, user: str = Depends(require_login_or_share_view_page)):
    """Read-only NetMon display page (for sharing / wallboard)."""
    return templates.TemplateResponse(
        "netmon_view.html",
        {
            "request": request,
            "user": (user or None),
            "flash": flash(request),
            "title": "网络波动 · 只读展示",
        },
    )


@router.get("/netmon/wall", response_class=HTMLResponse)
async def netmon_wall_page(request: Request, user: str = Depends(require_login_or_share_wall_page)):
    """NetMon wallboard (read-only)."""
    return templates.TemplateResponse(
        "netmon_wall.html",
        {
            "request": request,
            "user": (user or None),
            "flash": flash(request),
            "title": "网络波动 · 大屏展示",
        },
    )


@router.get("/remote-storage", response_class=HTMLResponse)
async def remote_storage_page(request: Request, user: str = Depends(require_role_page("nodes.read"))):
    nodes = filter_nodes_for_user(user, list_nodes())
    node_name_map: Dict[int, str] = {}
    for n in nodes:
        nid = _safe_int((n or {}).get("id"), 0)
        if nid <= 0:
            continue
        node_name_map[nid] = str((n or {}).get("name") or f"节点-{nid}")
        n["display_ip"] = extract_ip_for_display((n or {}).get("base_url", ""))

    profiles = _load_remote_storage_profiles()
    for p in profiles:
        _attach_remote_profile_runtime(p, node_name_map)

    perms = (request.session.get("user_permissions") if request and request.session else []) or []
    can_manage = ("*" in perms) or ("nodes.write" in perms) or ("nodes.*" in perms)

    return templates.TemplateResponse(
        "remote_storage.html",
        {
            "request": request,
            "user": user,
            "flash": flash(request),
            "title": "远程存储挂载",
            "nodes": nodes,
            "profiles": profiles,
            "can_manage": bool(can_manage),
        },
    )


def _remote_storage_profile_context(
    user: str,
    profile_id: str,
) -> tuple[List[Dict[str, Any]], int, Optional[Dict[str, Any]], Optional[Dict[str, Any]], Dict[int, str]]:
    rows = _load_remote_storage_profiles()
    idx, profile = _find_remote_storage_profile(rows, profile_id)
    node_name_map: Dict[int, str] = {}
    if idx < 0 or not isinstance(profile, dict):
        return rows, idx, None, None, node_name_map
    nodes = filter_nodes_for_user(user, list_nodes())
    node_map: Dict[int, Dict[str, Any]] = {}
    for n in nodes:
        nid = _safe_int((n or {}).get("id"), 0)
        if nid <= 0:
            continue
        node_map[nid] = n
        node_name_map[nid] = str((n or {}).get("name") or f"节点-{nid}")
    node_id = _safe_int(profile.get("target_node_id"), 0)
    node = node_map.get(node_id)
    return rows, idx, profile, (node if isinstance(node, dict) else None), node_name_map


@router.post("/remote-storage/profiles")
async def remote_storage_profile_save(
    request: Request,
    user: str = Depends(require_role_page("nodes.write")),
    profile_id: str = Form(""),
    name: str = Form(""),
    protocol: str = Form("smb"),
    host: str = Form(""),
    port: str = Form(""),
    share_path: str = Form(""),
    mount_point: str = Form(""),
    username: str = Form(""),
    options: str = Form(""),
    rclone_remote: str = Form(""),
    remote_path: str = Form(""),
    drive_letter: str = Form("Z"),
    password: str = Form(""),
    save_password: Optional[str] = Form(None),
    read_only: Optional[str] = Form(None),
    auto_mount: Optional[str] = Form(None),
    platform: str = Form("auto"),
    target_node_id: str = Form("0"),
    note: str = Form(""),
):
    proto = _safe_text(protocol, max_len=32).lower()
    if proto not in _REMOTE_STORAGE_PROTOCOLS:
        set_flash(request, "协议不受支持")
        return RedirectResponse(url="/remote-storage", status_code=303)

    profile_name = _safe_text(name, max_len=64)
    if not profile_name:
        set_flash(request, "请填写挂载方案名称")
        return RedirectResponse(url="/remote-storage", status_code=303)

    host_text = _safe_text(host, max_len=128)
    share_text = _safe_path(share_path, max_len=255)
    remote_path_text = _safe_path(remote_path, max_len=255)
    rclone_remote_text = _safe_text(rclone_remote, max_len=96)

    if proto != "rclone" and not host_text:
        set_flash(request, "该协议必须填写远程地址")
        return RedirectResponse(url="/remote-storage", status_code=303)

    if proto in ("smb", "nfs") and not share_text:
        set_flash(request, "SMB/NFS 必须填写共享路径")
        return RedirectResponse(url="/remote-storage", status_code=303)

    if proto == "rclone" and not rclone_remote_text:
        set_flash(request, "Rclone 协议必须填写 Remote 名称")
        return RedirectResponse(url="/remote-storage", status_code=303)

    port_val = _normalize_port(port)
    if port_val < 0:
        set_flash(request, "端口范围应在 1-65535（或留空）")
        return RedirectResponse(url="/remote-storage", status_code=303)

    platform_val = _safe_text(platform, max_len=16).lower()
    if platform_val not in _REMOTE_STORAGE_PLATFORMS:
        platform_val = "auto"

    target_node_id_val = max(0, _safe_int(target_node_id, 0))
    editable_nodes = filter_nodes_for_user(user, list_nodes())
    editable_node_map: Dict[int, Dict[str, Any]] = {}
    node_name_map: Dict[int, str] = {}
    editable_node_ids: set[int] = set()
    for n in editable_nodes:
        nid = _safe_int((n or {}).get("id"), 0)
        if nid <= 0:
            continue
        editable_node_ids.add(nid)
        editable_node_map[nid] = n
        node_name_map[nid] = str((n or {}).get("name") or f"节点-{nid}")
    if target_node_id_val <= 0:
        set_flash(request, "请选择目标节点")
        return RedirectResponse(url="/remote-storage", status_code=303)
    if target_node_id_val not in editable_node_ids:
        set_flash(request, "目标节点无权限或不存在")
        return RedirectResponse(url="/remote-storage", status_code=303)
    target_node = editable_node_map.get(target_node_id_val)
    if not isinstance(target_node, dict):
        set_flash(request, "目标节点不可用")
        return RedirectResponse(url="/remote-storage", status_code=303)

    node_system_type = normalize_node_system_type((target_node or {}).get("system_type"), default="auto")
    effective_platform = platform_val if platform_val != "auto" else node_system_type
    if effective_platform not in _REMOTE_STORAGE_PLATFORMS:
        effective_platform = "auto"

    mount_path = _safe_path(mount_point, max_len=255)
    if effective_platform == "macos":
        mount_path = _remote_storage_default_macos_mount_point(
            protocol=proto,
            share_path=share_text,
            remote_path=remote_path_text,
            rclone_remote=rclone_remote_text,
            fallback=profile_name,
        )
    if not mount_path:
        set_flash(request, "请填写本地挂载点")
        return RedirectResponse(url="/remote-storage", status_code=303)
    if not (mount_path.startswith("/") or _WIN_ABS_PATH_RE.match(mount_path)):
        set_flash(request, "本地挂载点必须是绝对路径")
        return RedirectResponse(url="/remote-storage", status_code=303)
    if mount_path == "/":
        set_flash(request, "本地挂载点不能是根目录 /")
        return RedirectResponse(url="/remote-storage", status_code=303)

    profile_data: Dict[str, Any] = {
        "name": profile_name,
        "protocol": proto,
        "host": host_text,
        "port": int(port_val),
        "share_path": share_text,
        "mount_point": mount_path,
        "username": _safe_text(username, max_len=64),
        "options": _safe_text(options, max_len=240),
        "rclone_remote": rclone_remote_text,
        "remote_path": remote_path_text,
        "drive_letter": _normalize_drive_letter(drive_letter, default="Z"),
        "password": "",
        "password_enc": "",
        "save_password": False,
        "read_only": _as_bool(read_only, default=False),
        "auto_mount": _as_bool(auto_mount, default=False),
        "macos_desktop_link": False,
        "platform": platform_val,
        "target_node_id": int(target_node_id_val),
        "note": _safe_text(note, max_len=280),
        "mount_status": "unknown",
        "mount_message": "",
        "mounted_at": "",
        "last_sync_at": "",
        "updated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }

    rows = _load_remote_storage_profiles()
    pid = _normalize_remote_profile_id(profile_id)
    idx = -1
    if pid:
        for i, item in enumerate(rows):
            if str(item.get("id") or "") == pid:
                idx = i
                break
    if idx < 0:
        if len(rows) >= 200:
            set_flash(request, "挂载方案已达上限（200 条），请先删除旧方案")
            return RedirectResponse(url="/remote-storage", status_code=303)
        pid = _normalize_remote_profile_id(
            f"rm_{int(datetime.now().timestamp() * 1000)}_{os.urandom(2).hex()}",
            default="",
        )
        if not pid:
            pid = _normalize_remote_profile_id(f"rm_{int(datetime.now().timestamp() * 1000)}")
        profile_data["id"] = pid
        action_name = "新增"
    else:
        old_row = rows[idx] if isinstance(rows[idx], dict) else {}
        profile_data["id"] = str(old_row.get("id") or pid)
        profile_data["mounted_at"] = _safe_text(old_row.get("mounted_at"), max_len=32)
        profile_data["password_enc"] = _safe_text(old_row.get("password_enc"), max_len=4096)
        action_name = "更新"

    input_password = _safe_text(password, max_len=128)
    save_password_flag = _as_bool(save_password, default=False)
    if save_password_flag and not _remote_storage_password_encryptable():
        set_flash(request, "当前未启用密码加密组件（cryptography），无法保存密码")
        return RedirectResponse(url="/remote-storage", status_code=303)
    old_password = ""
    old_password_enc = ""
    if idx >= 0 and isinstance(rows[idx], dict):
        old_password = _safe_text(rows[idx].get("password"), max_len=128)
        old_password_enc = _safe_text(rows[idx].get("password_enc"), max_len=4096)
    if save_password_flag:
        profile_data["password"] = input_password or old_password
        profile_data["password_enc"] = old_password_enc
        profile_data["save_password"] = bool(profile_data["password"] or profile_data["password_enc"])
    else:
        profile_data["password"] = ""
        profile_data["password_enc"] = ""
        profile_data["save_password"] = False

    if idx < 0:
        rows.append(profile_data)
    else:
        rows[idx] = profile_data

    rows.sort(key=lambda x: str(x.get("updated_at") or ""), reverse=True)
    _save_remote_storage_profiles(rows)

    try:
        _ensure_remote_profile_site(profile_data)
    except Exception:
        pass

    mount_task_id = 0
    mount_task_ok = False
    mount_task_err = ""
    try:
        mount_task_id, mount_task_ok, mount_task_err = _enqueue_remote_profile_mount_task(
            profile_id=str(profile_data.get("id") or ""),
            node_id=int(target_node_id_val),
            action="mount",
            actor=str(user or ""),
            password_override=input_password,
        )
    except Exception as exc:
        mount_task_err = str(exc or "").strip() or "后台任务提交失败"
        _update_remote_profile_mount_result(str(profile_data.get("id") or ""), "mount", False, mount_task_err)

    _audit_log_node_action(
        request=request,
        user=user,
        action="remote_storage.profile.save",
        node_id=int(target_node_id_val),
        node_name=str(node_name_map.get(target_node_id_val) or ""),
        detail={
            "profile_id": str(profile_data.get("id") or ""),
            "profile_name": str(profile_data.get("name") or ""),
            "protocol": str(profile_data.get("protocol") or ""),
            "target_node_id": int(target_node_id_val),
            "mount_task_id": int(mount_task_id),
            "mount_task_queued": bool(mount_task_ok),
            "mount_task_error": str(mount_task_err or ""),
        },
    )

    if mount_task_ok and mount_task_id > 0:
        set_flash(request, f"远程挂载方案已{action_name}，自动挂载队列任务 #{mount_task_id} 已提交，等待节点上报执行（失败原因会写入挂载信息）。")
    else:
        reason = mount_task_err or "后台任务提交失败"
        _update_remote_profile_mount_result(str(profile_data.get("id") or ""), "mount", False, reason)
        set_flash(request, f"远程挂载方案已{action_name}，但自动挂载任务提交失败：{reason}")
    return RedirectResponse(url="/remote-storage", status_code=303)


@router.post("/remote-storage/profiles/{profile_id}/mount")
async def remote_storage_profile_mount(
    request: Request,
    profile_id: str,
    password: str = Form(""),
    user: str = Depends(require_role_page("nodes.write")),
):
    rows = _load_remote_storage_profiles()
    idx, profile = _find_remote_storage_profile(rows, profile_id)
    if idx < 0 or not isinstance(profile, dict):
        set_flash(request, "挂载方案不存在")
        return RedirectResponse(url="/remote-storage", status_code=303)

    nodes = filter_nodes_for_user(user, list_nodes())
    node_map: Dict[int, Dict[str, Any]] = {}
    for n in nodes:
        nid = _safe_int((n or {}).get("id"), 0)
        if nid > 0:
            node_map[nid] = n
    node_id = _safe_int(profile.get("target_node_id"), 0)
    node = node_map.get(node_id)
    if node_id <= 0 or not isinstance(node, dict):
        set_flash(request, "目标节点无权限或不存在")
        return RedirectResponse(url="/remote-storage", status_code=303)

    task_id, queued, err_text = _enqueue_remote_profile_mount_task(
        profile_id=str(profile.get("id") or profile_id or ""),
        node_id=int(node_id),
        action="mount",
        actor=str(user or ""),
        password_override=_safe_text(password, max_len=128),
    )
    if queued and task_id > 0:
        set_flash(request, f"挂载队列任务 #{task_id} 已提交，等待节点上报执行（失败原因会写入挂载信息）。")
    else:
        _update_remote_profile_mount_result(str(profile.get("id") or profile_id or ""), "mount", False, err_text or "任务提交失败")
        set_flash(request, f"挂载任务提交失败：{err_text or '未知错误'}")
    return RedirectResponse(url="/remote-storage", status_code=303)


@router.post("/remote-storage/profiles/{profile_id}/unmount")
async def remote_storage_profile_unmount(
    request: Request,
    profile_id: str,
    password: str = Form(""),
    user: str = Depends(require_role_page("nodes.write")),
):
    rows = _load_remote_storage_profiles()
    idx, profile = _find_remote_storage_profile(rows, profile_id)
    if idx < 0 or not isinstance(profile, dict):
        set_flash(request, "挂载方案不存在")
        return RedirectResponse(url="/remote-storage", status_code=303)

    nodes = filter_nodes_for_user(user, list_nodes())
    node_map: Dict[int, Dict[str, Any]] = {}
    for n in nodes:
        nid = _safe_int((n or {}).get("id"), 0)
        if nid > 0:
            node_map[nid] = n
    node_id = _safe_int(profile.get("target_node_id"), 0)
    node = node_map.get(node_id)
    if node_id <= 0 or not isinstance(node, dict):
        set_flash(request, "目标节点无权限或不存在")
        return RedirectResponse(url="/remote-storage", status_code=303)

    task_id, queued, err_text = _enqueue_remote_profile_mount_task(
        profile_id=str(profile.get("id") or profile_id or ""),
        node_id=int(node_id),
        action="unmount",
        actor=str(user or ""),
        password_override=_safe_text(password, max_len=128),
    )
    if queued and task_id > 0:
        set_flash(request, f"卸载队列任务 #{task_id} 已提交，等待节点上报执行（失败原因会写入挂载信息）。")
    else:
        _update_remote_profile_mount_result(str(profile.get("id") or profile_id or ""), "unmount", False, err_text or "任务提交失败")
        set_flash(request, f"卸载任务提交失败：{err_text or '未知错误'}")
    return RedirectResponse(url="/remote-storage", status_code=303)


async def _remote_storage_profile_files_open(
    request: Request,
    profile_id: str,
    path: str = "",
    password: str = "",
    user: str = "",
):
    rows, idx, profile, node, _node_name_map = _remote_storage_profile_context(user, profile_id)
    if idx < 0 or not isinstance(profile, dict):
        set_flash(request, "挂载方案不存在")
        return RedirectResponse(url="/remote-storage", status_code=303)
    if not isinstance(node, dict):
        set_flash(request, "目标节点无权限或不存在")
        return RedirectResponse(url="/remote-storage", status_code=303)

    if not _remote_storage_profile_root_path(profile):
        set_flash(request, "挂载点无效，无法打开文件管理")
        return RedirectResponse(url="/remote-storage", status_code=303)

    if _request_has_nodes_write_permission(request):
        mount_status = _normalize_remote_mount_status(profile.get("mount_status"), default="unknown")
        if mount_status != "mounted":
            task_id, queued, err_text = _enqueue_remote_profile_mount_task(
                profile_id=str(profile.get("id") or profile_id or ""),
                node_id=int(_safe_int((profile or {}).get("target_node_id"), 0)),
                action="mount",
                actor=str(user or ""),
                password_override=_safe_text(password, max_len=128),
            )
            if queued and task_id > 0:
                set_flash(request, f"已提交自动挂载队列任务 #{task_id}，请等待节点上报执行后再打开文件管理（失败原因会写入挂载信息）。")
            else:
                _update_remote_profile_mount_result(str(profile.get("id") or profile_id or ""), "mount", False, err_text or "任务提交失败")
                set_flash(request, f"自动挂载任务提交失败：{err_text or '未知错误'}")
            return RedirectResponse(url="/remote-storage", status_code=303)
    else:
        if _normalize_remote_mount_status(profile.get("mount_status"), default="unknown") != "mounted":
            set_flash(request, "当前账号没有挂载权限；若目录不可访问，请联系管理员先执行挂载。")

    can_manage = bool(_request_has_nodes_write_permission(request))
    if can_manage:
        site = _ensure_remote_profile_site(profile)
    else:
        exists = _remote_profile_sites(profile.get("id"))
        site = None
        target_node_id = max(0, _safe_int(profile.get("target_node_id"), 0))
        target_root = _remote_storage_profile_root_path(profile)
        for row in exists:
            if not isinstance(row, dict):
                continue
            row_node_id = max(0, _safe_int(row.get("node_id"), 0))
            row_root = str(row.get("root_path") or "").strip()
            if target_node_id > 0 and row_node_id != target_node_id:
                continue
            if target_root and row_root and row_root != target_root:
                continue
            site = row
            break
        if site is None and exists:
            site = exists[0]
    site_id = max(0, _safe_int((site or {}).get("id"), 0))
    if site_id <= 0:
        if can_manage:
            set_flash(request, "文件管理初始化失败：未能创建挂载文件工作区")
        else:
            set_flash(request, "文件管理尚未初始化，请联系管理员先执行一次挂载文件管理")
        return RedirectResponse(url="/remote-storage", status_code=303)
    return RedirectResponse(url=_remote_profile_files_url_by_site(site_id, path), status_code=303)


@router.get("/remote-storage/profiles/{profile_id}/files")
async def remote_storage_profile_files(
    request: Request,
    profile_id: str,
    path: str = "",
    user: str = Depends(require_role_page("nodes.read")),
):
    return await _remote_storage_profile_files_open(
        request=request,
        profile_id=profile_id,
        path=path,
        password="",
        user=user,
    )


@router.post("/remote-storage/profiles/{profile_id}/files")
async def remote_storage_profile_files_post(
    request: Request,
    profile_id: str,
    path: str = Form(""),
    password: str = Form(""),
    user: str = Depends(require_role_page("nodes.read")),
):
    return await _remote_storage_profile_files_open(
        request=request,
        profile_id=profile_id,
        path=path,
        password=password,
        user=user,
    )


@router.get("/remote-storage/profiles/{profile_id}/files/view", response_class=HTMLResponse)
async def remote_storage_profile_files_view(
    request: Request,
    profile_id: str,
    path: str = "",
    user: str = Depends(require_role_page("nodes.read")),
):
    return await _remote_storage_profile_files_open(
        request=request,
        profile_id=profile_id,
        path=path,
        password="",
        user=user,
    )


def _remote_storage_file_op_redirect(profile_id: str, path: str = "") -> RedirectResponse:
    return RedirectResponse(url=_remote_storage_files_view_url(profile_id, path), status_code=303)


@router.post("/remote-storage/profiles/{profile_id}/files/mkdir")
async def remote_storage_profile_files_mkdir(
    request: Request,
    profile_id: str,
    path: str = Form(""),
    name: str = Form(""),
    user: str = Depends(require_role_page("nodes.write")),
):
    _rows, _idx, profile, node, _node_name_map = _remote_storage_profile_context(user, profile_id)
    if not isinstance(profile, dict):
        set_flash(request, "挂载方案不存在")
        return RedirectResponse(url="/remote-storage", status_code=303)
    if not isinstance(node, dict):
        set_flash(request, "目标节点无权限或不存在")
        return RedirectResponse(url="/remote-storage", status_code=303)
    if bool(profile.get("read_only")):
        set_flash(request, "只读挂载不允许创建目录")
        return _remote_storage_file_op_redirect(profile_id, path)

    rel_path = ""
    if path:
        try:
            rel_path = _normalize_rel_path(path)
        except Exception:
            set_flash(request, "路径不合法")
            return _remote_storage_file_op_redirect(profile_id, "")
    folder_name = str(name or "").strip()
    if not folder_name:
        set_flash(request, "目录名不能为空")
        return _remote_storage_file_op_redirect(profile_id, rel_path)
    root = _remote_storage_profile_root_path(profile)
    if not root:
        set_flash(request, "挂载点无效，无法创建目录")
        return _remote_storage_file_op_redirect(profile_id, rel_path)

    payload = {"root": root, "path": rel_path, "name": folder_name, "root_base": root}
    try:
        base_url, verify_tls = _direct_agent_request_target(node)
        data = await agent_post(
            base_url,
            str(node.get("api_key") or ""),
            "/api/v1/website/files/mkdir",
            payload,
            verify_tls,
            timeout=12.0,
        )
        if not bool((data or {}).get("ok", True)):
            raise AgentError(str((data or {}).get("error") or "创建目录失败"))
        set_flash(request, "目录创建成功")
    except Exception as exc:
        set_flash(request, f"创建目录失败：{exc}")
    return _remote_storage_file_op_redirect(profile_id, rel_path)


@router.post("/remote-storage/profiles/{profile_id}/files/upload")
async def remote_storage_profile_files_upload(
    request: Request,
    profile_id: str,
    path: str = Form(""),
    files: Optional[List[UploadFile]] = File(None),
    user: str = Depends(require_role_page("nodes.write")),
):
    _rows, _idx, profile, node, _node_name_map = _remote_storage_profile_context(user, profile_id)
    if not isinstance(profile, dict):
        set_flash(request, "挂载方案不存在")
        return RedirectResponse(url="/remote-storage", status_code=303)
    if not isinstance(node, dict):
        set_flash(request, "目标节点无权限或不存在")
        return RedirectResponse(url="/remote-storage", status_code=303)
    if bool(profile.get("read_only")):
        set_flash(request, "只读挂载不允许上传文件")
        return _remote_storage_file_op_redirect(profile_id, path)
    root = _remote_storage_profile_root_path(profile)
    if not root:
        set_flash(request, "挂载点无效，无法上传")
        return _remote_storage_file_op_redirect(profile_id, path)

    rel_path = ""
    if path:
        try:
            rel_path = _normalize_rel_path(path)
        except Exception:
            set_flash(request, "路径不合法")
            return _remote_storage_file_op_redirect(profile_id, "")

    uploads = files if isinstance(files, list) else []
    if not uploads:
        set_flash(request, "请先选择要上传的文件")
        return _remote_storage_file_op_redirect(profile_id, rel_path)

    ok_count = 0
    fail_count = 0
    fail_samples: List[str] = []
    base_url, verify_tls = _direct_agent_request_target(node)
    try:
        for upload in uploads:
            if upload is None:
                continue
            raw_name = str(upload.filename or "").replace("\\", "/").split("/")[-1].strip()
            if not raw_name:
                continue
            content = await upload.read()
            if len(content) > int(_REMOTE_STORAGE_UPLOAD_MAX_BYTES):
                fail_count += 1
                if len(fail_samples) < 5:
                    fail_samples.append(f"{raw_name}: 文件超过 {_format_bytes_h(_REMOTE_STORAGE_UPLOAD_MAX_BYTES)} 限制")
                continue
            payload = {
                "root": root,
                "path": rel_path,
                "filename": raw_name,
                "content_b64": base64.b64encode(content).decode("ascii"),
                "allow_empty": True,
                "root_base": root,
            }
            try:
                data = await agent_post(
                    base_url,
                    str(node.get("api_key") or ""),
                    "/api/v1/website/files/upload",
                    payload,
                    verify_tls,
                    timeout=60.0,
                )
                if not bool((data or {}).get("ok", True)):
                    raise AgentError(str((data or {}).get("error") or "上传失败"))
                ok_count += 1
            except Exception as exc:
                fail_count += 1
                if len(fail_samples) < 5:
                    fail_samples.append(f"{raw_name}: {exc}")
    finally:
        for upload in uploads:
            if upload is None:
                continue
            try:
                await upload.close()
            except Exception:
                pass

    if fail_count <= 0:
        set_flash(request, f"上传成功（{ok_count} 个文件）")
    else:
        msg = f"上传完成：成功 {ok_count} 个，失败 {fail_count} 个"
        if fail_samples:
            msg += f"。示例：{'；'.join(fail_samples)}"
        set_flash(request, msg)
    return _remote_storage_file_op_redirect(profile_id, rel_path)


@router.get("/remote-storage/profiles/{profile_id}/files/edit", response_class=HTMLResponse)
async def remote_storage_profile_files_edit(
    request: Request,
    profile_id: str,
    path: str,
    user: str = Depends(require_role_page("nodes.read")),
):
    _rows, _idx, profile, node, _node_name_map = _remote_storage_profile_context(user, profile_id)
    if not isinstance(profile, dict):
        set_flash(request, "挂载方案不存在")
        return RedirectResponse(url="/remote-storage", status_code=303)
    if not isinstance(node, dict):
        set_flash(request, "目标节点无权限或不存在")
        return RedirectResponse(url="/remote-storage", status_code=303)
    root = _remote_storage_profile_root_path(profile)
    if not root:
        set_flash(request, "挂载点无效，无法读取文件")
        return _remote_storage_file_op_redirect(profile_id, "")

    try:
        rel_path = _normalize_rel_path(path)
    except Exception:
        set_flash(request, "文件路径不合法")
        return _remote_storage_file_op_redirect(profile_id, "")
    if not rel_path:
        set_flash(request, "文件路径不能为空")
        return _remote_storage_file_op_redirect(profile_id, "")

    content = ""
    error = ""
    try:
        base_url, verify_tls = _direct_agent_request_target(node)
        q = urlencode({"root": root, "path": rel_path, "root_base": root})
        data = await agent_get(
            base_url,
            str(node.get("api_key") or ""),
            f"/api/v1/website/files/read?{q}",
            verify_tls,
            timeout=12.0,
        )
        if not bool((data or {}).get("ok", True)):
            raise AgentError(str((data or {}).get("error") or "读取文件失败"))
        content = str((data or {}).get("content") or "")
    except Exception as exc:
        error = str(exc)

    profile_view = dict(profile)
    profile_view["id"] = _normalize_remote_profile_id(profile.get("id"))
    profile_view["name"] = str(profile.get("name") or "挂载方案")
    return templates.TemplateResponse(
        "site_file_edit.html",
        {
            "request": request,
            "user": user,
            "flash": flash(request),
            "title": f"{'查看文件' if profile.get('read_only') else '编辑文件'} · {profile_view.get('name')}",
            "site": profile_view,
            "node": node,
            "path": rel_path,
            "content": content,
            "error": error,
            "is_read_only_mount": bool(profile.get("read_only")),
            "read_only_mount_label": str(profile.get("name") or ""),
            "embed_mode": False,
            "files_base": f"/remote-storage/profiles/{profile_view.get('id')}/files",
            "show_site_nav": False,
        },
    )


@router.post("/remote-storage/profiles/{profile_id}/files/save")
async def remote_storage_profile_files_save(
    request: Request,
    profile_id: str,
    path: str = Form(""),
    content: str = Form(""),
    user: str = Depends(require_role_page("nodes.write")),
):
    _rows, _idx, profile, node, _node_name_map = _remote_storage_profile_context(user, profile_id)
    if not isinstance(profile, dict):
        set_flash(request, "挂载方案不存在")
        return RedirectResponse(url="/remote-storage", status_code=303)
    if not isinstance(node, dict):
        set_flash(request, "目标节点无权限或不存在")
        return RedirectResponse(url="/remote-storage", status_code=303)
    if bool(profile.get("read_only")):
        set_flash(request, "只读挂载不允许保存文件")
        return _remote_storage_file_op_redirect(profile_id, _remote_storage_parent_path(path))

    try:
        rel_path = _normalize_rel_path(path)
    except Exception:
        set_flash(request, "文件路径不合法")
        return _remote_storage_file_op_redirect(profile_id, "")
    if not rel_path:
        set_flash(request, "文件路径不能为空")
        return _remote_storage_file_op_redirect(profile_id, "")

    root = _remote_storage_profile_root_path(profile)
    if not root:
        set_flash(request, "挂载点无效，无法保存")
        return _remote_storage_file_op_redirect(profile_id, "")

    payload = {"root": root, "path": rel_path, "content": str(content or ""), "root_base": root}
    try:
        base_url, verify_tls = _direct_agent_request_target(node)
        data = await agent_post(
            base_url,
            str(node.get("api_key") or ""),
            "/api/v1/website/files/write",
            payload,
            verify_tls,
            timeout=12.0,
        )
        if not bool((data or {}).get("ok", True)):
            raise AgentError(str((data or {}).get("error") or "保存失败"))
        set_flash(request, "保存成功")
    except Exception as exc:
        set_flash(request, f"保存失败：{exc}")
    return _remote_storage_file_op_redirect(profile_id, _remote_storage_parent_path(rel_path))


@router.post("/remote-storage/profiles/{profile_id}/files/delete")
async def remote_storage_profile_files_delete(
    request: Request,
    profile_id: str,
    path: str = Form(""),
    user: str = Depends(require_role_page("nodes.write")),
):
    _rows, _idx, profile, node, _node_name_map = _remote_storage_profile_context(user, profile_id)
    if not isinstance(profile, dict):
        set_flash(request, "挂载方案不存在")
        return RedirectResponse(url="/remote-storage", status_code=303)
    if not isinstance(node, dict):
        set_flash(request, "目标节点无权限或不存在")
        return RedirectResponse(url="/remote-storage", status_code=303)
    if bool(profile.get("read_only")):
        set_flash(request, "只读挂载不允许删除")
        return _remote_storage_file_op_redirect(profile_id, _remote_storage_parent_path(path))

    try:
        rel_path = _normalize_rel_path(path)
    except Exception:
        set_flash(request, "路径不合法")
        return _remote_storage_file_op_redirect(profile_id, "")
    if not rel_path:
        set_flash(request, "禁止删除根目录")
        return _remote_storage_file_op_redirect(profile_id, "")

    root = _remote_storage_profile_root_path(profile)
    if not root:
        set_flash(request, "挂载点无效，无法删除")
        return _remote_storage_file_op_redirect(profile_id, "")

    payload = {"root": root, "path": rel_path, "root_base": root}
    try:
        base_url, verify_tls = _direct_agent_request_target(node)
        data = await agent_post(
            base_url,
            str(node.get("api_key") or ""),
            "/api/v1/website/files/delete",
            payload,
            verify_tls,
            timeout=12.0,
        )
        if not bool((data or {}).get("ok", True)):
            raise AgentError(str((data or {}).get("error") or "删除失败"))
        set_flash(request, "删除成功")
    except Exception as exc:
        set_flash(request, f"删除失败：{exc}")
    return _remote_storage_file_op_redirect(profile_id, _remote_storage_parent_path(rel_path))


@router.post("/remote-storage/profiles/{profile_id}/files/unzip")
async def remote_storage_profile_files_unzip(
    request: Request,
    profile_id: str,
    path: str = Form(""),
    dest: str = Form(""),
    user: str = Depends(require_role_page("nodes.write")),
):
    _rows, _idx, profile, node, _node_name_map = _remote_storage_profile_context(user, profile_id)
    if not isinstance(profile, dict):
        set_flash(request, "挂载方案不存在")
        return RedirectResponse(url="/remote-storage", status_code=303)
    if not isinstance(node, dict):
        set_flash(request, "目标节点无权限或不存在")
        return RedirectResponse(url="/remote-storage", status_code=303)
    if bool(profile.get("read_only")):
        set_flash(request, "只读挂载不允许解压")
        return _remote_storage_file_op_redirect(profile_id, dest or path)

    try:
        rel_path = _normalize_rel_path(path)
    except Exception:
        set_flash(request, "压缩包路径不合法")
        return _remote_storage_file_op_redirect(profile_id, "")
    if not rel_path:
        set_flash(request, "压缩包路径不能为空")
        return _remote_storage_file_op_redirect(profile_id, "")

    rel_dest = ""
    if dest:
        try:
            rel_dest = _normalize_rel_path(dest)
        except Exception:
            rel_dest = ""

    root = _remote_storage_profile_root_path(profile)
    if not root:
        set_flash(request, "挂载点无效，无法解压")
        return _remote_storage_file_op_redirect(profile_id, "")

    payload = {"root": root, "path": rel_path, "dest": rel_dest, "root_base": root}
    try:
        base_url, verify_tls = _direct_agent_request_target(node)
        data = await agent_post(
            base_url,
            str(node.get("api_key") or ""),
            "/api/v1/website/files/unzip",
            payload,
            verify_tls,
            timeout=60.0,
        )
        if not bool((data or {}).get("ok", True)):
            raise AgentError(str((data or {}).get("error") or "解压失败"))
        set_flash(request, "解压成功")
    except Exception as exc:
        set_flash(request, f"解压失败：{exc}")
    return _remote_storage_file_op_redirect(profile_id, rel_dest or _remote_storage_parent_path(rel_path))


@router.get("/remote-storage/profiles/{profile_id}/files/download")
async def remote_storage_profile_files_download(
    request: Request,
    profile_id: str,
    path: str,
    user: str = Depends(require_role_page("nodes.read")),
):
    _rows, _idx, profile, node, _node_name_map = _remote_storage_profile_context(user, profile_id)
    if not isinstance(profile, dict):
        set_flash(request, "挂载方案不存在")
        return RedirectResponse(url="/remote-storage", status_code=303)
    if not isinstance(node, dict):
        set_flash(request, "目标节点无权限或不存在")
        return RedirectResponse(url="/remote-storage", status_code=303)
    root = _remote_storage_profile_root_path(profile)
    if not root:
        set_flash(request, "挂载点无效，无法下载")
        return _remote_storage_file_op_redirect(profile_id, "")

    try:
        rel_path = _normalize_rel_path(path)
    except Exception:
        set_flash(request, "下载路径不合法")
        return _remote_storage_file_op_redirect(profile_id, "")
    if not rel_path:
        set_flash(request, "下载路径不能为空")
        return _remote_storage_file_op_redirect(profile_id, "")

    base_url, verify_tls = _direct_agent_request_target(node)
    headers_extra: Dict[str, Any] = {}
    req_range = str(request.headers.get("range") or "").strip()
    if req_range:
        headers_extra["range"] = req_range
    req_if_range = str(request.headers.get("if-range") or "").strip()
    if req_if_range:
        headers_extra["if-range"] = req_if_range
    try:
        upstream = await agent_get_raw_stream(
            base_url,
            str(node.get("api_key") or ""),
            "/api/v1/website/files/raw",
            verify_tls,
            params={"root": root, "path": rel_path, "root_base": root},
            timeout=600.0,
            headers_extra=(headers_extra or None),
        )
    except Exception as exc:
        set_flash(request, f"下载失败：{exc}")
        return _remote_storage_file_op_redirect(profile_id, _remote_storage_parent_path(rel_path))

    status_code = int(upstream.status_code or 500)
    if status_code not in (200, 206):
        detail = ""
        try:
            body = await upstream.aread()
            detail = (body or b"").decode(errors="ignore").strip()
        except Exception:
            detail = ""
        try:
            await upstream.aclose()
        except Exception:
            pass
        if detail:
            set_flash(request, f"下载失败（HTTP {status_code}）：{detail[:120]}")
        else:
            set_flash(request, f"下载失败（HTTP {status_code}）")
        return _remote_storage_file_op_redirect(profile_id, _remote_storage_parent_path(rel_path))

    filename = rel_path.split("/")[-1] or "download.bin"
    resp_headers = _download_response_headers(filename, upstream.headers.get("content-length"))
    for src, dst in (
        ("content-range", "Content-Range"),
        ("accept-ranges", "Accept-Ranges"),
        ("etag", "ETag"),
        ("last-modified", "Last-Modified"),
    ):
        val = str(upstream.headers.get(src) or "").strip()
        if val:
            resp_headers[dst] = val
    media_type = str(upstream.headers.get("content-type") or "application/octet-stream")

    async def _iter_bytes():
        try:
            async for chunk in upstream.aiter_raw(chunk_size=256 * 1024):
                if chunk:
                    yield chunk
        finally:
            try:
                await upstream.aclose()
            except Exception:
                pass

    return StreamingResponse(_iter_bytes(), status_code=status_code, media_type=media_type, headers=resp_headers)


@router.post("/remote-storage/profiles/{profile_id}/delete")
async def remote_storage_profile_delete(
    request: Request,
    profile_id: str,
    user: str = Depends(require_role_page("nodes.write")),
):
    pid = _normalize_remote_profile_id(profile_id)
    if not pid:
        set_flash(request, "挂载方案不存在")
        return RedirectResponse(url="/remote-storage", status_code=303)

    rows = _load_remote_storage_profiles()
    keep: List[Dict[str, Any]] = []
    removed: Optional[Dict[str, Any]] = None
    for item in rows:
        cur = str((item or {}).get("id") or "")
        if cur == pid and removed is None:
            removed = item
            continue
        keep.append(item)
    if removed is None:
        set_flash(request, "挂载方案不存在或已删除")
        return RedirectResponse(url="/remote-storage", status_code=303)

    node_id = _safe_int((removed or {}).get("target_node_id"), 0)
    node_name = ""
    nodes = filter_nodes_for_user(user, list_nodes())
    node_map: Dict[int, Dict[str, Any]] = {}
    for n in nodes:
        nid = _safe_int((n or {}).get("id"), 0)
        if nid <= 0:
            continue
        node_map[nid] = n
        if nid == node_id:
            node_name = str((n or {}).get("name") or "")

    unmount_ok = False
    unmount_msg = ""
    unmount_task_id = 0
    unmount_queued = False
    node = node_map.get(node_id)
    if isinstance(node, dict) and node_id > 0:
        unmount_task_id, unmount_queued, unmount_msg = _enqueue_remote_profile_mount_task(
            profile_id=str((removed or {}).get("id") or ""),
            node_id=int(node_id),
            action="unmount",
            actor=str(user or ""),
            password_override="",
        )
        unmount_ok = bool(unmount_queued and unmount_task_id > 0)

    _save_remote_storage_profiles(keep)
    _purge_legacy_remote_profile_sites(pid)
    _audit_log_node_action(
        request=request,
        user=user,
        action="remote_storage.profile.delete",
        node_id=int(node_id),
        node_name=node_name,
        detail={
            "profile_id": str((removed or {}).get("id") or ""),
            "profile_name": str((removed or {}).get("name") or ""),
            "protocol": str((removed or {}).get("protocol") or ""),
            "unmount_ok": bool(unmount_ok),
            "unmount_task_id": int(unmount_task_id),
            "unmount_queued": bool(unmount_queued),
            "unmount_message": str(unmount_msg or ""),
        },
    )
    if unmount_task_id > 0 and unmount_queued:
        set_flash(request, f"远程挂载方案已删除（卸载队列任务 #{unmount_task_id} 已提交，等待节点上报执行）")
    elif unmount_msg and not unmount_ok:
        set_flash(request, f"远程挂载方案已删除（卸载提醒：{_safe_text(unmount_msg, max_len=120)}）")
    else:
        set_flash(request, "远程挂载方案已删除")
    return RedirectResponse(url="/remote-storage", status_code=303)


@router.get("/nodes/new", response_class=HTMLResponse)
async def node_new_page(request: Request, user: str = Depends(require_login_page)):
    api_key = generate_api_key()
    return templates.TemplateResponse(
        "nodes_new.html",
        {
            "request": request,
            "user": user,
            "flash": flash(request),
            "title": "添加机器",
            "api_key": api_key,
            "default_port": DEFAULT_AGENT_PORT,
        },
    )


@router.post("/nodes/new")
async def node_new_action(
    request: Request,
    user: str = Depends(require_role_page("nodes.write")),
    name: str = Form(""),
    group_name: str = Form("默认分组"),
    is_private: Optional[str] = Form(None),
    is_website: Optional[str] = Form(None),
    website_root_base: str = Form(""),
    ip_address: str = Form(...),
    scheme: str = Form("http"),
    system_type: str = Form("auto"),
    api_key: str = Form(""),
    verify_tls: Optional[str] = Form(None),
):
    _ = user

    ip_address = ip_address.strip()
    api_key = api_key.strip() or generate_api_key()
    scheme = scheme.strip().lower() or "http"
    if scheme not in ("http", "https"):
        set_flash(request, "协议仅支持 http 或 https")
        return RedirectResponse(url="/nodes/new", status_code=303)
    if not ip_address:
        set_flash(request, "IP 地址不能为空")
        return RedirectResponse(url="/nodes/new", status_code=303)
    if "://" not in ip_address:
        ip_address = f"{scheme}://{ip_address}"

    # 端口在 UI 中隐藏：
    # - 默认使用 Agent 标准端口 18700
    # - 如用户在 IP 中自带 :port，则仍可解析并写入 base_url（兼容特殊环境）
    port_value = DEFAULT_AGENT_PORT
    host, parsed_port, has_port, scheme = split_host_and_port(ip_address, port_value)
    if verify_tls is None:
        verify_tls = (scheme == "https")
    if not host:
        set_flash(request, "IP 地址不能为空")
        return RedirectResponse(url="/nodes/new", status_code=303)
    if has_port:
        port_value = parsed_port

    base_url = f"{scheme}://{format_host_for_url(host)}:{port_value}"  # 不在 UI 展示端口

    # name 为空则默认使用“纯 IP/Host”
    display_name = (name or "").strip() or extract_ip_for_display(base_url)

    verify_tls_flag = bool(verify_tls) if verify_tls is not None else (scheme == "https")
    role = "website" if is_website else "normal"
    root_base = (website_root_base or "").strip()
    system_type_val = normalize_node_system_type(system_type, default="auto")
    if system_type_val == "macos":
        role = "normal"
        root_base = ""
    if role == "website" and not root_base:
        root_base = "/www"
    if role != "website":
        root_base = ""

    node_id = add_node(
        display_name,
        base_url,
        api_key,
        verify_tls=verify_tls_flag,
        is_private=bool(is_private),
        group_name=group_name,
        role=role,
        website_root_base=root_base,
        system_type=system_type_val,
    )
    _audit_log_node_action(
        request=request,
        user=user,
        action="node.create",
        node_id=int(node_id),
        node_name=str(display_name or ""),
        detail={
            "source": "pages.new_form",
            "base_url": str(base_url),
            "group_name": str(group_name),
            "is_private": bool(is_private),
            "role": str(role),
            "website_root_base": str(root_base or ""),
            "system_type": str(system_type_val),
        },
    )
    request.session["show_install_cmd"] = True
    set_flash(request, "已添加机器")
    return RedirectResponse(url=f"/nodes/{node_id}", status_code=303)


@router.post("/nodes/add")
async def node_add_action(
    request: Request,
    user: str = Depends(require_role_page("nodes.write")),
    name: str = Form(""),
    group_name: str = Form("默认分组"),
    is_private: Optional[str] = Form(None),
    is_website: Optional[str] = Form(None),
    website_root_base: str = Form(""),
    system_type: str = Form("auto"),
    base_url: str = Form(...),
    api_key: str = Form(...),
    verify_tls: Optional[str] = Form(None),
):
    _ = user

    base_url = base_url.strip()
    api_key = api_key.strip()
    if not base_url or not api_key:
        set_flash(request, "API 地址与 Token 不能为空")
        return RedirectResponse(url="/", status_code=303)

    # Default to TLS verification for https:// URLs when checkbox is omitted.
    # urlparse may raise on malformed bracketed IPv6 like "http://[::1".
    try:
        scheme2 = (urlparse(base_url).scheme or "http").lower()
    except Exception:
        scheme2 = "http"
    verify_tls_flag = bool(verify_tls) if verify_tls is not None else (scheme2 == "https")
    system_type_val = normalize_node_system_type(system_type, default="auto")
    role = "website" if is_website else "normal"
    website_root_val = (website_root_base or "").strip()
    if system_type_val == "macos":
        role = "normal"
        website_root_val = ""
    if role == "website" and not website_root_val:
        website_root_val = "/www"
    if role != "website":
        website_root_val = ""

    node_id = add_node(
        name or base_url,
        base_url,
        api_key,
        verify_tls=verify_tls_flag,
        is_private=bool(is_private),
        group_name=group_name,
        role=role,
        website_root_base=website_root_val,
        system_type=system_type_val,
    )
    _audit_log_node_action(
        request=request,
        user=user,
        action="node.create",
        node_id=int(node_id),
        node_name=str(name or base_url),
        detail={
            "source": "pages.add_form",
            "base_url": str(base_url),
            "group_name": str(group_name),
            "is_private": bool(is_private),
            "role": str(role),
            "website_root_base": str(website_root_val),
            "system_type": str(system_type_val),
        },
    )
    set_flash(request, "已添加节点")
    return RedirectResponse(url=f"/nodes/{node_id}", status_code=303)


@router.post("/nodes/{node_id}/delete")
async def node_delete(request: Request, node_id: int, user: str = Depends(require_role_page("nodes.delete"))):
    node = get_node(int(node_id))
    delete_node(node_id)
    _audit_log_node_action(
        request=request,
        user=user,
        action="node.delete",
        node_id=int(node_id),
        node_name=str((node or {}).get("name") or ""),
        detail={
            "source": "pages.delete_form",
            "base_url": str((node or {}).get("base_url") or ""),
        },
    )
    set_flash(request, "已删除机器")
    return RedirectResponse(url="/", status_code=303)


@router.get("/nodes/{node_id}", response_class=HTMLResponse)
async def node_detail(request: Request, node_id: int, user: str = Depends(require_login_page)):
    node = get_node(node_id)
    if not node:
        set_flash(request, "机器不存在")
        return RedirectResponse(url="/", status_code=303)

    # 用于节点页左侧快速切换列表
    nodes = filter_nodes_for_user(user, list_nodes())
    node_id_safe = _safe_int(node.get("id"), 0)
    if node_id_safe <= 0 or node_id_safe not in {_safe_int((n or {}).get("id"), 0) for n in nodes}:
        set_flash(request, "机器不存在或无权限")
        return RedirectResponse(url="/", status_code=303)

    group_orders = get_group_orders()

    def _gk(name: str) -> tuple[int, str]:
        n = (name or "").strip() or "默认分组"
        try:
            order = int(group_orders.get(n, 1000))
        except Exception:
            order = 1000
        return (order, n)

    for n in nodes:
        n["display_ip"] = extract_ip_for_display(n.get("base_url", ""))
        # 用更宽松的阈值显示在线状态（避免轻微抖动导致频繁显示离线）
        n["online"] = is_report_fresh(n, max_age_sec=90)

    # 节点页左侧列表：按分组聚合展示
    def _gn(x: Dict[str, Any]) -> str:
        g = str(x.get("group_name") or "").strip()
        return g or "默认分组"

    for n in nodes:
        n["group_name"] = _gn(n)

    nodes_sorted = sorted(
        nodes,
        key=lambda x: (
            _gk(_gn(x)),
            0 if bool(x.get("online")) else 1,
            -_safe_int(x.get("id"), 0),
        ),
    )

    node_groups: List[Dict[str, Any]] = []
    cur = None
    buf: List[Dict[str, Any]] = []
    for n in nodes_sorted:
        g = _gn(n)
        if cur is None:
            cur = g
        if g != cur:
            node_groups.append(
                {
                    "name": cur,
                    "sort_order": _gk(cur)[0],
                    "nodes": buf,
                    "online": sum(1 for i in buf if i.get("online")),
                    "total": len(buf),
                }
            )
            cur = g
            buf = []
        buf.append(n)

    if cur is not None:
        node_groups.append(
            {
                "name": cur,
                "sort_order": _gk(cur)[0],
                "nodes": buf,
                "online": sum(1 for i in buf if i.get("online")),
                "total": len(buf),
            }
        )

    show_install_cmd = bool(request.session.pop("show_install_cmd", False))
    show_edit_node = str(request.query_params.get("edit") or "").strip() in ("1", "true", "yes")

    base_url = panel_bootstrap_base_url(request)
    node["display_ip"] = extract_ip_for_display(node.get("base_url", ""))
    curl_tls_opt = "-k " if (panel_bootstrap_insecure_tls(default=True) and str(base_url).lower().startswith("https://")) else ""

    # 在线判定：默认心跳 30s，取 3 倍窗口避免误判
    node["online"] = is_report_fresh(node, max_age_sec=90)

    # ✅ 一键接入 / 卸载命令（短命令，避免超长）
    # 说明：使用 node.api_key 作为 join token，脚本由面板返回并带参数执行。
    token = node["api_key"]
    curl_retry_opt_probe = (
        "CURL_RETRY_ALL_ERRORS=''; "
        "curl --help all 2>/dev/null | grep -q -- '--retry-all-errors' "
        "&& CURL_RETRY_ALL_ERRORS='--retry-all-errors'; "
    )
    install_cmd = (
        f"{curl_retry_opt_probe}"
        f"curl {curl_tls_opt}-fL --retry 5 $CURL_RETRY_ALL_ERRORS --connect-timeout 10 "
        f"-H \"X-Join-Token: {token}\" -o /tmp/realm-join.sh {base_url}/join "
        f"&& bash /tmp/realm-join.sh && rm -f /tmp/realm-join.sh"
    )
    uninstall_cmd = (
        f"{curl_retry_opt_probe}"
        f"curl {curl_tls_opt}-fL --retry 5 $CURL_RETRY_ALL_ERRORS --connect-timeout 10 "
        f"-H \"X-Join-Token: {token}\" -o /tmp/realm-uninstall.sh {base_url}/uninstall "
        f"&& bash /tmp/realm-uninstall.sh && rm -f /tmp/realm-uninstall.sh"
    )

    # 兼容旧字段（模板里可能还引用 node_port）
    agent_port = DEFAULT_AGENT_PORT

    return templates.TemplateResponse(
        "node.html",
        {
            "request": request,
            "user": user,
            "nodes": nodes,
            "node_groups": node_groups,
            "node": node,
            "flash": flash(request),
            "title": node["name"],
            "node_port": agent_port,
            "install_cmd": install_cmd,
            "uninstall_cmd": uninstall_cmd,
            "show_install_cmd": show_install_cmd,
            "show_edit_node": show_edit_node,
        },
    )
