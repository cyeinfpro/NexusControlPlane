from __future__ import annotations

import asyncio
import base64
import copy
from collections import Counter
import hashlib
import inspect
import io
import json
import logging
import os
import random
import re
import tempfile
import threading
import time
import uuid
import zipfile
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote, urlencode, urlparse

from fastapi import APIRouter, Depends, File, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse, Response
from starlette.background import BackgroundTask

from ..auth import (
    can_access_rule_endpoint,
    filter_nodes_for_user,
    get_user_by_username,
    is_rule_owner_scoped,
    stamp_endpoint_owner,
)
from ..clients.agent import agent_get, agent_get_raw_stream, agent_ping, agent_post
from ..core.bg_tasks import spawn_background_task
from ..core.deps import require_login
from ..core.settings import DEFAULT_AGENT_PORT
from ..db import (
    add_audit_log,
    add_certificate,
    add_netmon_monitor,
    add_node,
    add_site,
    bump_traffic_reset_version,
    connect,
    create_user_record,
    get_role_by_name,
    get_desired_pool,
    get_group_orders,
    get_last_report,
    get_last_reports,
    get_node,
    get_node_runtime,
    get_node_by_api_key,
    get_node_by_base_url,
    insert_netmon_samples,
    node_auto_restart_policy_from_row,
    normalize_node_system_type,
    list_certificates,
    list_netmon_monitors,
    list_netmon_samples,
    list_roles,
    list_panel_settings,
    list_rule_stats_series,
    list_sites,
    upsert_role,
    upsert_site_file_favorite,
    clear_rule_stats_samples,
    clear_node_direct_tunnel,
    list_nodes,
    list_nodes_runtime,
    set_node_direct_tunnel,
    set_desired_pool,
    set_panel_setting,
    set_node_auto_restart_policy,
    touch_node_last_seen,
    upsert_rule_owner_map,
    upsert_group_order,
    update_certificate,
    update_netmon_monitor,
    update_node_basic,
    update_user_record,
    update_site,
    update_site_health,
)
from ..services.apply import node_agent_request_target, node_verify_tls, schedule_apply_pool
from ..services.backup import get_pool_for_backup
from ..services.assets import panel_public_base_url
from ..services.node_fetch import FETCH_ORDER_PULL_FIRST, node_info_fetch_order, node_info_sources_order
from ..services.node_status import is_report_fresh
try:
    from ..services.panel_config import setting_bool, setting_float, setting_int
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

    def setting_bool(key: str, default: bool = False, env_names: Optional[list[str]] = None) -> bool:
        s = _cfg_env(env_names).lower()
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
        raw = _cfg_env(env_names)
        try:
            v = int(float(raw if raw else default))
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
        raw = _cfg_env(env_names)
        try:
            v = float(raw if raw else default)
        except Exception:
            v = float(default)
        if v < float(lo):
            v = float(lo)
        if v > float(hi):
            v = float(hi)
        return float(v)
from ..services.pool_ops import choose_receiver_port, load_pool_for_node, node_host_for_realm, remove_endpoints_by_sync_id
from ..services.stats_history import config as stats_history_config, ingest_stats_snapshot
from ..utils.crypto import generate_api_key
from ..utils.normalize import (
    extract_ip_for_display,
    format_host_for_url,
    safe_filename_part,
    sanitize_pool,
    split_host_and_port,
)
from ..utils.validate import PoolValidationError, PoolValidationIssue, validate_pool_inplace

router = APIRouter()
logger = logging.getLogger(__name__)

_FULL_BACKUP_JOBS: Dict[str, Dict[str, Any]] = {}
_FULL_BACKUP_LOCK = threading.Lock()
_FULL_BACKUP_TTL_SEC = 1800
_FULL_BACKUP_ACTIVE_MAX_SEC = 6 * 3600

_FULL_RESTORE_JOBS: Dict[str, Dict[str, Any]] = {}
_FULL_RESTORE_LOCK = threading.Lock()
_FULL_RESTORE_TTL_SEC = 1800
_FULL_RESTORE_ACTIVE_MAX_SEC = 6 * 3600
_RESTORE_UPLOAD_CHUNK_SIZE = 1024 * 1024


def _parse_restore_upload_max_bytes() -> int:
    raw_b = os.getenv("REALM_FULL_RESTORE_MAX_BYTES")
    raw_mb = os.getenv("REALM_FULL_RESTORE_MAX_MB")
    try:
        if raw_b:
            return max(1, int(float(str(raw_b).strip())))
    except Exception:
        pass
    try:
        if raw_mb:
            return max(1, int(float(str(raw_mb).strip()))) * 1024 * 1024
    except Exception:
        pass
    # default 5GB
    return 5 * 1024 * 1024 * 1024


def _format_bytes(num: int) -> str:
    n = float(max(0, int(num)))
    if n < 1024:
        return f"{int(n)} B"
    for unit in ("KB", "MB", "GB", "TB"):
        n /= 1024.0
        if n < 1024:
            return f"{n:.1f} {unit}"
    return f"{n:.1f} PB"


def _remove_file_quiet(path: Any) -> None:
    p = str(path or "").strip()
    if not p:
        return
    try:
        if os.path.exists(p):
            os.remove(p)
    except Exception:
        pass


def _download_content_disposition(filename: str, fallback: str = "download.bin") -> str:
    """Build RFC 5987 compatible Content-Disposition value.

    Keep ASCII-only `filename` for old clients and provide UTF-8 `filename*`.
    """
    raw = str(filename or "").replace("\r", "").replace("\n", "").replace('"', "").strip()
    if not raw:
        raw = str(fallback or "download.bin").strip() or "download.bin"
    ascii_name = "".join(
        ch
        if (("0" <= ch <= "9") or ("a" <= ch <= "z") or ("A" <= ch <= "Z") or ch in ("-", "_", "."))
        else "_"
        for ch in raw
    ).strip("._")
    if not ascii_name:
        ascii_name = str(fallback or "download.bin").strip() or "download.bin"
    try:
        encoded = quote(raw, safe="")
    except Exception:
        try:
            raw = raw.encode("utf-8", "ignore").decode("utf-8")
        except Exception:
            raw = ""
        if not raw:
            raw = ascii_name
        encoded = quote(raw, safe="")
    value = f"attachment; filename=\"{ascii_name}\"; filename*=UTF-8''{encoded}"
    try:
        value.encode("latin-1")
    except Exception:
        value = f"attachment; filename=\"{ascii_name}\""
    return value


_FULL_RESTORE_MAX_BYTES = _parse_restore_upload_max_bytes()


def _parse_full_restore_inmem_max_bytes() -> int:
    raw_b = os.getenv("REALM_FULL_RESTORE_INMEM_MAX_BYTES")
    raw_mb = os.getenv("REALM_FULL_RESTORE_INMEM_MAX_MB")
    try:
        if raw_b:
            v = max(1, int(float(str(raw_b).strip())))
            return min(v, _FULL_RESTORE_MAX_BYTES)
    except Exception:
        pass
    try:
        if raw_mb:
            v = max(1, int(float(str(raw_mb).strip()))) * 1024 * 1024
            return min(v, _FULL_RESTORE_MAX_BYTES)
    except Exception:
        pass
    # Full restore currently parses zip in-memory; keep a safe cap to avoid OOM.
    return min(256 * 1024 * 1024, _FULL_RESTORE_MAX_BYTES)


_FULL_RESTORE_INMEM_MAX_BYTES = _parse_full_restore_inmem_max_bytes()


def _parse_nodes_restore_upload_max_bytes() -> int:
    raw_b = os.getenv("REALM_NODES_RESTORE_MAX_BYTES")
    raw_mb = os.getenv("REALM_NODES_RESTORE_MAX_MB")
    try:
        if raw_b:
            v = max(1, int(float(str(raw_b).strip())))
            return min(v, _FULL_RESTORE_MAX_BYTES)
    except Exception:
        pass
    try:
        if raw_mb:
            v = max(1, int(float(str(raw_mb).strip()))) * 1024 * 1024
            return min(v, _FULL_RESTORE_MAX_BYTES)
    except Exception:
        pass
    # default 64MB, and never exceed full-restore cap.
    return min(64 * 1024 * 1024, _FULL_RESTORE_MAX_BYTES)


_NODES_RESTORE_MAX_BYTES = _parse_nodes_restore_upload_max_bytes()


def _parse_rule_restore_upload_max_bytes() -> int:
    raw_b = os.getenv("REALM_RULE_RESTORE_MAX_BYTES")
    raw_mb = os.getenv("REALM_RULE_RESTORE_MAX_MB")
    try:
        if raw_b:
            v = max(1, int(float(str(raw_b).strip())))
            return min(v, _NODES_RESTORE_MAX_BYTES)
    except Exception:
        pass
    try:
        if raw_mb:
            v = max(1, int(float(str(raw_mb).strip()))) * 1024 * 1024
            return min(v, _NODES_RESTORE_MAX_BYTES)
    except Exception:
        pass
    # default 32MB, and never exceed nodes-restore cap.
    return min(32 * 1024 * 1024, _NODES_RESTORE_MAX_BYTES)


_RULE_RESTORE_MAX_BYTES = _parse_rule_restore_upload_max_bytes()


def _env_flag(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return bool(default)
    return str(raw).strip().lower() not in ("0", "false", "off", "no")


def _env_float(name: str, default: float, lo: float, hi: float) -> float:
    try:
        v = float(str(os.getenv(name, str(default))).strip() or default)
    except Exception:
        v = float(default)
    if v < lo:
        v = lo
    if v > hi:
        v = hi
    return float(v)


def _env_int(name: str, default: int, lo: int, hi: int) -> int:
    try:
        v = int(float(str(os.getenv(name, str(default))).strip() or default))
    except Exception:
        v = int(default)
    if v < lo:
        v = lo
    if v > hi:
        v = hi
    return int(v)


_BACKUP_SITE_FILE_FETCH_BASE_TIMEOUT = _env_float("REALM_BACKUP_SITE_FILE_FETCH_BASE_TIMEOUT", 45.0, 20.0, 600.0)
_BACKUP_SITE_FILE_FETCH_PER_MB_SEC = _env_float("REALM_BACKUP_SITE_FILE_FETCH_PER_MB_SEC", 1.5, 0.0, 20.0)
_BACKUP_SITE_FILE_FETCH_MAX_TIMEOUT = _env_float("REALM_BACKUP_SITE_FILE_FETCH_MAX_TIMEOUT", 1800.0, 60.0, 7200.0)
_BACKUP_SITE_SCAN_MAX_SEC = _env_float("REALM_BACKUP_SITE_SCAN_MAX_SEC", 900.0, 30.0, 7200.0)
_BACKUP_SITE_FILE_STREAM_CHUNK_BYTES = _env_int(
    "REALM_BACKUP_SITE_FILE_STREAM_CHUNK_BYTES",
    256 * 1024,
    16 * 1024,
    4 * 1024 * 1024,
)
_BACKUP_SITE_FILE_MAX_FILES_PER_SITE = _env_int(
    "REALM_BACKUP_SITE_FILE_MAX_FILES_PER_SITE",
    300000,
    1000,
    5000000,
)
_BACKUP_SITE_FILE_MAX_TOTAL_FILES = _env_int(
    "REALM_BACKUP_SITE_FILE_MAX_TOTAL_FILES",
    1000000,
    5000,
    10000000,
)
_BACKUP_NETMON_SAMPLES_MAX = _env_int("REALM_BACKUP_NETMON_SAMPLES_MAX", 200000, 1000, 5000000)
_BACKUP_PANEL_STATE_MAX_ROWS_PER_TABLE = _env_int(
    "REALM_BACKUP_PANEL_STATE_MAX_ROWS_PER_TABLE",
    50000,
    1000,
    1000000,
)
_BACKUP_CONFIG_ONLY = _env_flag("REALM_BACKUP_CONFIG_ONLY", True)
_BACKUP_SKIP_SITE_FILES = _env_flag("REALM_BACKUP_SKIP_SITE_FILES", False)
_FULL_BACKUP_EVENT_MAX = _env_int("REALM_FULL_BACKUP_EVENT_MAX", 800, 100, 5000)
_FULL_BACKUP_MAX_CONCURRENT = _env_int("REALM_FULL_BACKUP_MAX_CONCURRENT", 1, 1, 4)
_FULL_RESTORE_EXEC_TIMEOUT_SEC = _env_float(
    "REALM_FULL_RESTORE_EXEC_TIMEOUT_SEC",
    3600.0,
    120.0,
    172800.0,
)


_SAVE_PRECHECK_ENABLED = _env_flag("REALM_SAVE_PRECHECK_ENABLED", True)
_SAVE_PRECHECK_HTTP_TIMEOUT = _env_float("REALM_SAVE_PRECHECK_HTTP_TIMEOUT", 4.5, 2.0, 20.0)
_SAVE_PRECHECK_PROBE_TIMEOUT = _env_float("REALM_SAVE_PRECHECK_PROBE_TIMEOUT", 1.2, 0.2, 6.0)
_SAVE_PRECHECK_MAX_ISSUES = _env_int("REALM_SAVE_PRECHECK_MAX_ISSUES", 24, 5, 120)
_TRACE_ROUTE_HTTP_TIMEOUT = _env_float("REALM_TRACE_ROUTE_HTTP_TIMEOUT", 28.0, 6.0, 90.0)
_POOL_JOB_TTL_SEC = _env_int("REALM_POOL_JOB_TTL_SEC", 1800, 120, 7 * 24 * 3600)
_POOL_JOB_MAX_ATTEMPTS = _env_int("REALM_POOL_JOB_MAX_ATTEMPTS", 3, 1, 10)
_POOL_JOB_RETRY_BASE_SEC = _env_float("REALM_POOL_JOB_RETRY_BASE_SEC", 1.2, 0.2, 30.0)
_POOL_JOB_RETRY_MAX_SEC = _env_float("REALM_POOL_JOB_RETRY_MAX_SEC", 8.0, 1.0, 120.0)
_POOL_JOB_ACK_TIMEOUT_SEC = _env_float("REALM_POOL_JOB_ACK_TIMEOUT_SEC", 45.0, 5.0, 600.0)
_POOL_JOB_ACK_POLL_SEC = _env_float("REALM_POOL_JOB_ACK_POLL_SEC", 1.0, 0.2, 10.0)
_POOL_JOB_REQUIRE_ACK = _env_flag("REALM_POOL_JOB_REQUIRE_ACK", True)
_SYS_SNAPSHOT_CACHE_ENABLED = _env_flag("REALM_SYS_SNAPSHOT_CACHE_ENABLED", True)
_SYS_SNAPSHOT_CACHE_TTL_SEC = _env_float("REALM_SYS_SNAPSHOT_CACHE_TTL_SEC", 2.5, 0.5, 30.0)
_SYS_SNAPSHOT_ERROR_CACHE_TTL_SEC = _env_float("REALM_SYS_SNAPSHOT_ERROR_CACHE_TTL_SEC", 8.0, 1.0, 120.0)
_SYS_SNAPSHOT_CACHE_MAX_ITEMS = _env_int("REALM_SYS_SNAPSHOT_CACHE_MAX_ITEMS", 4096, 64, 50000)
_SYS_SNAPSHOT_CACHE_CLEANUP_INTERVAL_SEC = _env_float("REALM_SYS_SNAPSHOT_CACHE_CLEANUP_INTERVAL_SEC", 15.0, 1.0, 300.0)

_POOL_JOBS: Dict[str, Dict[str, Any]] = {}
_POOL_JOBS_LOCK = threading.Lock()
_POOL_JOB_EXEC_LOCK = asyncio.Lock()
_SYS_SNAPSHOT_CACHE: Dict[str, Dict[str, Any]] = {}
_SYS_SNAPSHOT_CACHE_LOCK = threading.Lock()
_SYS_SNAPSHOT_CACHE_NEXT_CLEANUP_AT = 0.0


def _save_precheck_enabled() -> bool:
    return bool(setting_bool("save_precheck_enabled", default=bool(_SAVE_PRECHECK_ENABLED)))


def _save_precheck_http_timeout() -> float:
    return float(
        setting_float(
            "save_precheck_http_timeout",
            default=float(_SAVE_PRECHECK_HTTP_TIMEOUT),
            lo=2.0,
            hi=20.0,
        )
    )


def _save_precheck_probe_timeout() -> float:
    return float(
        setting_float(
            "save_precheck_probe_timeout",
            default=float(_SAVE_PRECHECK_PROBE_TIMEOUT),
            lo=0.2,
            hi=6.0,
        )
    )


def _save_precheck_max_issues() -> int:
    return int(
        setting_int(
            "save_precheck_max_issues",
            default=int(_SAVE_PRECHECK_MAX_ISSUES),
            lo=5,
            hi=120,
        )
    )


def _to_bool_loose(v: Any, default: bool = False) -> bool:
    if isinstance(v, bool):
        return v
    if v is None:
        return bool(default)
    if isinstance(v, (int, float)):
        return bool(int(v))
    s = str(v).strip().lower()
    if not s:
        return bool(default)
    if s in ("1", "true", "yes", "on", "y"):
        return True
    if s in ("0", "false", "no", "off", "n"):
        return False
    return bool(default)


def _to_int_loose(v: Any, default: int) -> int:
    try:
        return int(v)
    except Exception:
        try:
            return int(float(str(v).strip()))
        except Exception:
            return int(default)


def _to_float_loose(v: Any, default: float) -> float:
    try:
        return float(v)
    except Exception:
        try:
            return float(str(v).strip())
        except Exception:
            return float(default)


def _norm_int_seq(values: Any, lo: int, hi: int) -> List[int]:
    out: List[int] = []
    seen: set[int] = set()
    seq = values if isinstance(values, list) else []
    for x in seq:
        v = _to_int_loose(x, -1)
        if v < int(lo) or v > int(hi):
            continue
        if v in seen:
            continue
        seen.add(v)
        out.append(v)
    return out


def _parse_weekday_list(v: Any) -> List[int]:
    if isinstance(v, list):
        out = _norm_int_seq(v, 1, 7)
        if out:
            return out
    s = str(v or "").strip()
    if not s:
        return []
    parts = [p.strip() for p in s.split(",")]
    return _norm_int_seq(parts, 1, 7)


def _parse_monthday_list(v: Any) -> List[int]:
    if isinstance(v, list):
        out = _norm_int_seq(v, 1, 31)
        if out:
            return out
    s = str(v or "").strip()
    if not s:
        return []
    parts = [p.strip() for p in s.split(",")]
    return _norm_int_seq(parts, 1, 31)


def _normalize_auto_restart_policy_from_payload(data: Dict[str, Any], node: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
    keys = {
        "auto_restart_enabled",
        "auto_restart_schedule_type",
        "auto_restart_interval",
        "auto_restart_hour",
        "auto_restart_minute",
        "auto_restart_time",
        "auto_restart_weekdays",
        "auto_restart_monthdays",
    }
    has_any = any(k in data for k in keys)
    base = node_auto_restart_policy_from_row(node if isinstance(node, dict) else {})
    base_interval_raw = base.get("interval", 1)
    if base_interval_raw is None:
        base_interval_raw = 1
    base_hour_raw = base.get("hour", 4)
    if base_hour_raw is None:
        base_hour_raw = 4
    base_minute_raw = base.get("minute", 8)
    if base_minute_raw is None:
        base_minute_raw = 8

    policy = {
        "enabled": bool(base.get("enabled", True)),
        "schedule_type": str(base.get("schedule_type") or "daily").strip().lower(),
        "interval": _to_int_loose(base_interval_raw, 1),
        "hour": _to_int_loose(base_hour_raw, 4),
        "minute": _to_int_loose(base_minute_raw, 8),
        "weekdays": list(base.get("weekdays") or [1, 2, 3, 4, 5, 6, 7]),
        "monthdays": list(base.get("monthdays") or [1]),
    }
    if policy["schedule_type"] not in ("daily", "weekly", "monthly"):
        policy["schedule_type"] = "daily"
    if policy["interval"] < 1:
        policy["interval"] = 1
    if policy["interval"] > 365:
        policy["interval"] = 365
    policy["hour"] = max(0, min(23, int(policy["hour"])))
    policy["minute"] = max(0, min(59, int(policy["minute"])))

    if "auto_restart_enabled" in data:
        policy["enabled"] = _to_bool_loose(data.get("auto_restart_enabled"), bool(policy["enabled"]))
    if "auto_restart_schedule_type" in data:
        st = str(data.get("auto_restart_schedule_type") or "").strip().lower()
        if st in ("daily", "weekly", "monthly"):
            policy["schedule_type"] = st
    if "auto_restart_interval" in data:
        itv = _to_int_loose(data.get("auto_restart_interval"), int(policy["interval"]))
        if itv < 1:
            itv = 1
        if itv > 365:
            itv = 365
        policy["interval"] = int(itv)
    if "auto_restart_time" in data:
        tt = str(data.get("auto_restart_time") or "").strip()
        m = re.match(r"^\s*([0-9]{1,2})\s*:\s*([0-9]{1,2})\s*$", tt)
        if m:
            hh = _to_int_loose(m.group(1), int(policy["hour"]))
            mm = _to_int_loose(m.group(2), int(policy["minute"]))
            policy["hour"] = max(0, min(23, hh))
            policy["minute"] = max(0, min(59, mm))
    if "auto_restart_hour" in data:
        hh = _to_int_loose(data.get("auto_restart_hour"), int(policy["hour"]))
        policy["hour"] = max(0, min(23, hh))
    if "auto_restart_minute" in data:
        mm = _to_int_loose(data.get("auto_restart_minute"), int(policy["minute"]))
        policy["minute"] = max(0, min(59, mm))
    if "auto_restart_weekdays" in data:
        wd = _parse_weekday_list(data.get("auto_restart_weekdays"))
        if wd:
            policy["weekdays"] = wd
        elif policy["schedule_type"] == "weekly":
            policy["weekdays"] = [1, 2, 3, 4, 5, 6, 7]
    if "auto_restart_monthdays" in data:
        md = _parse_monthday_list(data.get("auto_restart_monthdays"))
        if md:
            policy["monthdays"] = md
        elif policy["schedule_type"] == "monthly":
            policy["monthdays"] = [1]

    if not policy["weekdays"]:
        policy["weekdays"] = [1, 2, 3, 4, 5, 6, 7]
    if not policy["monthdays"]:
        policy["monthdays"] = [1]
    return has_any, policy


def _parse_backup_direct_tunnel(item: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    dt_raw = item.get("direct_tunnel")
    data: Dict[str, Any]
    if isinstance(dt_raw, dict):
        data = dict(dt_raw)
    else:
        dt_keys = {
            "direct_tunnel_enabled",
            "direct_tunnel_sync_id",
            "direct_tunnel_relay_node_id",
            "direct_tunnel_listen_port",
            "direct_tunnel_public_host",
            "direct_tunnel_scheme",
            "direct_tunnel_verify_tls",
            "direct_tunnel_updated_at",
        }
        if not any(k in item for k in dt_keys):
            return None
        data = {
            "enabled": item.get("direct_tunnel_enabled"),
            "sync_id": item.get("direct_tunnel_sync_id"),
            "relay_node_id": item.get("direct_tunnel_relay_node_id"),
            "listen_port": item.get("direct_tunnel_listen_port"),
            "public_host": item.get("direct_tunnel_public_host"),
            "scheme": item.get("direct_tunnel_scheme"),
            "verify_tls": item.get("direct_tunnel_verify_tls"),
            "updated_at": item.get("direct_tunnel_updated_at"),
        }

    listen_port = _to_int_loose(data.get("listen_port"), 0)
    if listen_port < 1 or listen_port > 65535:
        listen_port = 0
    scheme = str(data.get("scheme") or "").strip().lower()
    if scheme not in ("http", "https"):
        scheme = ""
    relay_source_id = _to_int_loose(
        data.get(
            "relay_source_id",
            data.get(
                "relay_node_source_id",
                data.get("relay_node_id"),
            ),
        ),
        0,
    )
    relay_node_id = _to_int_loose(data.get("relay_node_id"), 0)
    relay_node_base_url = str(data.get("relay_node_base_url") or "").strip().rstrip("/")
    return {
        "enabled": _to_bool_loose(data.get("enabled"), False),
        "sync_id": str(data.get("sync_id") or "").strip(),
        "relay_source_id": max(0, int(relay_source_id)),
        "relay_node_id": max(0, int(relay_node_id)),
        "relay_node_base_url": relay_node_base_url,
        "listen_port": int(listen_port),
        "public_host": str(data.get("public_host") or "").strip(),
        "scheme": scheme,
        "verify_tls": _to_bool_loose(data.get("verify_tls"), False),
        "updated_at": str(data.get("updated_at") or "").strip(),
    }


def _parse_backup_auto_restart_policy(item: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    raw = item.get("auto_restart_policy")
    payload: Dict[str, Any] = {}
    if isinstance(raw, dict):
        if "enabled" in raw:
            payload["auto_restart_enabled"] = raw.get("enabled")
        if "schedule_type" in raw:
            payload["auto_restart_schedule_type"] = raw.get("schedule_type")
        if "interval" in raw:
            payload["auto_restart_interval"] = raw.get("interval")
        if "hour" in raw:
            payload["auto_restart_hour"] = raw.get("hour")
        if "minute" in raw:
            payload["auto_restart_minute"] = raw.get("minute")
        if "weekdays" in raw:
            payload["auto_restart_weekdays"] = raw.get("weekdays")
        if "monthdays" in raw:
            payload["auto_restart_monthdays"] = raw.get("monthdays")
    else:
        for k in (
            "auto_restart_enabled",
            "auto_restart_schedule_type",
            "auto_restart_interval",
            "auto_restart_hour",
            "auto_restart_minute",
            "auto_restart_time",
            "auto_restart_weekdays",
            "auto_restart_monthdays",
        ):
            if k in item:
                payload[k] = item.get(k)
    has_any, policy = _normalize_auto_restart_policy_from_payload(payload, {})
    if not has_any:
        return None
    return policy


def _resolve_restore_target_node_id(
    source_id: Optional[int],
    base_url: Optional[str],
    mapping: Dict[str, int],
    baseurl_to_nodeid: Dict[str, int],
) -> Optional[int]:
    if source_id is not None and int(source_id) > 0:
        hit = mapping.get(str(int(source_id)))
        if hit:
            return int(hit)
    bu = str(base_url or "").strip().rstrip("/")
    if bu:
        hit2 = baseurl_to_nodeid.get(bu)
        if hit2:
            return int(hit2)
        ex = get_node_by_base_url(bu)
        if ex:
            return _to_int_loose((ex or {}).get("id"), 0) or None
    return None


def _resolve_restore_relay_node_id(
    direct_tunnel: Dict[str, Any],
    mapping: Dict[str, int],
    baseurl_to_nodeid: Dict[str, int],
) -> int:
    relay_source_id = _to_int_loose(direct_tunnel.get("relay_source_id"), 0)
    if relay_source_id > 0:
        hit = mapping.get(str(relay_source_id))
        if hit:
            return int(hit)
    relay_base_url = str(direct_tunnel.get("relay_node_base_url") or "").strip().rstrip("/")
    if relay_base_url:
        hit2 = baseurl_to_nodeid.get(relay_base_url)
        if hit2:
            return int(hit2)
        ex = get_node_by_base_url(relay_base_url)
        if ex:
            return _to_int_loose((ex or {}).get("id"), 0)
    relay_node_id = _to_int_loose(direct_tunnel.get("relay_node_id"), 0)
    if relay_node_id > 0:
        hit3 = mapping.get(str(relay_node_id))
        if hit3:
            return int(hit3)
        if get_node(int(relay_node_id)):
            return int(relay_node_id)
    return 0


def _restore_node_feature_configs(
    nodes_list: List[Any],
    mapping: Dict[str, int],
    baseurl_to_nodeid: Dict[str, int],
) -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "direct_tunnel": {"restored": 0, "skipped": 0, "failed": 0},
        "auto_restart_policy": {"restored": 0, "skipped": 0, "failed": 0},
        "errors": [],
    }
    for item in nodes_list:
        if not isinstance(item, dict):
            continue
        source_id_raw = item.get("source_id")
        source_id: Optional[int] = None
        try:
            source_id = int(source_id_raw) if source_id_raw is not None else None
        except Exception:
            source_id = None
        base_url = str(item.get("base_url") or "").strip().rstrip("/")
        target_node_id = _resolve_restore_target_node_id(source_id, base_url, mapping, baseurl_to_nodeid)
        if not target_node_id or target_node_id <= 0:
            continue

        dt_cfg = _parse_backup_direct_tunnel(item)
        if dt_cfg is None:
            out["direct_tunnel"]["skipped"] += 1
        else:
            try:
                relay_target_id = _resolve_restore_relay_node_id(dt_cfg, mapping, baseurl_to_nodeid)
                set_node_direct_tunnel(
                    int(target_node_id),
                    enabled=bool(dt_cfg.get("enabled")),
                    sync_id=str(dt_cfg.get("sync_id") or ""),
                    relay_node_id=max(0, int(relay_target_id)),
                    listen_port=_to_int_loose(dt_cfg.get("listen_port"), 0),
                    public_host=str(dt_cfg.get("public_host") or ""),
                    scheme=str(dt_cfg.get("scheme") or ""),
                    verify_tls=_to_bool_loose(dt_cfg.get("verify_tls"), False),
                    updated_at=str(dt_cfg.get("updated_at") or "").strip() or None,
                )
                out["direct_tunnel"]["restored"] += 1
            except Exception as exc:
                out["direct_tunnel"]["failed"] += 1
                out["errors"].append(f"节点[{target_node_id}]直连隧道恢复失败：{exc}")

        auto_restart_cfg = _parse_backup_auto_restart_policy(item)
        if auto_restart_cfg is None:
            out["auto_restart_policy"]["skipped"] += 1
        else:
            try:
                set_node_auto_restart_policy(
                    int(target_node_id),
                    enabled=_to_bool_loose(auto_restart_cfg.get("enabled"), True),
                    schedule_type=str(auto_restart_cfg.get("schedule_type") or "daily"),
                    interval=_to_int_loose(auto_restart_cfg.get("interval"), 1),
                    hour=_to_int_loose(auto_restart_cfg.get("hour"), 4),
                    minute=_to_int_loose(auto_restart_cfg.get("minute"), 8),
                    weekdays=_norm_int_seq(auto_restart_cfg.get("weekdays"), 1, 7) or [1, 2, 3, 4, 5, 6, 7],
                    monthdays=_norm_int_seq(auto_restart_cfg.get("monthdays"), 1, 31) or [1],
                )
                out["auto_restart_policy"]["restored"] += 1
            except Exception as exc:
                out["auto_restart_policy"]["failed"] += 1
                out["errors"].append(f"节点[{target_node_id}]自动重启策略恢复失败：{exc}")
    out["errors"] = list((out.get("errors") or []))[:50]
    return out


def _pool_job_now() -> float:
    return float(time.time())


def _prune_pool_jobs_locked(now_ts: Optional[float] = None) -> None:
    now = float(now_ts if now_ts is not None else _pool_job_now())
    stale_ids: List[str] = []
    for jid, job in _POOL_JOBS.items():
        st = str(job.get("status") or "")
        updated = _to_float_loose(job.get("updated_at"), 0.0)
        if st in ("success", "error") and (now - updated) > float(_POOL_JOB_TTL_SEC):
            stale_ids.append(jid)
    for jid in stale_ids:
        _POOL_JOBS.pop(jid, None)


def _pool_job_view(job: Dict[str, Any], include_result: bool = True) -> Dict[str, Any]:
    meta = job.get("meta")
    out: Dict[str, Any] = {
        "job_id": str(job.get("job_id") or ""),
        "node_id": _to_int_loose(job.get("node_id"), 0),
        "kind": str(job.get("kind") or ""),
        "status": str(job.get("status") or ""),
        "created_at": _to_float_loose(job.get("created_at"), 0.0),
        "updated_at": _to_float_loose(job.get("updated_at"), 0.0),
        "attempts": _to_int_loose(job.get("attempts"), 0),
        "max_attempts": _to_int_loose(job.get("max_attempts"), 0),
        "next_retry_at": _to_float_loose(job.get("next_retry_at"), 0.0),
        "status_code": _to_int_loose(job.get("status_code"), 0),
        "error": str(job.get("error") or ""),
        "meta": dict(meta) if isinstance(meta, dict) else {},
    }
    if include_result:
        res = job.get("result")
        out["result"] = dict(res) if isinstance(res, dict) else {}
    return out


def _pool_job_parse_json_response(resp: JSONResponse) -> Dict[str, Any]:
    try:
        body = resp.body
        if isinstance(body, (bytes, bytearray)):
            txt = body.decode("utf-8", errors="ignore")
        else:
            txt = str(body or "")
        data = json.loads(txt) if txt else {}
        return data if isinstance(data, dict) else {"ok": False, "error": str(data)}
    except Exception:
        return {"ok": False, "error": "unknown_response"}


def _pool_job_set(job_id: str, **kwargs: Any) -> None:
    now = _pool_job_now()
    with _POOL_JOBS_LOCK:
        job = _POOL_JOBS.get(job_id)
        if not isinstance(job, dict):
            return
        for k, v in kwargs.items():
            job[k] = v
        job["updated_at"] = now


def _pool_job_get(job_id: str) -> Optional[Dict[str, Any]]:
    with _POOL_JOBS_LOCK:
        _prune_pool_jobs_locked()
        job = _POOL_JOBS.get(job_id)
        if not isinstance(job, dict):
            return None
        return dict(job)


def _pool_job_error_text(data: Any, fallback: str = "任务失败") -> str:
    if isinstance(data, dict):
        msg = str(data.get("error") or "").strip()
        if msg:
            return msg
    txt = str(data or "").strip()
    return txt or fallback


def _pool_job_is_retriable(status_code: int, data: Dict[str, Any]) -> bool:
    if status_code <= 0:
        return True
    if status_code >= 500:
        return True
    if status_code == 409:
        if isinstance(data, dict):
            code = str(data.get("code") or "").strip().lower()
            err = str(data.get("error") or "").strip().lower()
            if code == "stale_index" or "索引已过期" in err:
                return False
        return True
    if status_code in (408, 425, 429):
        return True
    if isinstance(data, dict):
        err = str(data.get("error") or "").lower()
        if "超时" in err or "timeout" in err:
            return True
        if "预检失败" in err or "precheck" in err:
            return True
    return False


def _json_deep_clone(value: Any) -> Any:
    try:
        return json.loads(json.dumps(value))
    except Exception:
        if isinstance(value, dict):
            return dict(value)
        if isinstance(value, list):
            return list(value)
        return value


def _normalize_pool_dict(pool: Any) -> Dict[str, Any]:
    out = pool if isinstance(pool, dict) else {}
    if not isinstance(out.get("endpoints"), list):
        out["endpoints"] = []
    return out


def _resolve_rule_user(user_or_name: Any) -> Any:
    if isinstance(user_or_name, str):
        try:
            u = get_user_by_username(user_or_name)
            if u is not None:
                return u
        except Exception:
            return user_or_name
    return user_or_name


def _is_relay_sync_rule(ex: Any) -> bool:
    if not isinstance(ex, dict):
        return False
    mode = str(ex.get("sync_tunnel_mode") or ex.get("sync_tunnel_type") or "").strip().lower()
    return mode in ("relay", "wss_relay")


def _rule_key_for_endpoint(endpoint: Dict[str, Any]) -> str:
    ex = endpoint.get("extra_config")
    if not isinstance(ex, dict):
        ex = {}
    sid = str(ex.get("sync_id") or "").strip()
    if sid and (ex.get("sync_role") or ex.get("sync_peer_node_id") or ex.get("sync_lock")):
        return f"wss:{sid}"
    if sid and (ex.get("intranet_role") or ex.get("intranet_peer_node_id") or ex.get("intranet_lock")):
        return f"intranet:{sid}"
    listen = str(endpoint.get("listen") or "").strip()
    proto = str(endpoint.get("protocol") or "tcp+udp").strip().lower()
    return f"tcp:{listen}|{proto}"


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
    action: str,
    user: str,
    node_id: int,
    node_name: str = "",
    detail: Optional[Dict[str, Any]] = None,
    request: Optional[Request] = None,
) -> None:
    try:
        add_audit_log(
            action=action,
            actor=str(user or "").strip(),
            node_id=int(node_id or 0),
            node_name=str(node_name or "").strip(),
            detail=detail if isinstance(detail, dict) else {},
            source_ip=_request_source_ip(request),
        )
    except Exception:
        pass


def _pool_change_summary(old_pool: Dict[str, Any], new_pool: Dict[str, Any]) -> Dict[str, Any]:
    def _keys(pool: Dict[str, Any]) -> List[str]:
        keys: List[str] = []
        eps = pool.get("endpoints") if isinstance(pool.get("endpoints"), list) else []
        for idx, ep in enumerate(eps):
            if not isinstance(ep, dict):
                continue
            try:
                k = _rule_key_for_endpoint(ep)
            except Exception:
                k = ""
            if not k:
                k = f"idx:{idx}"
            keys.append(k)
        return keys

    old_keys = Counter(_keys(old_pool if isinstance(old_pool, dict) else {}))
    new_keys = Counter(_keys(new_pool if isinstance(new_pool, dict) else {}))
    created = int(sum((new_keys - old_keys).values()))
    deleted = int(sum((old_keys - new_keys).values()))

    old_eps = (old_pool.get("endpoints") if isinstance(old_pool.get("endpoints"), list) else []) if isinstance(old_pool, dict) else []
    new_eps = (new_pool.get("endpoints") if isinstance(new_pool.get("endpoints"), list) else []) if isinstance(new_pool, dict) else []
    updated_hint = 0
    if created == 0 and deleted == 0:
        try:
            old_sig = json.dumps(old_eps, ensure_ascii=False, sort_keys=True)
            new_sig = json.dumps(new_eps, ensure_ascii=False, sort_keys=True)
            if old_sig != new_sig:
                updated_hint = 1
        except Exception:
            updated_hint = 0

    return {
        "rules_before": int(sum(old_keys.values())),
        "rules_after": int(sum(new_keys.values())),
        "created_rules": int(created),
        "deleted_rules": int(deleted),
        "updated_hint": int(updated_hint),
    }


def _visible_endpoint_tuples(user: str, pool: Dict[str, Any]) -> List[Tuple[int, Dict[str, Any]]]:
    eps = pool.get("endpoints") if isinstance(pool.get("endpoints"), list) else []
    out: List[Tuple[int, Dict[str, Any]]] = []
    user_ref = _resolve_rule_user(user)
    scoped = is_rule_owner_scoped(user_ref)
    for idx, ep in enumerate(eps):
        if not isinstance(ep, dict):
            continue
        if scoped and (not can_access_rule_endpoint(user_ref, ep)):
            continue
        out.append((idx, ep))
    return out


def _filter_pool_for_user(user: str, pool: Any) -> Dict[str, Any]:
    user_ref = _resolve_rule_user(user)
    full = _normalize_pool_dict(_json_deep_clone(pool if isinstance(pool, dict) else {}))
    if not is_rule_owner_scoped(user_ref):
        return full
    full["endpoints"] = [ep for _idx, ep in _visible_endpoint_tuples(user_ref, full)]
    return full


def _merge_submitted_pool_for_user(user: str, existing_pool: Dict[str, Any], submitted_pool: Dict[str, Any]) -> Dict[str, Any]:
    user_ref = _resolve_rule_user(user)
    existing = _normalize_pool_dict(_json_deep_clone(existing_pool if isinstance(existing_pool, dict) else {}))
    submitted = _normalize_pool_dict(_json_deep_clone(submitted_pool if isinstance(submitted_pool, dict) else {}))
    if not is_rule_owner_scoped(user_ref):
        return submitted

    posted_eps_raw = submitted.get("endpoints") if isinstance(submitted.get("endpoints"), list) else []
    posted_eps: List[Dict[str, Any]] = []
    for ep in posted_eps_raw:
        if not isinstance(ep, dict):
            continue
        stamp_endpoint_owner(ep, user_ref)
        posted_eps.append(ep)

    merged_eps: List[Dict[str, Any]] = []
    take = 0
    existing_eps = existing.get("endpoints") if isinstance(existing.get("endpoints"), list) else []
    for old_ep in existing_eps:
        if not isinstance(old_ep, dict):
            continue
        if can_access_rule_endpoint(user_ref, old_ep):
            if take < len(posted_eps):
                merged_eps.append(posted_eps[take])
                take += 1
            continue
        merged_eps.append(old_ep)

    while take < len(posted_eps):
        merged_eps.append(posted_eps[take])
        take += 1

    if not isinstance(submitted, dict):
        submitted = {}
    for k, v in existing.items():
        if k == "endpoints":
            continue
        if k not in submitted:
            submitted[k] = v
    submitted["endpoints"] = merged_eps
    return submitted


def _filter_stats_payload_for_user(user: str, pool: Dict[str, Any], stats_payload: Dict[str, Any]) -> Dict[str, Any]:
    user_ref = _resolve_rule_user(user)
    if not isinstance(stats_payload, dict):
        return {}
    data = dict(stats_payload)
    rules = data.get("rules")
    if not isinstance(rules, list):
        data["rules"] = []
        return data
    if not is_rule_owner_scoped(user_ref):
        return data

    visible = _visible_endpoint_tuples(user_ref, pool)
    idx_map: Dict[int, int] = {int(actual_idx): int(v_idx) for v_idx, (actual_idx, _ep) in enumerate(visible)}
    listen_map: Dict[str, int] = {}
    rule_keys: set[str] = set()
    for v_idx, (_actual_idx, ep) in enumerate(visible):
        listen = str(ep.get("listen") or "").strip()
        if listen and listen not in listen_map:
            listen_map[listen] = int(v_idx)
        try:
            rule_keys.add(_rule_key_for_endpoint(ep))
        except Exception:
            continue

    out_rules: List[Dict[str, Any]] = []
    for r in rules:
        if not isinstance(r, dict):
            continue
        nr = dict(r)
        keep = False
        idx_raw = r.get("idx")
        idx_val: Optional[int] = None
        try:
            idx_val = int(idx_raw)
        except Exception:
            idx_val = None
        if idx_val is not None and idx_val in idx_map:
            nr["idx"] = int(idx_map[idx_val])
            keep = True
        if not keep:
            listen = str(r.get("listen") or "").strip()
            if listen and listen in listen_map:
                nr["idx"] = int(listen_map[listen])
                keep = True
        if not keep:
            rkey = str(r.get("key") or r.get("rule_key") or "").strip()
            if rkey and rkey in rule_keys:
                keep = True
        if keep:
            out_rules.append(nr)
    data["rules"] = out_rules
    return data


def _visible_rule_history_keys(user: str, pool: Dict[str, Any]) -> set[str]:
    user_ref = _resolve_rule_user(user)
    out: set[str] = set()
    for _idx, ep in _visible_endpoint_tuples(user_ref, pool):
        if not isinstance(ep, dict):
            continue
        listen = str(ep.get("listen") or "").strip()
        if listen:
            out.add(listen)
        try:
            out.add(_rule_key_for_endpoint(ep))
        except Exception:
            continue
    return out


def _pool_like_response_with_filter(user: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        return {}
    if not isinstance(payload.get("pool"), dict):
        return dict(payload)
    out = dict(payload)
    out["pool"] = _filter_pool_for_user(user, payload.get("pool"))
    return out


async def _pool_job_wait_ack(node_id: int, desired_ver: int) -> Tuple[bool, str]:
    need = int(desired_ver or 0)
    if need <= 0:
        return True, ""
    if not _POOL_JOB_REQUIRE_ACK:
        return True, ""
    deadline = _pool_job_now() + float(_POOL_JOB_ACK_TIMEOUT_SEC)
    last_ack = 0
    last_seen = ""
    report_fresh = False
    while _pool_job_now() < deadline:
        n = get_node(int(node_id))
        if not n:
            return False, "节点不存在"
        try:
            last_ack = int(n.get("agent_ack_version") or 0)
        except Exception:
            last_ack = 0
        last_seen = str(n.get("last_seen_at") or "")
        try:
            report_fresh = bool(is_report_fresh(n, max_age_sec=max(90, int(_POOL_JOB_ACK_TIMEOUT_SEC) * 2)))
        except Exception:
            report_fresh = False
        if last_ack >= need:
            return True, ""
        await asyncio.sleep(max(0.2, float(_POOL_JOB_ACK_POLL_SEC)))
    if not report_fresh:
        return (
            False,
            f"节点未确认配置版本（ack={last_ack}, desired={need}，last_seen={last_seen or 'never'}）。"
            f"请检查 Agent 上报链路（REALM_PANEL_URL/REALM_AGENT_ID/网络连通）。"
        )
    return False, f"节点未确认配置版本（ack={last_ack}, desired={need}）"


async def _pool_job_invoke(kind: str, node_id: int, payload: Dict[str, Any], user: str) -> Tuple[int, Dict[str, Any]]:
    if kind in ("pool_save", "rule_restore"):
        payload2 = dict(payload) if isinstance(payload, dict) else {}
        payload2["_async_job"] = True
        ret = await api_pool_set(None, int(node_id), payload2, user=user)
    elif kind == "rule_delete":
        ret = await api_rule_delete(None, int(node_id), payload, user=user)
    elif kind == "direct_tunnel_configure":
        ret = await _direct_tunnel_configure_impl(
            int(node_id),
            payload if isinstance(payload, dict) else {},
            user=user,
            request=None,
            audit_action="node.direct_tunnel.configure_async_done",
        )
    elif kind == "direct_tunnel_disable":
        ret = await _direct_tunnel_disable_impl(
            int(node_id),
            user=user,
            request=None,
            audit_action="node.direct_tunnel.disable_async_done",
        )
    else:
        return 400, {"ok": False, "error": f"unsupported_job_kind:{kind}"}

    if isinstance(ret, JSONResponse):
        status = int(ret.status_code or 500)
        data = _pool_job_parse_json_response(ret)
        if "ok" not in data:
            data["ok"] = status < 400
        return status, data

    if isinstance(ret, dict):
        ok = bool(ret.get("ok", True))
        return (200 if ok else 500), ret

    return 500, {"ok": False, "error": "unknown_response_type"}


async def _run_pool_job(job_id: str) -> None:
    snap = _pool_job_get(job_id)
    if not isinstance(snap, dict):
        return
    kind = str(snap.get("kind") or "")
    node_id = int(snap.get("node_id") or 0)
    payload = snap.get("_payload") if isinstance(snap.get("_payload"), dict) else {}
    user = str(snap.get("_user") or "").strip() or "system"
    max_attempts = max(1, int(snap.get("max_attempts") or _POOL_JOB_MAX_ATTEMPTS))

    for attempt in range(1, max_attempts + 1):
        _pool_job_set(job_id, status="running", attempts=int(attempt), next_retry_at=0.0, error="", status_code=0)

        status_code = 0
        data: Dict[str, Any] = {}
        try:
            async with _POOL_JOB_EXEC_LOCK:
                status_code, data = await _pool_job_invoke(kind, node_id, payload, user)
        except Exception as exc:
            status_code = 599
            data = {"ok": False, "error": f"任务执行异常：{exc}"}

        ok = bool(isinstance(data, dict) and data.get("ok") is True and status_code < 400)
        if ok:
            desired_ver = 0
            try:
                desired_ver = int(data.get("desired_version") or 0)
            except Exception:
                desired_ver = 0
            if desired_ver > 0:
                ack_ok, ack_err = await _pool_job_wait_ack(node_id, desired_ver)
                if not ack_ok:
                    status_code = 504
                    data = {"ok": False, "error": ack_err, "desired_version": desired_ver}
                    ok = False
            if ok:
                _pool_job_set(
                    job_id,
                    status="success",
                    status_code=int(status_code),
                    result=data,
                    error="",
                    next_retry_at=0.0,
                )
                return

        err = _pool_job_error_text(data, "任务失败")
        retriable = _pool_job_is_retriable(int(status_code), data if isinstance(data, dict) else {})
        if attempt < max_attempts and retriable:
            delay = min(float(_POOL_JOB_RETRY_MAX_SEC), float(_POOL_JOB_RETRY_BASE_SEC) * (2 ** (attempt - 1)))
            _pool_job_set(
                job_id,
                status="retrying",
                status_code=int(status_code),
                result=data if isinstance(data, dict) else {},
                error=err,
                next_retry_at=float(_pool_job_now() + delay),
            )
            await asyncio.sleep(max(0.2, delay))
            continue

        _pool_job_set(
            job_id,
            status="error",
            status_code=int(status_code),
            result=data if isinstance(data, dict) else {},
            error=err,
            next_retry_at=0.0,
        )
        return


def _enqueue_pool_job(node_id: int, kind: str, payload: Dict[str, Any], user: str, meta: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    now = _pool_job_now()
    job_id = uuid.uuid4().hex
    job = {
        "job_id": job_id,
        "node_id": int(node_id),
        "kind": str(kind),
        "status": "queued",
        "created_at": now,
        "updated_at": now,
        "attempts": 0,
        "max_attempts": int(_POOL_JOB_MAX_ATTEMPTS),
        "next_retry_at": 0.0,
        "status_code": 0,
        "error": "",
        "result": {},
        "meta": dict(meta) if isinstance(meta, dict) else {},
        "_payload": dict(payload) if isinstance(payload, dict) else {},
        "_user": str(user or "system"),
    }
    with _POOL_JOBS_LOCK:
        _prune_pool_jobs_locked(now)
        _POOL_JOBS[job_id] = job
    try:
        spawn_background_task(_run_pool_job(job_id), label="pool-job")
    except Exception as exc:
        _pool_job_set(
            job_id,
            status="error",
            status_code=500,
            error=f"任务调度失败：{exc}",
            next_retry_at=0.0,
        )
    return _pool_job_view(job, include_result=False)


async def _read_full_restore_upload(file: UploadFile) -> tuple[Optional[bytes], Optional[str], int]:
    try:
        await file.seek(0)
    except Exception:
        pass

    total = 0
    buf = bytearray()
    try:
        while True:
            chunk = await file.read(_RESTORE_UPLOAD_CHUNK_SIZE)
            if not chunk:
                break
            total += len(chunk)
            if total > _FULL_RESTORE_MAX_BYTES:
                return (
                    None,
                    f"备份包过大（当前限制 {_format_bytes(_FULL_RESTORE_MAX_BYTES)}）",
                    413,
                )
            if total > _FULL_RESTORE_INMEM_MAX_BYTES:
                return (
                    None,
                    (
                        "备份包过大，超出当前内存处理上限 "
                        f"({_format_bytes(_FULL_RESTORE_INMEM_MAX_BYTES)})"
                    ),
                    413,
                )
            buf.extend(chunk)
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        return None, f"读取文件失败：{exc}", 400

    raw = bytes(buf)
    if not raw or raw[:2] != b"PK":
        return (
            None,
            "请上传全量备份 ZIP（支持 nexus-backup-*.zip 与 nexus-auto-backup-*.zip）",
            400,
        )
    return raw, None, 200


def _backup_steps_template() -> List[Dict[str, Any]]:
    return [
        {"key": "scan", "label": "扫描数据", "status": "pending", "detail": ""},
        {"key": "rules", "label": "规则快照", "status": "pending", "detail": ""},
        {"key": "sites", "label": "网站配置", "status": "pending", "detail": ""},
        {"key": "site_files", "label": "网站文件", "status": "pending", "detail": ""},
        {"key": "certs", "label": "证书信息", "status": "pending", "detail": ""},
        {"key": "netmon", "label": "网络波动配置", "status": "pending", "detail": ""},
        {"key": "panel_state", "label": "面板状态数据", "status": "pending", "detail": ""},
        {"key": "package", "label": "打包压缩", "status": "pending", "detail": ""},
    ]


def _prune_full_backup_jobs() -> None:
    now = time.time()
    stale_file_paths: List[str] = []
    with _FULL_BACKUP_LOCK:
        stale_ids: List[str] = []
        for jid, job in _FULL_BACKUP_JOBS.items():
            st = str(job.get("status") or "")
            created_at = _to_float_loose(job.get("created_at"), 0.0)
            updated_at = _to_float_loose(job.get("updated_at"), 0.0)
            if st in ("queued", "running") and created_at > 0 and (now - created_at) > float(_FULL_BACKUP_ACTIVE_MAX_SEC):
                stale_ids.append(jid)
                continue
            if st in ("done", "failed") and (now - updated_at) > _FULL_BACKUP_TTL_SEC:
                stale_ids.append(jid)
        for jid in stale_ids:
            job = _FULL_BACKUP_JOBS.pop(jid, None)
            if isinstance(job, dict):
                stale_file_paths.append(str(job.get("file_path") or ""))
    for p in stale_file_paths:
        _remove_file_quiet(p)


def _backup_job_snapshot(job_id: str) -> Optional[Dict[str, Any]]:
    with _FULL_BACKUP_LOCK:
        job = _FULL_BACKUP_JOBS.get(job_id)
        if not isinstance(job, dict):
            return None
        file_path = str(job.get("file_path") or "")
        in_mem_ok = bool(job.get("content"))
        try:
            file_ok = bool(file_path and os.path.exists(file_path))
        except Exception:
            file_ok = False
        counts = job.get("counts")
        steps = job.get("steps")
        events = job.get("events")
        return {
            "job_id": str(job_id),
            "status": str(job.get("status") or "unknown"),
            "progress": _to_int_loose(job.get("progress"), 0),
            "stage": str(job.get("stage") or ""),
            "error": str(job.get("error") or ""),
            "created_at": _to_float_loose(job.get("created_at"), 0.0),
            "updated_at": _to_float_loose(job.get("updated_at"), 0.0),
            "size_bytes": _to_int_loose(job.get("size_bytes"), 0),
            "filename": str(job.get("filename") or ""),
            "steps": list(steps) if isinstance(steps, list) else [],
            "counts": dict(counts) if isinstance(counts, dict) else {},
            "events": list(events) if isinstance(events, list) else [],
            "event_total": _to_int_loose(job.get("event_total"), 0),
            "can_download": bool(job.get("status") == "done" and (in_mem_ok or file_ok)),
        }


def _active_full_backup_job_ids() -> List[str]:
    now = time.time()
    out: List[str] = []
    with _FULL_BACKUP_LOCK:
        for jid, job in _FULL_BACKUP_JOBS.items():
            if not isinstance(job, dict):
                continue
            st = str(job.get("status") or "")
            if st not in ("queued", "running"):
                continue
            created_at = _to_float_loose(job.get("created_at"), 0.0)
            if created_at > 0 and (now - created_at) > float(_FULL_BACKUP_ACTIVE_MAX_SEC):
                continue
            out.append(str(jid))
    return out


def _backup_event_level(level: Any) -> str:
    s = str(level or "").strip().lower()
    if s in ("debug", "info", "warn", "error"):
        return s
    return "info"


def _append_backup_event(
    job: Dict[str, Any],
    *,
    ts: float,
    stage: str,
    progress: int,
    level: str,
    detail: str,
) -> None:
    detail_s = str(detail or "").strip()
    if not detail_s:
        return
    stage_s = str(stage or "").strip()
    lvl = _backup_event_level(level)
    events = job.get("events")
    if not isinstance(events, list):
        events = []
        job["events"] = events
    event_total = _to_int_loose(job.get("event_total"), 0)
    event = {
        "ts_ms": int(max(0.0, float(ts)) * 1000.0),
        "stage": stage_s,
        "progress": int(max(0, min(100, int(progress)))),
        "level": lvl,
        "detail": detail_s,
    }
    if events:
        last = events[-1]
        if (
            isinstance(last, dict)
            and str(last.get("detail") or "") == detail_s
            and str(last.get("stage") or "") == stage_s
            and str(last.get("level") or "") == lvl
        ):
            try:
                rep = int(last.get("repeat") or 1)
            except Exception:
                rep = 1
            last["repeat"] = int(rep + 1)
            last["ts_ms"] = int(event["ts_ms"])
            last["progress"] = int(event["progress"])
            job["event_total"] = int(event_total + 1)
            return
    events.append(event)
    if len(events) > int(_FULL_BACKUP_EVENT_MAX):
        del events[: len(events) - int(_FULL_BACKUP_EVENT_MAX)]
    job["event_total"] = int(event_total + 1)


def _touch_backup_job(
    job_id: str,
    *,
    status: Optional[str] = None,
    progress: Optional[int] = None,
    stage: Optional[str] = None,
    error: Optional[str] = None,
    counts: Optional[Dict[str, Any]] = None,
    step_key: Optional[str] = None,
    step_status: Optional[str] = None,
    step_detail: Optional[str] = None,
    filename: Optional[str] = None,
    size_bytes: Optional[int] = None,
    content: Optional[bytes] = None,
    file_path: Optional[str] = None,
    event_text: Optional[str] = None,
    event_level: Optional[str] = None,
) -> None:
    now = time.time()
    remove_old_path = ""
    with _FULL_BACKUP_LOCK:
        job = _FULL_BACKUP_JOBS.get(job_id)
        if not isinstance(job, dict):
            return
        if status is not None:
            job["status"] = str(status)
        if progress is not None:
            p = max(0, min(100, int(progress)))
            job["progress"] = p
        if stage is not None:
            job["stage"] = str(stage)
        if error is not None:
            job["error"] = str(error)
        if counts is not None:
            job["counts"] = dict(counts)
        if filename is not None:
            job["filename"] = str(filename)
        if size_bytes is not None:
            job["size_bytes"] = int(size_bytes)
        if content is not None:
            job["content"] = bytes(content)
        if file_path is not None:
            new_path = str(file_path or "").strip()
            old_path = str(job.get("file_path") or "").strip()
            if old_path and old_path != new_path:
                remove_old_path = old_path
            job["file_path"] = new_path
            if new_path:
                # Release in-memory blob when switching to file-backed artifact.
                job["content"] = b""
        if step_key:
            for s in (job.get("steps") or []):
                if str(s.get("key") or "") == str(step_key):
                    if step_status is not None:
                        s["status"] = str(step_status)
                    if step_detail is not None:
                        s["detail"] = str(step_detail)
                    break
        if event_text is not None:
            _append_backup_event(
                job,
                ts=now,
                stage=str(stage if stage is not None else (job.get("stage") or "")),
                progress=_to_int_loose(progress if progress is not None else job.get("progress"), 0),
                level=str(event_level if event_level is not None else ("error" if str(job.get("status") or "") == "failed" else "info")),
                detail=str(event_text or ""),
            )
        job["updated_at"] = now
    if remove_old_path:
        _remove_file_quiet(remove_old_path)


async def _emit_backup_progress(callback: Any, payload: Dict[str, Any]) -> None:
    if callback is None:
        return
    try:
        ret = callback(payload)
        if inspect.isawaitable(ret):
            await ret
    except Exception:
        pass


def _clean_site_rel_path(raw: Any) -> str:
    txt = str(raw or "").replace("\\", "/").strip().strip("/")
    if not txt:
        return ""
    parts: List[str] = []
    for seg in txt.split("/"):
        s = str(seg or "").strip()
        if not s or s == ".":
            continue
        if s == "..":
            return ""
        parts.append(s)
    return "/".join(parts)


def _site_pkg_dir_name(site: Dict[str, Any]) -> str:
    sid = int(site.get("source_id") or site.get("id") or 0)
    domains = site.get("domains") if isinstance(site.get("domains"), list) else []
    hint = ""
    if domains:
        hint = str(domains[0] or "").strip()
    if not hint:
        hint = str(site.get("name") or f"site-{sid}").strip()
    safe = safe_filename_part(hint)[:64] or "site"
    return f"site-{sid}-{safe}"


def _site_scan_label(site: Dict[str, Any]) -> str:
    domains = site.get("domains") if isinstance(site.get("domains"), list) else []
    if domains:
        for raw in domains:
            d = str(raw or "").strip()
            if not d:
                continue
            if d.startswith("__"):
                # Internal marker domain (e.g. remote storage profile binding), not user-facing.
                continue
            return d
    name = str(site.get("name") or "").strip()
    if name:
        return name
    sid = int(site.get("source_id") or site.get("id") or 0)
    return f"site-{sid}" if sid > 0 else "site"


def _is_remote_storage_mount_site(site: Dict[str, Any]) -> bool:
    if str(site.get("type") or "").strip().lower() == "storage_mount":
        return True
    domains = site.get("domains") if isinstance(site.get("domains"), list) else []
    for d in domains:
        if str(d or "").strip().lower().startswith("__remote_storage__:"):
            return True
    return False


_REMOTE_PROFILE_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


def _normalize_remote_profile_id(raw: Any) -> str:
    text = str(raw or "").strip()
    if not text or not _REMOTE_PROFILE_ID_RE.match(text):
        return ""
    return text


def _normalize_remote_profile_item(raw: Any) -> Optional[Dict[str, Any]]:
    if not isinstance(raw, dict):
        return None
    pid = _normalize_remote_profile_id(raw.get("id"))
    if not pid:
        return None
    item = dict(raw)
    item["id"] = pid
    # Legacy website bridge field, no longer used.
    item.pop("site_id", None)
    return item


def _normalize_remote_profiles_list(raw: Any) -> Tuple[List[Dict[str, Any]], int]:
    rows = raw if isinstance(raw, list) else []
    out: List[Dict[str, Any]] = []
    invalid = 0
    for row in rows:
        normalized = _normalize_remote_profile_item(row)
        if not isinstance(normalized, dict):
            invalid += 1
            continue
        out.append(normalized)
    return out, int(invalid)


def _site_file_fetch_timeout(size_hint_bytes: int) -> float:
    try:
        sz = max(0, int(size_hint_bytes or 0))
    except Exception:
        sz = 0
    extra = (float(sz) / float(1024 * 1024)) * float(_BACKUP_SITE_FILE_FETCH_PER_MB_SEC)
    timeout = float(_BACKUP_SITE_FILE_FETCH_BASE_TIMEOUT) + extra
    if timeout > float(_BACKUP_SITE_FILE_FETCH_MAX_TIMEOUT):
        timeout = float(_BACKUP_SITE_FILE_FETCH_MAX_TIMEOUT)
    if timeout < 20.0:
        timeout = 20.0
    return float(timeout)


def _backup_agent_request_target(node: Dict[str, Any]) -> Tuple[str, bool]:
    dt = node.get("direct_tunnel") if isinstance(node.get("direct_tunnel"), dict) else {}
    if bool(dt.get("enabled")):
        relay_node_id = _to_int_loose(dt.get("relay_node_id"), 0)
        listen_port = _to_int_loose(dt.get("listen_port"), 0)
        if relay_node_id > 0 and 1 <= listen_port <= 65535:
            host = str(dt.get("public_host") or "").strip()
            if not host:
                relay = get_node(relay_node_id)
                if isinstance(relay, dict):
                    relay_raw = str(relay.get("base_url") or "").strip()
                    if relay_raw:
                        if "://" not in relay_raw:
                            relay_raw = f"http://{relay_raw}"
                        try:
                            host = str(urlparse(relay_raw).hostname or "").strip()
                        except Exception:
                            host = ""
            if host:
                scheme = str(dt.get("scheme") or "").strip().lower()
                if scheme not in ("http", "https"):
                    node_raw = str((node or {}).get("base_url") or "").strip()
                    if "://" not in node_raw:
                        node_raw = f"http://{node_raw}" if node_raw else "http://"
                    try:
                        scheme = str(urlparse(node_raw).scheme or "http").strip().lower()
                    except Exception:
                        scheme = "http"
                    if scheme not in ("http", "https"):
                        scheme = "http"
                return f"{scheme}://{format_host_for_url(host)}:{int(listen_port)}", bool(dt.get("verify_tls"))
    return str((node or {}).get("base_url") or "").strip(), bool(node_verify_tls(node))


def _backup_node_root_base(node: Dict[str, Any], root_path: str = "") -> str:
    base = str(node.get("website_root_base") or "").strip()
    root = str(root_path or "").strip()
    if not root:
        return base
    b = base.rstrip("/")
    if not b:
        return root
    if root == b or root.startswith(b + "/"):
        return base
    return root


async def _collect_site_file_index(
    site: Dict[str, Any],
    node: Dict[str, Any],
    *,
    progress_callback: Any = None,
    site_index: int = 0,
    total_sites: int = 0,
) -> Dict[str, Any]:
    root = str(site.get("root_path") or "").strip()
    target_base_url, target_verify_tls = _backup_agent_request_target(node)
    node_base_url = str(node.get("base_url") or "").strip()
    via_tunnel = bool(target_base_url and target_base_url != node_base_url)
    site_name = _site_scan_label(site)
    route_label = "直连隧道路由" if via_tunnel else "base_url 直连"
    out: Dict[str, Any] = {
        "source_site_id": int(site.get("source_id") or site.get("id") or 0),
        "source_node_id": int(site.get("node_source_id") or site.get("node_id") or 0),
        "node_base_url": str(site.get("node_base_url") or node.get("base_url") or ""),
        "fetch_base_url": str(target_base_url or ""),
        "fetch_via_tunnel": bool(via_tunnel),
        "root_path": root,
        "package_dir": _site_pkg_dir_name(site),
        "dirs": [],
        "dir_count": 0,
        "files": [],
        "file_count": 0,
        "total_bytes": 0,
        "errors": [],
    }
    site_head = (
        f"{site_index}/{total_sites} · {site_name}"
        if total_sites > 0 and site_index > 0
        else site_name
    )
    site_base_progress = (
        68 + int(((site_index - 1) / max(1, total_sites)) * 10)
        if total_sites > 0 and site_index > 0
        else 68
    )
    if not root:
        msg = "站点 root_path 为空，跳过文件备份"
        out["errors"].append(msg)
        await _emit_backup_progress(
            progress_callback,
            {
                "progress": site_base_progress,
                "stage": "扫描网站文件",
                "step_key": "site_files",
                "step_status": "running",
                "step_detail": f"{site_head} · root_path 为空，跳过",
                "event_level": "warn",
                "event_text": f"扫描站点 {site_name}（{route_label}）：{msg}",
            },
        )
        return out
    if not target_base_url:
        msg = "节点 Agent 地址为空，跳过文件备份"
        out["errors"].append(msg)
        await _emit_backup_progress(
            progress_callback,
            {
                "progress": site_base_progress,
                "stage": "扫描网站文件",
                "step_key": "site_files",
                "step_status": "running",
                "step_detail": f"{site_head} · Agent 地址为空，跳过",
                "event_level": "warn",
                "event_text": f"扫描站点 {site_name}（{route_label}）：{msg}",
            },
        )
        return out

    root_base = _backup_node_root_base(node, root)
    queue: List[str] = [""]
    seen_dirs = set([""])
    dirs: List[str] = []
    files: List[Dict[str, Any]] = []
    loop_ticks = 0
    dirs_scanned = 0
    scan_started = time.time()
    last_emit_ts = 0.0
    list_error_events = 0

    def _site_scan_progress_now() -> int:
        if total_sites <= 0 or site_index <= 0:
            return 68
        site_base = 68 + int(((site_index - 1) / max(1, total_sites)) * 10)
        site_cap = 68 + int((site_index / max(1, total_sites)) * 10)
        span = max(1, site_cap - site_base - 1)
        ratio = dirs_scanned / max(1, dirs_scanned + len(queue))
        return min(site_cap - 1, site_base + int(ratio * span))

    while queue:
        if float(_BACKUP_SITE_SCAN_MAX_SEC) > 0 and (time.time() - scan_started) > float(_BACKUP_SITE_SCAN_MAX_SEC):
            msg = f"站点文件扫描超时（>{int(_BACKUP_SITE_SCAN_MAX_SEC)} 秒），已提前结束"
            out["errors"].append(msg)
            await _emit_backup_progress(
                progress_callback,
                {
                    "progress": _site_scan_progress_now(),
                    "stage": "扫描网站文件",
                    "step_key": "site_files",
                    "step_status": "running",
                    "step_detail": f"{site_head} · 扫描超时，已提前结束",
                    "event_level": "warn",
                    "event_text": f"扫描站点 {site_name}（{route_label}）：{msg}",
                },
            )
            break
        rel = queue.pop(0)
        dirs_scanned += 1
        now_ts = time.time()
        if (
            progress_callback is not None
            and total_sites > 0
            and site_index > 0
            and (dirs_scanned == 1 or (dirs_scanned % 25) == 0 or (now_ts - last_emit_ts) >= 2.5)
        ):
            await _emit_backup_progress(
                progress_callback,
                {
                    "progress": _site_scan_progress_now(),
                    "stage": "扫描网站文件",
                    "step_key": "site_files",
                    "step_status": "running",
                    "step_detail": (
                        f"{site_index}/{total_sites} · {site_name} · 已扫目录 {dirs_scanned} · 待扫 {len(queue)}"
                    ),
                },
            )
            last_emit_ts = now_ts
        q = urlencode({"root": root, "path": rel, "root_base": root_base})
        try:
            data = await agent_get(
                target_base_url,
                str(node.get("api_key") or ""),
                f"/api/v1/website/files/list?{q}",
                target_verify_tls,
                timeout=20,
            )
        except Exception as exc:
            msg = f"目录读取失败 [{rel or '/'}]：{exc}"
            out["errors"].append(msg)
            if list_error_events < 6:
                list_error_events += 1
                await _emit_backup_progress(
                    progress_callback,
                    {
                        "progress": _site_scan_progress_now(),
                        "stage": "扫描网站文件",
                        "step_key": "site_files",
                        "step_status": "running",
                        "step_detail": f"{site_head} · 目录读取失败 {rel or '/'}",
                        "event_level": "warn",
                        "event_text": f"扫描站点 {site_name}（{route_label}）：{msg}",
                    },
                )
            continue

        if not data.get("ok", True):
            msg = f"目录读取失败 [{rel or '/'}]：{data.get('error') or 'unknown'}"
            out["errors"].append(msg)
            if list_error_events < 6:
                list_error_events += 1
                await _emit_backup_progress(
                    progress_callback,
                    {
                        "progress": _site_scan_progress_now(),
                        "stage": "扫描网站文件",
                        "step_key": "site_files",
                        "step_status": "running",
                        "step_detail": f"{site_head} · 目录读取失败 {rel or '/'}",
                        "event_level": "warn",
                        "event_text": f"扫描站点 {site_name}（{route_label}）：{msg}",
                    },
                )
            continue

        items = data.get("items")
        if not isinstance(items, list):
            msg = f"目录读取失败 [{rel or '/'}]：返回数据格式异常"
            out["errors"].append(msg)
            if list_error_events < 6:
                list_error_events += 1
                await _emit_backup_progress(
                    progress_callback,
                    {
                        "progress": _site_scan_progress_now(),
                        "stage": "扫描网站文件",
                        "step_key": "site_files",
                        "step_status": "running",
                        "step_detail": f"{site_head} · 目录返回格式异常 {rel or '/'}",
                        "event_level": "warn",
                        "event_text": f"扫描站点 {site_name}（{route_label}）：{msg}",
                    },
                )
            continue

        for it in items:
            loop_ticks += 1
            if (loop_ticks % 500) == 0:
                # Yield periodically to keep progress API responsive on huge directories.
                await asyncio.sleep(0)
            if not isinstance(it, dict):
                continue
            p = _clean_site_rel_path(it.get("path"))
            if not p:
                continue
            if bool(it.get("is_dir")):
                if p not in seen_dirs:
                    seen_dirs.add(p)
                    dirs.append(p)
                    queue.append(p)
                continue
            if len(files) >= int(_BACKUP_SITE_FILE_MAX_FILES_PER_SITE):
                msg = f"文件数量超过单站点上限（{int(_BACKUP_SITE_FILE_MAX_FILES_PER_SITE)}），其余文件已跳过"
                out["errors"].append(msg)
                await _emit_backup_progress(
                    progress_callback,
                    {
                        "progress": _site_scan_progress_now(),
                        "stage": "扫描网站文件",
                        "step_key": "site_files",
                        "step_status": "running",
                        "step_detail": f"{site_head} · 文件数达到单站点上限，已截断",
                        "event_level": "warn",
                        "event_text": f"扫描站点 {site_name}（{route_label}）：{msg}",
                    },
                )
                queue.clear()
                break
            try:
                size_i = max(0, int(it.get("size") or 0))
            except Exception:
                size_i = 0
            files.append({"path": p, "size": size_i})

    # Deduplicate by path (keep first)
    seen_file_paths = set()
    cleaned: List[Dict[str, Any]] = []
    total_bytes = 0
    for idx, f in enumerate(sorted(files, key=lambda x: str(x.get("path") or "")), start=1):
        if (idx % 1000) == 0:
            await asyncio.sleep(0)
        p = str(f.get("path") or "")
        if not p or p in seen_file_paths:
            continue
        seen_file_paths.add(p)
        sz = max(0, int(f.get("size") or 0))
        total_bytes += sz
        cleaned.append({"path": p, "size": sz})

    out["files"] = cleaned
    out["dirs"] = sorted(dirs)
    out["dir_count"] = len(out["dirs"])
    out["file_count"] = len(cleaned)
    out["total_bytes"] = int(total_bytes)
    return out


async def _build_full_backup_bundle(
    request: Optional[Request] = None,
    progress_callback: Any = None,
    nodes_override: Optional[List[Dict[str, Any]]] = None,
    include_content: bool = True,
    panel_public_url_override: str = "",
) -> Dict[str, Any]:
    await _emit_backup_progress(
        progress_callback,
        {"progress": 4, "stage": "扫描数据", "step_key": "scan", "step_status": "running", "step_detail": "读取节点与面板配置"},
    )

    nodes = list(nodes_override) if isinstance(nodes_override, list) else list_nodes()
    group_orders = get_group_orders()

    def _safe_int(v: Any, default: int = 0) -> int:
        try:
            return int(v)
        except Exception:
            return int(default)

    def _clean_node_ids(raw: Any) -> List[int]:
        if not isinstance(raw, list):
            return []
        out: List[int] = []
        for x in raw:
            nid = _safe_int(x, 0)
            if nid > 0 and nid not in out:
                out.append(nid)
        return out

    node_map: Dict[int, Dict[str, Any]] = {}
    for n in nodes:
        nid = _safe_int((n or {}).get("id"), 0)
        if nid > 0 and nid not in node_map:
            node_map[nid] = n
    node_ids_scope = set(node_map.keys())

    sites_all = list_sites()
    if node_ids_scope:
        sites = [s for s in sites_all if _safe_int((s or {}).get("node_id"), 0) in node_ids_scope]
    else:
        sites = []

    certs_all = list_certificates()
    if node_ids_scope:
        certs = [c for c in certs_all if _safe_int((c or {}).get("node_id"), 0) in node_ids_scope]
    else:
        certs = []

    monitors_raw = list_netmon_monitors()
    monitors: List[Dict[str, Any]] = []
    for m in monitors_raw:
        if not isinstance(m, dict):
            continue
        node_ids = _clean_node_ids(m.get("node_ids"))
        if node_ids_scope:
            node_ids = [nid for nid in node_ids if nid in node_ids_scope]
            if not node_ids:
                continue
        m2 = dict(m)
        m2["node_ids"] = list(node_ids)
        monitors.append(m2)

    monitor_ids = [_safe_int(m.get("id"), 0) for m in monitors if _safe_int(m.get("id"), 0) > 0]
    if bool(_BACKUP_CONFIG_ONLY):
        netmon_samples = []
    else:
        netmon_samples_all = list_netmon_samples(
            monitor_ids,
            0,
            limit=int(_BACKUP_NETMON_SAMPLES_MAX),
        ) if monitor_ids else []
        if node_ids_scope:
            netmon_samples = [
                s for s in netmon_samples_all if _safe_int((s or {}).get("node_id"), 0) in node_ids_scope
            ]
        else:
            netmon_samples = []
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")

    fixed_zip_files = 11  # + panel/state.json + remote_storage/profiles.json + netmon/config.json + netmon/samples.json
    await _emit_backup_progress(
        progress_callback,
        {
            "progress": 12,
            "stage": "扫描完成",
            "step_key": "scan",
            "step_status": "done",
            "step_detail": f"节点 {len(nodes)} · 站点 {len(sites)} · 证书 {len(certs)} · 监控 {len(monitors)}",
            "counts": {
                "nodes": len(nodes),
                "rules": len(nodes),
                "sites": len(sites),
                "site_files": 0,
                "remote_storage_profiles": 0,
                "certificates": len(certs),
                "netmon_monitors": len(monitors),
                "netmon_samples": len(netmon_samples),
                "panel_items": 0,
                "files": fixed_zip_files + len(nodes),
            },
        },
    )

    # Build per-node rules snapshot with progress
    rules_entries: List[tuple[str, Dict[str, Any]]] = []
    total_nodes = len(nodes)
    if total_nodes:
        await _emit_backup_progress(
            progress_callback,
            {
                "progress": 14,
                "stage": "规则快照",
                "step_key": "rules",
                "step_status": "running",
                "step_detail": f"0/{total_nodes}",
            },
        )

        sem = asyncio.Semaphore(12)

        async def build_one(n: Dict[str, Any]) -> tuple[str, Dict[str, Any]]:
            node_id = int(n.get("id") or 0)
            data = await get_pool_for_backup(n)
            data.setdefault("node", {"id": node_id, "name": n.get("name"), "base_url": n.get("base_url")})
            safe = safe_filename_part(n.get("name") or f"node-{node_id}")
            path = f"rules/realm-rules-{safe}-id{node_id}.json"
            return path, data

        async def guarded(n: Dict[str, Any]) -> tuple[str, Dict[str, Any]]:
            async with sem:
                return await build_one(n)

        tasks = [asyncio.create_task(guarded(n)) for n in nodes]
        done = 0
        for fut in asyncio.as_completed(tasks):
            r = await fut
            rules_entries.append(r)
            done += 1
            pct = 14 + int((done / max(1, total_nodes)) * 38)
            await _emit_backup_progress(
                progress_callback,
                {
                    "progress": pct,
                    "stage": "规则快照",
                    "step_key": "rules",
                    "step_status": "running",
                    "step_detail": f"{done}/{total_nodes}",
                },
            )

    await _emit_backup_progress(
        progress_callback,
        {
            "progress": 52,
            "stage": "规则快照完成",
            "step_key": "rules",
            "step_status": "done",
            "step_detail": f"{len(rules_entries)} 个规则文件",
        },
    )

    # Base payloads
    await _emit_backup_progress(
        progress_callback,
        {"progress": 60, "stage": "整理网站配置", "step_key": "sites", "step_status": "running", "step_detail": f"{len(sites)} 个站点"},
    )

    def _backup_node_auto_restart_policy(node: Dict[str, Any]) -> Dict[str, Any]:
        pol = node.get("auto_restart_policy") if isinstance(node.get("auto_restart_policy"), dict) else {}
        schedule_type = str(pol.get("schedule_type") or "daily").strip().lower()
        if schedule_type not in ("daily", "weekly", "monthly"):
            schedule_type = "daily"
        interval = _safe_int(pol.get("interval"), 1)
        if interval < 1:
            interval = 1
        if interval > 365:
            interval = 365
        hour = _safe_int(pol.get("hour"), 4)
        if hour < 0:
            hour = 0
        if hour > 23:
            hour = 23
        minute = _safe_int(pol.get("minute"), 8)
        if minute < 0:
            minute = 0
        if minute > 59:
            minute = 59
        weekdays = _norm_int_seq(pol.get("weekdays"), 1, 7) or [1, 2, 3, 4, 5, 6, 7]
        monthdays = _norm_int_seq(pol.get("monthdays"), 1, 31) or [1]
        return {
            "enabled": bool(pol.get("enabled", True)),
            "schedule_type": schedule_type,
            "interval": int(interval),
            "hour": int(hour),
            "minute": int(minute),
            "weekdays": weekdays,
            "monthdays": monthdays,
            "desired_version": _safe_int(pol.get("desired_version"), 0),
            "ack_version": _safe_int(pol.get("ack_version"), 0),
            "updated_at": str(pol.get("updated_at") or ""),
        }

    def _backup_node_direct_tunnel(node: Dict[str, Any]) -> Dict[str, Any]:
        dt = node.get("direct_tunnel") if isinstance(node.get("direct_tunnel"), dict) else {}
        relay_source_id = _safe_int(dt.get("relay_node_id"), 0)
        relay_node = node_map.get(relay_source_id) if relay_source_id > 0 else None
        relay_base_url = str((relay_node or {}).get("base_url") or "").strip().rstrip("/")
        listen_port = _safe_int(dt.get("listen_port"), 0)
        if listen_port < 1 or listen_port > 65535:
            listen_port = 0
        scheme = str(dt.get("scheme") or "").strip().lower()
        if scheme not in ("http", "https"):
            scheme = ""
        return {
            "enabled": bool(dt.get("enabled") or False),
            "sync_id": str(dt.get("sync_id") or ""),
            "relay_source_id": max(0, int(relay_source_id)),
            "relay_node_id": max(0, int(relay_source_id)),
            "relay_node_base_url": relay_base_url,
            "listen_port": int(listen_port),
            "public_host": str(dt.get("public_host") or ""),
            "scheme": scheme,
            "verify_tls": bool(dt.get("verify_tls") or False),
            "updated_at": str(dt.get("updated_at") or ""),
        }

    nodes_payload = {
        "kind": "realm_full_backup",
        "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "panel_public_url": str(panel_public_url_override or (panel_public_base_url(request) if request is not None else "")),
        "group_orders": [
            {"group_name": k, "sort_order": int(v)}
            for k, v in sorted(group_orders.items(), key=lambda kv: (kv[1], kv[0]))
        ],
        "nodes": [
            {
                "source_id": int(n.get("id") or 0),
                "name": n.get("name"),
                "base_url": n.get("base_url"),
                "api_key": n.get("api_key"),
                "verify_tls": bool(n.get("verify_tls", 0)),
                "is_private": bool(n.get("is_private", 0)),
                "group_name": n.get("group_name") or "默认分组",
                "role": n.get("role") or "normal",
                "capabilities": n.get("capabilities") if isinstance(n.get("capabilities"), dict) else {},
                "website_root_base": n.get("website_root_base") or "",
                "system_type": normalize_node_system_type(n.get("system_type"), default="auto"),
                "direct_tunnel": _backup_node_direct_tunnel(n),
                "auto_restart_policy": _backup_node_auto_restart_policy(n),
            }
            for n in nodes
        ],
    }
    sites_payload = {
        "kind": "realm_sites_backup",
        "created_at": nodes_payload["created_at"],
        "sites": [
            {
                "source_id": int(s.get("id") or 0),
                "node_source_id": int(s.get("node_id") or 0),
                "node_base_url": str((node_map.get(int(s.get("node_id") or 0)) or {}).get("base_url") or ""),
                "name": str(s.get("name") or ""),
                "domains": [str(x).strip() for x in (s.get("domains") or []) if str(x).strip()],
                "root_path": str(s.get("root_path") or ""),
                "proxy_target": str(s.get("proxy_target") or ""),
                "type": str(s.get("type") or "static"),
                "web_server": str(s.get("web_server") or "nginx"),
                "nginx_tpl": str(s.get("nginx_tpl") or ""),
                "https_redirect": bool(s.get("https_redirect") or False),
                "gzip_enabled": True if s.get("gzip_enabled") is None else bool(s.get("gzip_enabled")),
                "status": str(s.get("status") or "running"),
                "health_status": str(s.get("health_status") or ""),
                "health_code": int(s.get("health_code") or 0),
                "health_latency_ms": int(s.get("health_latency_ms") or 0),
                "health_error": str(s.get("health_error") or ""),
                "health_checked_at": s.get("health_checked_at"),
                "created_at": s.get("created_at"),
                "updated_at": s.get("updated_at"),
            }
            for s in sites
        ],
    }
    await _emit_backup_progress(
        progress_callback,
        {"progress": 66, "stage": "网站配置完成", "step_key": "sites", "step_status": "done", "step_detail": f"{len(sites_payload['sites'])} 条"},
    )

    # Build website file index (list tree first; content will be pulled in package stage)
    site_files_manifest: Dict[str, Any] = {
        "kind": "realm_site_files_backup",
        "created_at": nodes_payload["created_at"],
        "sites": [],
        "summary": {"sites": 0, "files_total": 0, "files_ok": 0, "files_failed": 0, "bytes_total": 0},
    }
    site_file_total = 0
    site_file_bytes = 0
    site_file_failed = 0
    total_sites = 0
    skipped_storage_count = 0
    if bool(_BACKUP_SKIP_SITE_FILES):
        await _emit_backup_progress(
            progress_callback,
            {
                "progress": 68,
                "stage": "网站文件扫描已跳过",
                "step_key": "site_files",
                "step_status": "done",
                "step_detail": "配置模式：仅备份配置项，跳过网站文件内容",
                "event_level": "info",
                "event_text": "配置模式已启用：网站文件内容不纳入全量备份",
                "counts": {
                    "nodes": len(nodes),
                    "rules": len(rules_entries),
                    "sites": len(sites_payload["sites"]),
                    "site_files": 0,
                    "remote_storage_profiles": 0,
                    "certificates": len(certs),
                    "netmon_monitors": len(monitors),
                    "netmon_samples": 0,
                    "panel_items": 0,
                    "files": fixed_zip_files + len(rules_entries),
                },
            },
        )
    else:
        scan_sites: List[Dict[str, Any]] = []
        skipped_storage_sites: List[Dict[str, str]] = []
        for s in (sites_payload.get("sites") or []):
            if not isinstance(s, dict):
                continue
            if _is_remote_storage_mount_site(s):
                skipped_storage_sites.append(
                    {
                        "name": _site_scan_label(s),
                        "root_path": str(s.get("root_path") or "").strip(),
                    }
                )
                continue
            scan_sites.append(s)
        total_sites = len(scan_sites)
        skipped_storage_count = len(skipped_storage_sites)
        start_detail = f"0/{total_sites}"
        if skipped_storage_count > 0:
            start_detail += f" · 已跳过远程存储 {skipped_storage_count}"
        await _emit_backup_progress(
            progress_callback,
            {
                "progress": 68,
                "stage": "扫描网站文件",
                "step_key": "site_files",
                "step_status": "running",
                "step_detail": start_detail,
            },
        )
        if skipped_storage_sites:
            for idx, row in enumerate(skipped_storage_sites, start=1):
                n = str(row.get("name") or "storage_mount")
                root_hint = str(row.get("root_path") or "").strip() or "-"
                await _emit_backup_progress(
                    progress_callback,
                    {
                        "progress": 68,
                        "stage": "扫描网站文件",
                        "step_key": "site_files",
                        "step_status": "running",
                        "step_detail": f"跳过远程存储 {idx}/{skipped_storage_count} · {n}",
                        "event_level": "info",
                        "event_text": f"跳过远程存储挂载站点 {n}（root={root_hint}）",
                    },
                )
        if total_sites:
            for i, s in enumerate(scan_sites, start=1):
                sid = int(s.get("source_id") or 0)
                nid = int(s.get("node_source_id") or 0)
                site_name = _site_scan_label(s)
                root_hint = str(s.get("root_path") or "").strip() or "-"
                node = node_map.get(nid)
                if not node:
                    entry = {
                        "source_site_id": sid,
                        "source_node_id": nid,
                        "node_base_url": str(s.get("node_base_url") or ""),
                        "root_path": str(s.get("root_path") or ""),
                        "package_dir": _site_pkg_dir_name(s),
                        "dirs": [],
                        "dir_count": 0,
                        "files": [],
                        "file_count": 0,
                        "total_bytes": 0,
                        "errors": ["未找到站点节点，跳过文件备份"],
                    }
                    await _emit_backup_progress(
                        progress_callback,
                        {
                            "progress": 68 + int((i / max(1, total_sites)) * 10),
                            "stage": "扫描网站文件",
                            "step_key": "site_files",
                            "step_status": "running",
                            "step_detail": f"{i}/{total_sites} · {site_name} · 节点不存在，跳过",
                            "event_level": "warn",
                            "event_text": f"扫描站点 {site_name}（root={root_hint}）：节点不存在，跳过",
                        },
                    )
                else:
                    target_base_url, _target_verify_tls = _backup_agent_request_target(node)
                    via_tunnel = bool(str(target_base_url or "").strip() and str(target_base_url or "").strip() != str(node.get("base_url") or "").strip())
                    await _emit_backup_progress(
                        progress_callback,
                        {
                            "progress": 68 + int(((i - 1) / max(1, total_sites)) * 10),
                            "stage": "扫描网站文件",
                            "step_key": "site_files",
                            "step_status": "running",
                            "step_detail": f"{i}/{total_sites} · {site_name} · 准备扫描",
                            "event_level": "info",
                            "event_text": (
                                f"开始扫描站点 {site_name}（node={nid}，"
                                f"{'直连隧道路由' if via_tunnel else 'base_url 直连'}，root={root_hint}）"
                            ),
                        },
                    )
                    entry = await _collect_site_file_index(
                        s,
                        node,
                        progress_callback=progress_callback,
                        site_index=i,
                        total_sites=total_sites,
                    )

                pkg_dir = str(entry.get("package_dir") or _site_pkg_dir_name(s))
                dirs_idx = entry.get("dirs") if isinstance(entry.get("dirs"), list) else []
                cleaned_dirs: List[str] = []
                seen_dirs: set[str] = set()
                for d in dirs_idx:
                    rel_dir = _clean_site_rel_path(d)
                    if not rel_dir or rel_dir in seen_dirs:
                        continue
                    seen_dirs.add(rel_dir)
                    cleaned_dirs.append(rel_dir)
                cleaned_dirs.sort()
                files_idx = entry.get("files") if isinstance(entry.get("files"), list) else []
                cleaned_files = []
                for f in files_idx:
                    if not isinstance(f, dict):
                        continue
                    rel_path = _clean_site_rel_path(f.get("path"))
                    if not rel_path:
                        continue
                    size_i = max(0, int(f.get("size") or 0))
                    cleaned_files.append(
                        {
                            "path": rel_path,
                            "size": size_i,
                            "zip_path": f"websites/files/{pkg_dir}/{rel_path}",
                        }
                    )
                entry["dirs"] = cleaned_dirs
                entry["dir_count"] = len(cleaned_dirs)
                entry["files"] = cleaned_files
                entry["file_count"] = len(cleaned_files)
                entry["total_bytes"] = int(sum(int(x.get("size") or 0) for x in cleaned_files))
                entry["site_label"] = site_name
                entry["scan_root_path"] = str(s.get("root_path") or "").strip()
                entry["fetch_route"] = "direct_tunnel" if bool(entry.get("fetch_via_tunnel")) else "base_url"

                site_file_total += int(entry["file_count"])
                site_file_bytes += int(entry["total_bytes"])
                site_file_failed += len(entry.get("errors") or [])
                site_files_manifest["sites"].append(entry)
                if site_file_total >= int(_BACKUP_SITE_FILE_MAX_TOTAL_FILES):
                    site_files_manifest["summary"] = {
                        "sites": len(site_files_manifest["sites"]),
                        "sites_scanned": int(total_sites),
                        "sites_skipped": int(skipped_storage_count),
                        "files_total": site_file_total,
                        "files_ok": 0,
                        "files_failed": 0,
                        "bytes_total": site_file_bytes,
                    }
                    await _emit_backup_progress(
                        progress_callback,
                        {
                            "progress": 78,
                            "stage": "网站文件扫描中止",
                            "step_key": "site_files",
                            "step_status": "done",
                            "step_detail": f"文件数达到上限 {int(_BACKUP_SITE_FILE_MAX_TOTAL_FILES)}，已提前结束扫描",
                        },
                    )
                    break

                site_err_count = len(entry.get("errors") or [])
                site_route_label = "直连隧道路由" if bool(entry.get("fetch_via_tunnel")) else "base_url 直连"
                site_root = str(entry.get("scan_root_path") or "").strip() or "-"
                site_summary = (
                    f"站点扫描完成 {site_name}（{site_route_label}，root={site_root}）："
                    f"文件 {int(entry.get('file_count') or 0)}，大小 {int(entry.get('total_bytes') or 0)} bytes，错误 {site_err_count}"
                )
                if site_err_count > 0:
                    first_err = str((entry.get("errors") or [""])[0] or "").strip()
                    if first_err:
                        site_summary += f"；首个错误：{first_err[:180]}"
                p = 68 + int((i / max(1, total_sites)) * 10)
                await _emit_backup_progress(
                    progress_callback,
                    {
                        "progress": p,
                        "stage": "扫描网站文件",
                        "step_key": "site_files",
                        "step_status": "running",
                        "step_detail": f"{i}/{total_sites} · {site_name} · 已发现 {site_file_total} 个文件",
                        "event_level": "warn" if site_err_count > 0 else "info",
                        "event_text": site_summary,
                        "counts": {
                            "nodes": len(nodes),
                            "rules": len(rules_entries),
                            "sites": len(sites_payload["sites"]),
                            "site_files": site_file_total,
                            "remote_storage_profiles": 0,
                            "certificates": len(certs),
                            "netmon_monitors": len(monitors),
                            "netmon_samples": len(netmon_samples),
                            "panel_items": 0,
                            "files": fixed_zip_files + len(rules_entries) + site_file_total,
                        },
                    },
                )
        site_files_manifest["summary"] = {
            "sites": len(site_files_manifest["sites"]),
            "sites_scanned": int(total_sites),
            "sites_skipped": int(skipped_storage_count),
            "files_total": site_file_total,
            "files_ok": 0,
            "files_failed": 0,
            "bytes_total": site_file_bytes,
        }
        await _emit_backup_progress(
            progress_callback,
            {
                "progress": 78,
                "stage": "网站文件扫描完成",
                "step_key": "site_files",
                "step_status": "done",
                "step_detail": (
                    f"{site_file_total} 个文件 · 扫描站点 {total_sites}"
                    + (f" · 跳过远程存储 {skipped_storage_count}" if skipped_storage_count > 0 else "")
                ),
                "event_level": "info",
                "event_text": (
                    f"网站文件扫描完成：文件 {site_file_total}，扫描站点 {total_sites}"
                    + (f"，跳过远程存储 {skipped_storage_count}" if skipped_storage_count > 0 else "")
                ),
                "counts": {
                    "nodes": len(nodes),
                    "rules": len(rules_entries),
                    "sites": len(sites_payload["sites"]),
                    "site_files": site_file_total,
                    "remote_storage_profiles": 0,
                    "certificates": len(certs),
                    "netmon_monitors": len(monitors),
                    "netmon_samples": len(netmon_samples),
                    "panel_items": 0,
                    "files": fixed_zip_files + len(rules_entries) + site_file_total,
                },
            },
        )

    await _emit_backup_progress(
        progress_callback,
        {"progress": 80, "stage": "整理证书信息", "step_key": "certs", "step_status": "running", "step_detail": f"{len(certs)} 条证书"},
    )
    certs_payload = {
        "kind": "realm_certificates_backup",
        "created_at": nodes_payload["created_at"],
        "certificates": [
            {
                "source_id": int(c.get("id") or 0),
                "node_source_id": int(c.get("node_id") or 0),
                "node_base_url": str((node_map.get(int(c.get("node_id") or 0)) or {}).get("base_url") or ""),
                "site_source_id": int(c.get("site_id") or 0) if c.get("site_id") is not None else None,
                "domains": [str(x).strip() for x in (c.get("domains") or []) if str(x).strip()],
                "issuer": str(c.get("issuer") or "letsencrypt"),
                "challenge": str(c.get("challenge") or "http-01"),
                "status": str(c.get("status") or "pending"),
                "not_before": c.get("not_before"),
                "not_after": c.get("not_after"),
                "renew_at": c.get("renew_at"),
                "last_error": str(c.get("last_error") or ""),
                "created_at": c.get("created_at"),
                "updated_at": c.get("updated_at"),
            }
            for c in certs
        ],
    }
    await _emit_backup_progress(
        progress_callback,
        {"progress": 84, "stage": "证书信息完成", "step_key": "certs", "step_status": "done", "step_detail": f"{len(certs_payload['certificates'])} 条"},
    )

    await _emit_backup_progress(
        progress_callback,
        {"progress": 86, "stage": "整理网络波动配置", "step_key": "netmon", "step_status": "running", "step_detail": f"{len(monitors)} 个监控"},
    )
    monitors_items: List[Dict[str, Any]] = []
    for m in monitors:
        node_ids = _clean_node_ids(m.get("node_ids"))
        node_base_urls = [str((node_map.get(nid) or {}).get("base_url") or "") for nid in node_ids]
        monitors_items.append(
            {
                "source_id": int(m.get("id") or 0),
                "target": str(m.get("target") or ""),
                "mode": str(m.get("mode") or "ping"),
                "tcp_port": int(m.get("tcp_port") or 443),
                "interval_sec": int(m.get("interval_sec") or 5),
                "warn_ms": int(m.get("warn_ms") or 0),
                "crit_ms": int(m.get("crit_ms") or 0),
                "enabled": bool(m.get("enabled") or 0),
                "node_ids": list(node_ids),
                "node_source_ids": list(node_ids),
                "node_base_urls": node_base_urls,
                "last_run_ts_ms": int(m.get("last_run_ts_ms") or 0),
                "last_run_msg": str(m.get("last_run_msg") or ""),
                "created_at": m.get("created_at"),
                "updated_at": m.get("updated_at"),
            }
        )

    monitors_payload = {
        "kind": "realm_netmon_backup",
        "created_at": nodes_payload["created_at"],
        "monitors": monitors_items,
    }
    netmon_samples_payload = {
        "kind": "realm_netmon_samples_backup",
        "created_at": nodes_payload["created_at"],
        "samples": [],
        "summary": {"samples": 0},
    }
    for s in netmon_samples:
        try:
            src_mid = int(s.get("monitor_id") or 0)
        except Exception:
            src_mid = 0
        try:
            src_nid = int(s.get("node_id") or 0)
        except Exception:
            src_nid = 0
        latency_val: Optional[float] = None
        lat_raw = s.get("latency_ms")
        if lat_raw is not None and str(lat_raw).strip() != "":
            try:
                latency_val = float(lat_raw)
            except Exception:
                latency_val = None
        try:
            ts_ms_i = int(s.get("ts_ms") or 0)
        except Exception:
            ts_ms_i = 0
        netmon_samples_payload["samples"].append(
            {
                "source_monitor_id": src_mid,
                "source_node_id": src_nid,
                "node_base_url": str((node_map.get(src_nid) or {}).get("base_url") or ""),
                "ts_ms": ts_ms_i,
                "ok": bool(s.get("ok") or 0),
                "latency_ms": latency_val,
                "error": str(s.get("error") or ""),
            }
        )
    netmon_samples_payload["summary"] = {"samples": len(netmon_samples_payload["samples"])}
    await _emit_backup_progress(
        progress_callback,
        {
            "progress": 90,
            "stage": "网络波动配置完成",
            "step_key": "netmon",
            "step_status": "done",
            "step_detail": (
                f"{len(monitors_payload['monitors'])} 个监控 · 配置模式已跳过样本"
                if bool(_BACKUP_CONFIG_ONLY)
                else f"{len(monitors_payload['monitors'])} 个监控 · {len(netmon_samples_payload['samples'])} 条样本"
            ),
            "event_level": "info",
            "event_text": (
                f"网络波动配置完成：{len(monitors_payload['monitors'])} 个监控，配置模式已跳过历史样本"
                if bool(_BACKUP_CONFIG_ONLY)
                else ""
            ),
            "counts": {
                "nodes": len(nodes),
                "rules": len(rules_entries),
                "sites": len(sites_payload["sites"]),
                "site_files": site_file_total,
                "remote_storage_profiles": 0,
                "certificates": len(certs),
                "netmon_monitors": len(monitors),
                "netmon_samples": len(netmon_samples),
                "panel_items": 0,
                "files": fixed_zip_files + len(rules_entries) + site_file_total,
            },
        },
    )

    await _emit_backup_progress(
        progress_callback,
        {
            "progress": 91,
            "stage": "整理面板状态数据",
            "step_key": "panel_state",
            "step_status": "running",
            "step_detail": (
                "配置模式：角色/用户/令牌/规则归属"
                if bool(_BACKUP_CONFIG_ONLY)
                else "角色/用户/分享/任务/审计/统计记录"
            ),
        },
    )

    def _safe_json_loads(raw: Any, default: Any) -> Any:
        try:
            return json.loads(str(raw or "")) if str(raw or "").strip() else default
        except Exception:
            return default

    remote_storage_payload: Dict[str, Any] = {
        "kind": "realm_remote_storage_profiles_backup",
        "created_at": nodes_payload["created_at"],
        "profiles": [],
        "summary": {},
        "errors": [],
    }

    panel_state_payload: Dict[str, Any] = {
        "kind": "realm_panel_state_backup",
        "created_at": nodes_payload["created_at"],
        "panel_settings": [],
        "roles": [],
        "users": [],
        "user_tokens": [],
        "rule_owner_map": [],
        "site_file_favorites": [],
        "site_file_share_short_links": [],
        "site_file_share_revocations": [],
        "site_events": [],
        "site_checks": [],
        "audit_logs": [],
        "tasks": [],
        "rule_stats_samples": [],
        "summary": {},
        "errors": [],
    }
    panel_state_row_cap = int(_BACKUP_PANEL_STATE_MAX_ROWS_PER_TABLE)
    panel_state_config_only = bool(_BACKUP_CONFIG_ONLY)
    panel_state_history_cap = 0 if panel_state_config_only else int(panel_state_row_cap)

    async def _panel_state_heartbeat(detail: str, *, event_level: str = "info", event_text: str = "") -> None:
        txt = str(detail or "").strip()
        if not txt:
            return
        await _emit_backup_progress(
            progress_callback,
            {
                "progress": 91,
                "stage": "整理面板状态数据",
                "step_key": "panel_state",
                "step_status": "running",
                "step_detail": txt,
                "event_level": str(event_level or "info"),
                "event_text": str(event_text or txt),
            },
        )

    def _panel_state_cap_warn(label: str, rows_len: int) -> None:
        if panel_state_row_cap > 0 and int(rows_len) >= int(panel_state_row_cap):
            panel_state_payload["errors"].append(f"{label} 达到上限 {int(panel_state_row_cap)} 条，已截断")
    try:
        panel_settings_map = list_panel_settings()
        remote_profiles_raw = panel_settings_map.get("remote_storage_profiles")
        remote_profiles = _safe_json_loads(remote_profiles_raw, [])
        remote_profiles_override_value = ""
        if isinstance(remote_profiles, list):
            normalized_profiles, invalid_profile_items = _normalize_remote_profiles_list(remote_profiles)
            remote_storage_payload["profiles"] = normalized_profiles
            remote_profiles_override_value = json.dumps(normalized_profiles, ensure_ascii=False, separators=(",", ":"))
            if invalid_profile_items > 0:
                remote_storage_payload["errors"].append(
                    f"remote_storage_profiles 含 {int(invalid_profile_items)} 条非法条目，已跳过"
                )
        elif str(remote_profiles_raw or "").strip():
            remote_storage_payload["errors"].append("remote_storage_profiles 格式异常（期望数组）")

        for skey, sval in sorted(panel_settings_map.items(), key=lambda kv: str(kv[0])):
            key_s = str(skey or "").strip()
            if not key_s:
                continue
            value_s = str(sval or "")
            if key_s == "remote_storage_profiles" and remote_profiles_override_value:
                value_s = remote_profiles_override_value
            panel_state_payload["panel_settings"].append(
                {
                    "key": key_s,
                    "value": value_s,
                }
            )

        roles = list_roles()
        role_name_by_id: Dict[int, str] = {}
        for r in roles:
            rid = int(r.get("id") or 0)
            role_name = str(r.get("name") or "").strip()
            if rid > 0 and role_name:
                role_name_by_id[rid] = role_name
            panel_state_payload["roles"].append(
                {
                    "source_id": rid,
                    "name": role_name,
                    "description": str(r.get("description") or ""),
                    "permissions": [str(x).strip() for x in (r.get("permissions") or []) if str(x).strip()],
                    "builtin": bool(r.get("builtin") or 0),
                    "created_at": r.get("created_at"),
                    "updated_at": r.get("updated_at"),
                }
            )

        await _panel_state_heartbeat(
            f"面板基础信息：设置 {len(panel_state_payload['panel_settings'])} · 角色 {len(panel_state_payload['roles'])}"
        )

        with connect() as conn:
            user_rows = conn.execute(
                "SELECT id, username, salt_b64, hash_b64, iterations, role_id, enabled, expires_at, policy_json, "
                "last_login_at, created_by, created_at, updated_at FROM users ORDER BY id ASC LIMIT ?",
                (panel_state_row_cap,),
            ).fetchall()
            _panel_state_cap_warn("users", len(user_rows))
            user_name_by_id: Dict[int, str] = {}
            for idx, row in enumerate(user_rows, start=1):
                d = dict(row)
                src_uid = int(d.get("id") or 0)
                username = str(d.get("username") or "").strip()
                policy = _safe_json_loads(d.get("policy_json"), {})
                if not isinstance(policy, dict):
                    policy = {}
                if src_uid > 0 and username:
                    user_name_by_id[src_uid] = username
                panel_state_payload["users"].append(
                    {
                        "source_id": src_uid,
                        "username": username,
                        "salt_b64": str(d.get("salt_b64") or ""),
                        "hash_b64": str(d.get("hash_b64") or ""),
                        "iterations": int(d.get("iterations") or 120000),
                        "source_role_id": int(d.get("role_id") or 0),
                        "role_name": role_name_by_id.get(int(d.get("role_id") or 0), ""),
                        "enabled": bool(d.get("enabled") or 0),
                        "expires_at": d.get("expires_at"),
                        "policy": policy,
                        "last_login_at": d.get("last_login_at"),
                        "created_by": str(d.get("created_by") or ""),
                        "created_at": d.get("created_at"),
                        "updated_at": d.get("updated_at"),
                    }
                )
                if (idx % 500) == 0:
                    await asyncio.sleep(0)
            await _panel_state_heartbeat(f"用户 {len(panel_state_payload['users'])} 条")

            token_rows = conn.execute(
                "SELECT id, user_id, token_sha256, name, scopes_json, expires_at, last_used_at, created_by, created_at, revoked_at "
                "FROM user_tokens ORDER BY id ASC LIMIT ?",
                (panel_state_row_cap,),
            ).fetchall()
            _panel_state_cap_warn("user_tokens", len(token_rows))
            for idx, row in enumerate(token_rows, start=1):
                d = dict(row)
                scopes = _safe_json_loads(d.get("scopes_json"), [])
                if not isinstance(scopes, list):
                    scopes = []
                src_user_id = int(d.get("user_id") or 0)
                panel_state_payload["user_tokens"].append(
                    {
                        "source_id": int(d.get("id") or 0),
                        "source_user_id": src_user_id,
                        "source_username": user_name_by_id.get(src_user_id, ""),
                        "token_sha256": str(d.get("token_sha256") or ""),
                        "name": str(d.get("name") or ""),
                        "scopes": [str(x).strip() for x in scopes if str(x).strip()],
                        "expires_at": d.get("expires_at"),
                        "last_used_at": d.get("last_used_at"),
                        "created_by": str(d.get("created_by") or ""),
                        "created_at": d.get("created_at"),
                        "revoked_at": d.get("revoked_at"),
                    }
                )
                if (idx % 500) == 0:
                    await asyncio.sleep(0)
            await _panel_state_heartbeat(f"令牌 {len(panel_state_payload['user_tokens'])} 条")

            owner_rows = conn.execute(
                "SELECT id, node_id, rule_key, owner_user_id, owner_username, first_seen_at, last_seen_at, active "
                "FROM rule_owner_map ORDER BY id ASC LIMIT ?",
                (panel_state_row_cap,),
            ).fetchall()
            _panel_state_cap_warn("rule_owner_map", len(owner_rows))
            for idx, row in enumerate(owner_rows, start=1):
                d = dict(row)
                panel_state_payload["rule_owner_map"].append(
                    {
                        "source_id": int(d.get("id") or 0),
                        "source_node_id": int(d.get("node_id") or 0),
                        "rule_key": str(d.get("rule_key") or ""),
                        "owner_source_user_id": int(d.get("owner_user_id") or 0),
                        "owner_username": str(d.get("owner_username") or ""),
                        "first_seen_at": d.get("first_seen_at"),
                        "last_seen_at": d.get("last_seen_at"),
                        "active": bool(d.get("active") or 0),
                    }
                )
                if (idx % 500) == 0:
                    await asyncio.sleep(0)
            await _panel_state_heartbeat(f"规则归属 {len(panel_state_payload['rule_owner_map'])} 条")
            if panel_state_config_only:
                await _panel_state_heartbeat("配置模式：已跳过分享/事件/检测/审计/任务/统计历史")

            fav_rows = conn.execute(
                "SELECT id, site_id, owner, path, is_dir, created_at, updated_at "
                "FROM site_file_favorites ORDER BY id ASC LIMIT ?",
                (panel_state_history_cap,),
            ).fetchall()
            _panel_state_cap_warn("site_file_favorites", len(fav_rows))
            for idx, row in enumerate(fav_rows, start=1):
                d = dict(row)
                panel_state_payload["site_file_favorites"].append(
                    {
                        "source_id": int(d.get("id") or 0),
                        "source_site_id": int(d.get("site_id") or 0),
                        "owner": str(d.get("owner") or ""),
                        "path": str(d.get("path") or ""),
                        "is_dir": bool(d.get("is_dir") or 0),
                        "created_at": d.get("created_at"),
                        "updated_at": d.get("updated_at"),
                    }
                )
                if (idx % 500) == 0:
                    await asyncio.sleep(0)

            share_rows = conn.execute(
                "SELECT code, site_id, token, token_sha256, created_by, created_at "
                "FROM site_file_share_short_links ORDER BY created_at ASC LIMIT ?",
                (panel_state_history_cap,),
            ).fetchall()
            _panel_state_cap_warn("site_file_share_short_links", len(share_rows))
            for idx, row in enumerate(share_rows, start=1):
                d = dict(row)
                panel_state_payload["site_file_share_short_links"].append(
                    {
                        "code": str(d.get("code") or ""),
                        "source_site_id": int(d.get("site_id") or 0),
                        "token": str(d.get("token") or ""),
                        "token_sha256": str(d.get("token_sha256") or ""),
                        "created_by": str(d.get("created_by") or ""),
                        "created_at": d.get("created_at"),
                    }
                )
                if (idx % 500) == 0:
                    await asyncio.sleep(0)

            rev_rows = conn.execute(
                "SELECT id, site_id, token_sha256, revoked_by, reason, revoked_at "
                "FROM site_file_share_revocations ORDER BY id ASC LIMIT ?",
                (panel_state_history_cap,),
            ).fetchall()
            _panel_state_cap_warn("site_file_share_revocations", len(rev_rows))
            for idx, row in enumerate(rev_rows, start=1):
                d = dict(row)
                panel_state_payload["site_file_share_revocations"].append(
                    {
                        "source_id": int(d.get("id") or 0),
                        "source_site_id": int(d.get("site_id") or 0),
                        "token_sha256": str(d.get("token_sha256") or ""),
                        "revoked_by": str(d.get("revoked_by") or ""),
                        "reason": str(d.get("reason") or ""),
                        "revoked_at": d.get("revoked_at"),
                    }
                )
                if (idx % 500) == 0:
                    await asyncio.sleep(0)
            await _panel_state_heartbeat(
                f"文件分享：收藏 {len(panel_state_payload['site_file_favorites'])} · 短链 {len(panel_state_payload['site_file_share_short_links'])} · 吊销 {len(panel_state_payload['site_file_share_revocations'])}"
            )

            evt_rows = conn.execute(
                "SELECT id, site_id, action, status, actor, payload_json, result_json, error, created_at "
                "FROM site_events ORDER BY id ASC LIMIT ?",
                (panel_state_history_cap,),
            ).fetchall()
            _panel_state_cap_warn("site_events", len(evt_rows))
            for idx, row in enumerate(evt_rows, start=1):
                d = dict(row)
                payload_obj = _safe_json_loads(d.get("payload_json"), {})
                result_obj = _safe_json_loads(d.get("result_json"), {})
                if not isinstance(payload_obj, dict):
                    payload_obj = {}
                if not isinstance(result_obj, dict):
                    result_obj = {}
                panel_state_payload["site_events"].append(
                    {
                        "source_id": int(d.get("id") or 0),
                        "source_site_id": int(d.get("site_id") or 0),
                        "action": str(d.get("action") or ""),
                        "status": str(d.get("status") or "success"),
                        "actor": str(d.get("actor") or ""),
                        "payload": payload_obj,
                        "result": result_obj,
                        "error": str(d.get("error") or ""),
                        "created_at": d.get("created_at"),
                    }
                )
                if (idx % 500) == 0:
                    await asyncio.sleep(0)

            chk_rows = conn.execute(
                "SELECT id, site_id, ok, status_code, latency_ms, error, checked_at "
                "FROM site_checks ORDER BY id ASC LIMIT ?",
                (panel_state_history_cap,),
            ).fetchall()
            _panel_state_cap_warn("site_checks", len(chk_rows))
            for idx, row in enumerate(chk_rows, start=1):
                d = dict(row)
                panel_state_payload["site_checks"].append(
                    {
                        "source_id": int(d.get("id") or 0),
                        "source_site_id": int(d.get("site_id") or 0),
                        "ok": bool(d.get("ok") or 0),
                        "status_code": int(d.get("status_code") or 0),
                        "latency_ms": int(d.get("latency_ms") or 0),
                        "error": str(d.get("error") or ""),
                        "checked_at": d.get("checked_at"),
                    }
                )
                if (idx % 500) == 0:
                    await asyncio.sleep(0)
            await _panel_state_heartbeat(
                f"站点记录：事件 {len(panel_state_payload['site_events'])} · 检测 {len(panel_state_payload['site_checks'])}"
            )

            node_ids_for_scope = sorted([int(x) for x in node_ids_scope if int(x) > 0])
            node_ids_params = tuple(node_ids_for_scope)

            if node_ids_for_scope:
                placeholders = ",".join(["?"] * len(node_ids_for_scope))
                audit_rows = conn.execute(
                    "SELECT id, actor, action, node_id, node_name, source_ip, detail_json, created_at "
                    f"FROM audit_logs WHERE node_id IN ({placeholders}) OR node_id=0 ORDER BY id ASC LIMIT ?",
                    tuple(list(node_ids_params) + [panel_state_history_cap]),
                ).fetchall()
            else:
                audit_rows = conn.execute(
                    "SELECT id, actor, action, node_id, node_name, source_ip, detail_json, created_at "
                    "FROM audit_logs ORDER BY id ASC LIMIT ?",
                    (panel_state_history_cap,),
                ).fetchall()
            _panel_state_cap_warn("audit_logs", len(audit_rows))
            for idx, row in enumerate(audit_rows, start=1):
                d = dict(row)
                src_nid = int(d.get("node_id") or 0)
                detail_obj = _safe_json_loads(d.get("detail_json"), {})
                if not isinstance(detail_obj, dict):
                    detail_obj = {}
                panel_state_payload["audit_logs"].append(
                    {
                        "source_id": int(d.get("id") or 0),
                        "actor": str(d.get("actor") or ""),
                        "action": str(d.get("action") or ""),
                        "source_node_id": src_nid,
                        "node_base_url": str((node_map.get(src_nid) or {}).get("base_url") or ""),
                        "node_name": str(d.get("node_name") or ""),
                        "source_ip": str(d.get("source_ip") or ""),
                        "detail": detail_obj,
                        "created_at": d.get("created_at"),
                    }
                )
                if (idx % 500) == 0:
                    await asyncio.sleep(0)
            await _panel_state_heartbeat(f"审计日志 {len(panel_state_payload['audit_logs'])} 条")

            if node_ids_for_scope:
                placeholders = ",".join(["?"] * len(node_ids_for_scope))
                task_rows = conn.execute(
                    "SELECT id, node_id, type, payload_json, status, progress, result_json, error, created_at, updated_at "
                    f"FROM tasks WHERE node_id IN ({placeholders}) ORDER BY id ASC LIMIT ?",
                    tuple(list(node_ids_params) + [panel_state_history_cap]),
                ).fetchall()
            else:
                task_rows = conn.execute(
                    "SELECT id, node_id, type, payload_json, status, progress, result_json, error, created_at, updated_at "
                    "FROM tasks ORDER BY id ASC LIMIT ?",
                    (panel_state_history_cap,),
                ).fetchall()
            _panel_state_cap_warn("tasks", len(task_rows))
            for idx, row in enumerate(task_rows, start=1):
                d = dict(row)
                src_nid = int(d.get("node_id") or 0)
                payload_obj = _safe_json_loads(d.get("payload_json"), {})
                result_obj = _safe_json_loads(d.get("result_json"), {})
                if not isinstance(payload_obj, (dict, list)):
                    payload_obj = {}
                if not isinstance(result_obj, (dict, list)):
                    result_obj = {}
                panel_state_payload["tasks"].append(
                    {
                        "source_id": int(d.get("id") or 0),
                        "source_node_id": src_nid,
                        "node_base_url": str((node_map.get(src_nid) or {}).get("base_url") or ""),
                        "type": str(d.get("type") or ""),
                        "payload": payload_obj,
                        "status": str(d.get("status") or ""),
                        "progress": int(d.get("progress") or 0),
                        "result": result_obj,
                        "error": str(d.get("error") or ""),
                        "created_at": d.get("created_at"),
                        "updated_at": d.get("updated_at"),
                    }
                )
                if (idx % 500) == 0:
                    await asyncio.sleep(0)
            await _panel_state_heartbeat(f"任务记录 {len(panel_state_payload['tasks'])} 条")

            if node_ids_for_scope:
                placeholders = ",".join(["?"] * len(node_ids_for_scope))
                stat_rows = conn.execute(
                    "SELECT id, node_id, rule_key, ts_ms, rx_bytes, tx_bytes, connections_active, connections_total, created_at "
                    f"FROM rule_stats_samples WHERE node_id IN ({placeholders}) ORDER BY id ASC LIMIT ?",
                    tuple(list(node_ids_params) + [panel_state_history_cap]),
                ).fetchall()
            else:
                stat_rows = conn.execute(
                    "SELECT id, node_id, rule_key, ts_ms, rx_bytes, tx_bytes, connections_active, connections_total, created_at "
                    "FROM rule_stats_samples ORDER BY id ASC LIMIT ?",
                    (panel_state_history_cap,),
                ).fetchall()
            _panel_state_cap_warn("rule_stats_samples", len(stat_rows))
            for idx, row in enumerate(stat_rows, start=1):
                d = dict(row)
                src_nid = int(d.get("node_id") or 0)
                panel_state_payload["rule_stats_samples"].append(
                    {
                        "source_id": int(d.get("id") or 0),
                        "source_node_id": src_nid,
                        "node_base_url": str((node_map.get(src_nid) or {}).get("base_url") or ""),
                        "rule_key": str(d.get("rule_key") or ""),
                        "ts_ms": int(d.get("ts_ms") or 0),
                        "rx_bytes": int(d.get("rx_bytes") or 0),
                        "tx_bytes": int(d.get("tx_bytes") or 0),
                        "connections_active": int(d.get("connections_active") or 0),
                        "connections_total": int(d.get("connections_total") or 0),
                        "created_at": d.get("created_at"),
                    }
                )
                if (idx % 500) == 0:
                    await asyncio.sleep(0)
            await _panel_state_heartbeat(f"规则统计样本 {len(panel_state_payload['rule_stats_samples'])} 条")
    except Exception as exc:
        panel_state_payload["errors"].append(f"panel_state_collect_failed: {exc}")
        remote_storage_payload["errors"].append(f"remote_storage_profiles_collect_failed: {exc}")

    remote_storage_profiles_total = len(remote_storage_payload.get("profiles") or [])
    remote_storage_payload["summary"] = {
        "profiles": int(remote_storage_profiles_total),
        "errors": len(remote_storage_payload.get("errors") or []),
    }

    panel_state_payload["summary"] = {
        "panel_settings": len(panel_state_payload["panel_settings"]),
        "roles": len(panel_state_payload["roles"]),
        "users": len(panel_state_payload["users"]),
        "user_tokens": len(panel_state_payload["user_tokens"]),
        "rule_owner_map": len(panel_state_payload["rule_owner_map"]),
        "site_file_favorites": len(panel_state_payload["site_file_favorites"]),
        "site_file_share_short_links": len(panel_state_payload["site_file_share_short_links"]),
        "site_file_share_revocations": len(panel_state_payload["site_file_share_revocations"]),
        "site_events": len(panel_state_payload["site_events"]),
        "site_checks": len(panel_state_payload["site_checks"]),
        "audit_logs": len(panel_state_payload["audit_logs"]),
        "tasks": len(panel_state_payload["tasks"]),
        "rule_stats_samples": len(panel_state_payload["rule_stats_samples"]),
        "errors": len(panel_state_payload.get("errors") or []),
        "total_items": (
            len(panel_state_payload["panel_settings"])
            + len(panel_state_payload["roles"])
            + len(panel_state_payload["users"])
            + len(panel_state_payload["user_tokens"])
            + len(panel_state_payload["rule_owner_map"])
            + len(panel_state_payload["site_file_favorites"])
            + len(panel_state_payload["site_file_share_short_links"])
            + len(panel_state_payload["site_file_share_revocations"])
            + len(panel_state_payload["site_events"])
            + len(panel_state_payload["site_checks"])
            + len(panel_state_payload["audit_logs"])
            + len(panel_state_payload["tasks"])
            + len(panel_state_payload["rule_stats_samples"])
        ),
    }
    panel_items_total = int((panel_state_payload.get("summary") or {}).get("total_items") or 0)
    await _emit_backup_progress(
        progress_callback,
        {
            "progress": 93,
            "stage": "面板状态数据完成",
            "step_key": "panel_state",
            "step_status": "done",
            "step_detail": f"{panel_items_total} 条 · 挂载方案 {int(remote_storage_profiles_total)}",
            "counts": {
                "nodes": len(nodes),
                "rules": len(rules_entries),
                "sites": len(sites_payload["sites"]),
                "site_files": site_file_total,
                "remote_storage_profiles": int(remote_storage_profiles_total),
                "certificates": len(certs),
                "netmon_monitors": len(monitors),
                "netmon_samples": len(netmon_samples),
                "panel_items": panel_items_total,
                "files": fixed_zip_files + len(rules_entries) + site_file_total,
            },
        },
    )

    meta_payload = {
        "kind": "realm_backup_meta",
        "created_at": nodes_payload["created_at"],
        "nodes": len(nodes),
        "sites": len(sites_payload["sites"]),
        "site_file_sites_scanned": int(total_sites),
        "site_file_sites_skipped": int(skipped_storage_count),
        "site_files": int(site_file_total),
        "site_files_failed": int(site_file_failed),
        "site_file_bytes": int(site_file_bytes),
        "remote_storage_profiles": int(remote_storage_profiles_total),
        "certificates": len(certs_payload["certificates"]),
        "netmon_monitors": len(monitors_payload["monitors"]),
        "netmon_samples": len(netmon_samples_payload["samples"]),
        "panel_items": panel_items_total,
        "panel_state_errors": int((panel_state_payload.get("summary") or {}).get("errors") or 0),
        "rules": len(rules_entries),
        "files": fixed_zip_files + len(rules_entries) + int(site_file_total),
    }

    await _emit_backup_progress(
        progress_callback,
        {"progress": 94, "stage": "打包压缩", "step_key": "package", "step_status": "running", "step_detail": f"{meta_payload['files']} 个文件"},
    )
    fd, bundle_path = tempfile.mkstemp(prefix="nexus-backup-", suffix=".zip")
    os.close(fd)
    site_files_ok = 0
    site_files_failed_transfer = 0
    site_files_bytes_ok = 0
    try:
        with zipfile.ZipFile(bundle_path, "w", compression=zipfile.ZIP_DEFLATED) as z:
            z.writestr("nodes.json", json.dumps(nodes_payload, ensure_ascii=False, indent=2))
            z.writestr("websites/sites.json", json.dumps(sites_payload, ensure_ascii=False, indent=2))
            z.writestr("websites/certificates.json", json.dumps(certs_payload, ensure_ascii=False, indent=2))
            z.writestr("netmon/monitors.json", json.dumps(monitors_payload, ensure_ascii=False, indent=2))
            z.writestr("netmon/config.json", json.dumps(monitors_payload, ensure_ascii=False, indent=2))
            z.writestr("netmon/samples.json", json.dumps(netmon_samples_payload, ensure_ascii=False, indent=2))
            z.writestr("panel/state.json", json.dumps(panel_state_payload, ensure_ascii=False, indent=2))
            z.writestr("remote_storage/profiles.json", json.dumps(remote_storage_payload, ensure_ascii=False, indent=2))
            for path, data in rules_entries:
                z.writestr(path, json.dumps(data, ensure_ascii=False, indent=2))

            file_jobs: List[tuple[Dict[str, Any], Dict[str, Any]]] = []
            site_job_totals: Dict[str, int] = {}
            site_job_done: Dict[str, int] = {}
            site_job_ok: Dict[str, int] = {}
            site_job_fail: Dict[str, int] = {}
            last_site_job_key = ""
            for site_item in (site_files_manifest.get("sites") or []):
                if not isinstance(site_item, dict):
                    continue
                site_id = int(site_item.get("source_site_id") or 0)
                site_name = str(site_item.get("site_label") or site_item.get("package_dir") or "").strip()
                site_key = f"{site_id}:{site_name}"
                for file_item in (site_item.get("files") or []):
                    if isinstance(file_item, dict):
                        file_jobs.append((site_item, file_item))
                        site_job_totals[site_key] = int(site_job_totals.get(site_key) or 0) + 1
            total_jobs = len(file_jobs)
            if total_jobs:
                for i, (site_item, file_item) in enumerate(file_jobs, start=1):
                    site_id = int(site_item.get("source_site_id") or 0)
                    site_label = str(
                        site_item.get("site_label")
                        or site_item.get("package_dir")
                        or (f"site-{site_id}" if site_id > 0 else "site")
                    ).strip()
                    site_root = str(site_item.get("scan_root_path") or site_item.get("root_path") or "").strip() or "-"
                    site_route_label = "直连隧道路由" if bool(site_item.get("fetch_via_tunnel")) else "base_url 直连"
                    site_key = f"{site_id}:{site_label}"
                    if site_key != last_site_job_key:
                        last_site_job_key = site_key
                        site_jobs_total = int(site_job_totals.get(site_key) or 0)
                        await _emit_backup_progress(
                            progress_callback,
                            {
                                "progress": 94 + int(((i - 1) / max(1, total_jobs)) * 5),
                                "stage": "打包压缩",
                                "step_key": "package",
                                "step_status": "running",
                                "step_detail": f"拉取网站文件 {i}/{total_jobs} · {site_label}",
                                "event_level": "info",
                                "event_text": (
                                    f"开始拉取站点文件 {site_label}（{site_route_label}，root={site_root}）："
                                    f"共 {site_jobs_total} 个文件"
                                ),
                            },
                        )
                    node = node_map.get(int(site_item.get("source_node_id") or 0))
                    rel_path = _clean_site_rel_path(file_item.get("path"))
                    zip_item_path = str(file_item.get("zip_path") or "").strip()
                    root = str(site_item.get("root_path") or "").strip()
                    p = 94 + int((i / max(1, total_jobs)) * 5)
                    if not node or not root or not rel_path or not zip_item_path:
                        file_item["status"] = "failed"
                        file_item["error"] = "元数据不完整，跳过"
                        site_files_failed_transfer += 1
                        site_job_fail[site_key] = int(site_job_fail.get(site_key) or 0) + 1
                    else:
                        target_base_url, target_verify_tls = _backup_agent_request_target(node)
                        try:
                            r = await agent_get_raw_stream(
                                target_base_url,
                                str(node.get("api_key") or ""),
                                "/api/v1/website/files/raw",
                                target_verify_tls,
                                params={
                                    "root": root,
                                    "path": rel_path,
                                    "root_base": _backup_node_root_base(node, root),
                                },
                                timeout=_site_file_fetch_timeout(int(file_item.get("size") or 0)),
                            )
                            if r.status_code != 200:
                                detail = ""
                                try:
                                    body = await r.aread()
                                    detail = (body or b"").decode(errors="ignore").strip()
                                except Exception:
                                    detail = ""
                                finally:
                                    try:
                                        await r.aclose()
                                    except Exception:
                                        pass
                                if detail:
                                    raise RuntimeError(f"HTTP {r.status_code}: {detail[:160]}")
                                raise RuntimeError(f"HTTP {r.status_code}")
                            size_written = 0
                            tmp_fd, tmp_path = tempfile.mkstemp(prefix="nexus-site-file-", suffix=".tmp")
                            os.close(tmp_fd)
                            try:
                                with open(tmp_path, "wb") as wf:
                                    async for chunk in r.aiter_bytes(chunk_size=int(_BACKUP_SITE_FILE_STREAM_CHUNK_BYTES)):
                                        if not chunk:
                                            continue
                                        wf.write(chunk)
                                        size_written += len(chunk)
                                z.write(tmp_path, arcname=zip_item_path)
                            finally:
                                try:
                                    await r.aclose()
                                except Exception:
                                    pass
                                _remove_file_quiet(tmp_path)
                            file_item["status"] = "ok"
                            file_item["size"] = int(size_written)
                            site_files_ok += 1
                            site_files_bytes_ok += int(size_written)
                            site_job_ok[site_key] = int(site_job_ok.get(site_key) or 0) + 1
                        except Exception as exc:
                            file_item["status"] = "failed"
                            file_item["error"] = str(exc)
                            site_files_failed_transfer += 1
                            site_job_fail[site_key] = int(site_job_fail.get(site_key) or 0) + 1
                            errs = site_item.get("errors")
                            if not isinstance(errs, list):
                                site_item["errors"] = []
                            site_item["errors"].append(f"文件拉取失败：{rel_path} · {exc}")
                            await _emit_backup_progress(
                                progress_callback,
                                {
                                    "progress": p,
                                    "stage": "打包压缩",
                                    "step_key": "package",
                                    "step_status": "running",
                                    "step_detail": f"拉取网站文件 {i}/{total_jobs} · {site_label}",
                                    "event_level": "warn",
                                    "event_text": f"文件拉取失败：{site_label}/{rel_path}（{site_route_label}） · {exc}",
                                },
                            )

                    site_job_done[site_key] = int(site_job_done.get(site_key) or 0) + 1
                    if int(site_job_done.get(site_key) or 0) >= int(site_job_totals.get(site_key) or 0):
                        done_ok = int(site_job_ok.get(site_key) or 0)
                        done_fail = int(site_job_fail.get(site_key) or 0)
                        await _emit_backup_progress(
                            progress_callback,
                            {
                                "progress": p,
                                "stage": "打包压缩",
                                "step_key": "package",
                                "step_status": "running",
                                "step_detail": f"拉取网站文件 {i}/{total_jobs} · {site_label}",
                                "event_level": "warn" if done_fail > 0 else "info",
                                "event_text": (
                                    f"站点文件拉取完成 {site_label}（{site_route_label}）："
                                    f"成功 {done_ok}，失败 {done_fail}"
                                ),
                            },
                        )
                    await _emit_backup_progress(
                        progress_callback,
                        {
                            "progress": p,
                            "stage": "打包压缩",
                            "step_key": "package",
                            "step_status": "running",
                            "step_detail": f"拉取网站文件 {i}/{total_jobs} · {site_label}",
                        },
                    )

            # Finalize file manifest/meta with actual transfer result
            site_files_manifest["summary"] = {
                "sites": len(site_files_manifest.get("sites") or []),
                "sites_scanned": int(total_sites),
                "sites_skipped": int(skipped_storage_count),
                "files_total": total_jobs,
                "files_ok": int(site_files_ok),
                "files_failed": int(site_files_failed_transfer),
                "bytes_total": int(site_files_bytes_ok),
            }
            z.writestr("websites/files_manifest.json", json.dumps(site_files_manifest, ensure_ascii=False, indent=2))

            meta_payload["site_files"] = int(site_files_ok)
            meta_payload["site_files_failed"] = int(site_files_failed_transfer + site_file_failed)
            meta_payload["site_file_bytes"] = int(site_files_bytes_ok)
            meta_payload["remote_storage_profiles"] = int(remote_storage_profiles_total)
            meta_payload["panel_items"] = panel_items_total
            meta_payload["panel_state_errors"] = int((panel_state_payload.get("summary") or {}).get("errors") or 0)
            meta_payload["files"] = fixed_zip_files + len(rules_entries) + int(site_files_ok)
            z.writestr("backup_meta.json", json.dumps(meta_payload, ensure_ascii=False, indent=2))
            z.writestr(
                "README.txt",
                "Nexus 全量备份说明\n\n"
                "1) 恢复节点列表：登录面板 → 控制台 → 点击『恢复节点列表』，上传本压缩包（或解压后的 nodes.json）。\n"
                "2) 全量恢复：控制台 → 全量恢复，自动恢复 nodes(含直连隧道/自动重启策略)/rules/websites/certificates/netmon/panel_state。\n"
                "3) 网站文件已打包在 websites/files/ 目录，恢复时会按站点映射自动回传到节点。\n"
                "4) 网络波动配置位于 netmon/monitors.json（兼容 netmon/config.json），历史样本位于 netmon/samples.json。\n"
                "5) 远程存储挂载方案单独保存在 remote_storage/profiles.json。\n"
                "6) panel/state.json 包含用户权限、面板设置、分享记录、审计日志、任务与规则统计样本等面板状态数据。\n"
                "7) 恢复单节点规则：进入节点页面 → 更多 → 恢复规则，把 rules/ 目录下对应节点的规则文件上传/粘贴即可。\n",
            )
    except Exception:
        _remove_file_quiet(bundle_path)
        raise

    filename = f"nexus-backup-{ts}.zip"
    try:
        size_bytes = int(os.path.getsize(bundle_path))
    except Exception:
        size_bytes = 0
    content = b""
    if include_content:
        try:
            with open(bundle_path, "rb") as f:
                content = bytes(f.read())
        except Exception:
            _remove_file_quiet(bundle_path)
            raise
    await _emit_backup_progress(
        progress_callback,
        {
            "progress": 100,
            "stage": "备份完成",
            "step_key": "package",
            "step_status": "done",
            "step_detail": f"{size_bytes} bytes",
            "counts": {
                "nodes": meta_payload["nodes"],
                "rules": meta_payload["rules"],
                "sites": meta_payload["sites"],
                "site_files": int(meta_payload.get("site_files") or 0),
                "remote_storage_profiles": int(meta_payload.get("remote_storage_profiles") or 0),
                "certificates": meta_payload["certificates"],
                "netmon_monitors": meta_payload["netmon_monitors"],
                "netmon_samples": int(meta_payload.get("netmon_samples") or 0),
                "panel_items": int(meta_payload.get("panel_items") or 0),
                "files": meta_payload["files"],
            },
        },
    )

    return {
        "filename": filename,
        "content": content,
        "zip_path": bundle_path,
        "size_bytes": size_bytes,
        "meta": meta_payload,
    }


def _restore_steps_template() -> List[Dict[str, Any]]:
    return [
        {"key": "upload", "label": "上传备份包", "status": "pending", "detail": ""},
        {"key": "parse", "label": "解析备份包", "status": "pending", "detail": ""},
        {"key": "rules", "label": "恢复节点与规则", "status": "pending", "detail": ""},
        {"key": "sites_files", "label": "恢复网站与文件", "status": "pending", "detail": ""},
        {"key": "certs_netmon", "label": "恢复证书与网络波动", "status": "pending", "detail": ""},
        {"key": "panel_state", "label": "恢复用户与面板状态", "status": "pending", "detail": ""},
        {"key": "finalize", "label": "收尾与校验", "status": "pending", "detail": ""},
    ]


def _prune_full_restore_jobs() -> None:
    now = time.time()
    with _FULL_RESTORE_LOCK:
        stale_ids: List[str] = []
        for jid, job in _FULL_RESTORE_JOBS.items():
            st = str(job.get("status") or "")
            created_at = _to_float_loose(job.get("created_at"), 0.0)
            updated_at = _to_float_loose(job.get("updated_at"), 0.0)
            if st in ("queued", "running") and created_at > 0 and (now - created_at) > float(_FULL_RESTORE_ACTIVE_MAX_SEC):
                stale_ids.append(jid)
                continue
            if st in ("done", "failed") and (now - updated_at) > _FULL_RESTORE_TTL_SEC:
                stale_ids.append(jid)
        for jid in stale_ids:
            _FULL_RESTORE_JOBS.pop(jid, None)


def _restore_job_snapshot(job_id: str) -> Optional[Dict[str, Any]]:
    with _FULL_RESTORE_LOCK:
        job = _FULL_RESTORE_JOBS.get(job_id)
        if not isinstance(job, dict):
            return None
        result = job.get("result")
        steps = job.get("steps")
        return {
            "job_id": str(job_id),
            "status": str(job.get("status") or "unknown"),
            "progress": _to_int_loose(job.get("progress"), 0),
            "stage": str(job.get("stage") or ""),
            "error": str(job.get("error") or ""),
            "created_at": _to_float_loose(job.get("created_at"), 0.0),
            "updated_at": _to_float_loose(job.get("updated_at"), 0.0),
            "steps": list(steps) if isinstance(steps, list) else [],
            "result": dict(result) if isinstance(result, dict) else {},
        }


def _touch_restore_job(
    job_id: str,
    *,
    status: Optional[str] = None,
    progress: Optional[int] = None,
    stage: Optional[str] = None,
    error: Optional[str] = None,
    result: Optional[Dict[str, Any]] = None,
    step_key: Optional[str] = None,
    step_status: Optional[str] = None,
    step_detail: Optional[str] = None,
) -> None:
    now = time.time()
    with _FULL_RESTORE_LOCK:
        job = _FULL_RESTORE_JOBS.get(job_id)
        if not isinstance(job, dict):
            return
        if status is not None:
            job["status"] = str(status)
        if progress is not None:
            p = max(0, min(100, int(progress)))
            job["progress"] = p
        if stage is not None:
            job["stage"] = str(stage)
        if error is not None:
            job["error"] = str(error)
        if result is not None:
            job["result"] = dict(result)
        if step_key:
            for s in (job.get("steps") or []):
                if str(s.get("key") or "") == str(step_key):
                    if step_status is not None:
                        s["status"] = str(step_status)
                    if step_detail is not None:
                        s["detail"] = str(step_detail)
                    break
        job["updated_at"] = now


def _restore_stage_by_progress(progress: int) -> Dict[str, str]:
    p = int(progress)
    if p < 15:
        return {"key": "upload", "stage": "上传备份包中…"}
    if p < 28:
        return {"key": "parse", "stage": "解析备份包…"}
    if p < 48:
        return {"key": "rules", "stage": "恢复节点与规则…"}
    if p < 66:
        return {"key": "sites_files", "stage": "恢复网站配置与文件…"}
    if p < 80:
        return {"key": "certs_netmon", "stage": "恢复证书与网络波动…"}
    if p < 94:
        return {"key": "panel_state", "stage": "恢复用户权限与面板状态…"}
    return {"key": "finalize", "stage": "收尾与校验…"}


def _restore_running_detail(step_key: str, elapsed_sec: int) -> str:
    k = str(step_key or "").strip()
    sec = max(0, int(elapsed_sec or 0))
    if k == "upload":
        return f"上传中（流式接收） {sec}s"
    if k == "parse":
        return f"解析压缩包目录与元数据 {sec}s"
    if k == "rules":
        return f"恢复节点与规则并尝试下发 {sec}s"
    if k == "sites_files":
        return f"恢复网站配置与文件内容（大文件会更慢） {sec}s"
    if k == "certs_netmon":
        return f"恢复证书与网络波动配置 {sec}s"
    if k == "panel_state":
        return f"恢复用户权限与面板状态配置 {sec}s"
    if k == "finalize":
        if sec < 30:
            return f"校验映射与恢复统计 {sec}s"
        if sec < 90:
            return f"提交数据库事务并同步状态 {sec}s"
        return f"清理临时资源与最终一致性校验 {sec}s"
    return f"执行中 {sec}s"


async def _restore_progress_ticker(job_id: str) -> None:
    order = ["upload", "parse", "rules", "sites_files", "certs_netmon", "panel_state", "finalize"]
    while True:
        await asyncio.sleep(0.6)
        now_ts = time.time()
        with _FULL_RESTORE_LOCK:
            job = _FULL_RESTORE_JOBS.get(job_id)
            if not isinstance(job, dict):
                return
            if str(job.get("status") or "") != "running":
                return
            cur = int(job.get("progress") or 6)
            created_at = float(job.get("created_at") or now_ts)
        if cur >= 95:
            elapsed = max(0, int(now_ts - created_at))
            _touch_restore_job(
                job_id,
                progress=95,
                stage="收尾与校验…",
                step_key="finalize",
                step_status="running",
                step_detail=_restore_running_detail("finalize", elapsed),
            )
            continue
        bump = random.randint(1, 3) if cur < 60 else random.randint(1, 2)
        nxt = min(95, cur + bump)
        pos = _restore_stage_by_progress(nxt)
        cur_key = str(pos.get("key") or "")
        idx = order.index(cur_key) if cur_key in order else 0
        elapsed = max(0, int(now_ts - created_at))
        _touch_restore_job(
            job_id,
            progress=nxt,
            stage=pos.get("stage"),
            step_key=cur_key,
            step_status="running",
            step_detail=_restore_running_detail(cur_key, elapsed),
        )
        for i, k in enumerate(order):
            if i < idx:
                _touch_restore_job(job_id, step_key=k, step_status="done", step_detail="已完成")
            elif i > idx:
                _touch_restore_job(job_id, step_key=k, step_status="pending", step_detail="")


def _parse_json_response_obj(resp: JSONResponse) -> Dict[str, Any]:
    try:
        body = getattr(resp, "body", b"") or b""
        if isinstance(body, bytes):
            return json.loads(body.decode("utf-8"))
        return json.loads(str(body))
    except Exception:
        return {"ok": False, "error": "接口返回异常"}


def _restore_cancel_message(exc: BaseException, fallback: str) -> str:
    cls_name = str(exc.__class__.__name__ or "").strip()
    msg = str(exc or "").strip()
    if isinstance(exc, asyncio.CancelledError):
        return f"{fallback}（请求断开或任务取消）"
    if "disconnect" in cls_name.lower():
        return f"{fallback}（请求连接已断开）"
    if msg:
        return msg
    return fallback


def _touch_node_last_seen_safe(node_id: int, node: Optional[Dict[str, Any]] = None) -> None:
    """Direct-agent success should also refresh online timestamp."""
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        touch_node_last_seen(int(node_id), last_seen_at=now_str)
    except Exception:
        return
    if isinstance(node, dict):
        node["last_seen_at"] = now_str


def _report_ping_payload(node_id: int, node: Dict[str, Any], allow_stale: bool) -> Optional[Dict[str, Any]]:
    fresh = bool(is_report_fresh(node))
    if (not allow_stale) and (not fresh):
        return None
    rep = get_last_report(node_id)
    if not isinstance(rep, dict):
        return None
    info = rep.get("info")
    return {
        "ok": True,
        "source": "report",
        "stale": (not fresh),
        "last_seen_at": node.get("last_seen_at"),
        "info": info,
    }


@router.get("/api/nodes/{node_id}/ping")
async def api_ping(request: Request, node_id: int, user: str = Depends(require_login)):
    node = get_node(node_id)
    if not node:
        return JSONResponse({"ok": False, "error": "节点不存在"}, status_code=404)

    last_direct_err = ""
    for idx, source in enumerate(node_info_sources_order(force_pull=False)):
        if source == "report":
            payload = _report_ping_payload(node_id, node, allow_stale=(idx > 0))
            if isinstance(payload, dict):
                return payload
            continue

        try:
            target_base_url, target_verify_tls, _target_route = node_agent_request_target(node)
            info = await agent_ping(target_base_url, node["api_key"], target_verify_tls)
        except Exception as exc:
            last_direct_err = str(exc)
            continue
        if bool(info.get("ok")):
            _touch_node_last_seen_safe(node_id, node)
            if "source" not in info:
                info["source"] = "agent"
            return info
        last_direct_err = str(info.get("error", "offline"))

    fallback = _report_ping_payload(node_id, node, allow_stale=True)
    if isinstance(fallback, dict):
        return fallback
    return {"ok": False, "error": last_direct_err or "offline"}


@router.post("/api/nodes/{node_id}/trace")
async def api_trace_route(request: Request, node_id: int, payload: Dict[str, Any], user: str = Depends(require_login)):
    node = get_node(node_id)
    if not node:
        return JSONResponse({"ok": False, "error": "节点不存在"}, status_code=404)

    target = _trace_route_target(payload.get("target") if isinstance(payload, dict) else "")
    if not target:
        return JSONResponse({"ok": False, "error": "目标不能为空"}, status_code=400)

    max_hops = _trace_route_max_hops(payload.get("max_hops") if isinstance(payload, dict) else None)
    timeout_f = _trace_route_timeout(payload.get("timeout") if isinstance(payload, dict) else None)
    probes = _trace_route_probes(payload.get("probes") if isinstance(payload, dict) else None)

    body = {
        "target": target,
        "max_hops": int(max_hops),
        "timeout": float(timeout_f),
        "probes": int(probes),
    }

    try:
        target_base_url, target_verify_tls, _target_route = node_agent_request_target(node)
        data = await agent_post(
            target_base_url,
            node.get("api_key", ""),
            "/api/v1/netprobe/trace",
            body,
            target_verify_tls,
            timeout=_TRACE_ROUTE_HTTP_TIMEOUT,
        )
    except Exception as exc:
        return JSONResponse({"ok": False, "error": f"路由追踪请求失败：{exc}"}, status_code=502)

    if not isinstance(data, dict):
        return JSONResponse({"ok": False, "error": "Agent 返回异常"}, status_code=502)

    if data.get("ok") is not True:
        err = str(data.get("error") or "trace_failed").strip() or "trace_failed"
        detail = str(data.get("detail") or "").strip()
        if detail and detail not in err:
            err = f"{err}：{detail}"
        data["error"] = err
    return data


@router.get("/api/nodes/{node_id}/pool")
async def api_pool_get(request: Request, node_id: int, user: str = Depends(require_login)):
    node = get_node(node_id)
    if not node:
        return JSONResponse({"ok": False, "error": "节点不存在"}, status_code=404)

    # Push-report mode: prefer desired pool stored on panel
    desired_ver, desired_pool = get_desired_pool(node_id)
    if isinstance(desired_pool, dict):
        return {
            "ok": True,
            "pool": _filter_pool_for_user(user, desired_pool),
            "desired_version": desired_ver,
            "source": "panel_desired",
        }

    rep: Optional[Dict[str, Any]] = None
    last_pull_err = ""
    for source in node_info_sources_order(force_pull=False):
        if source == "report":
            if rep is None:
                rep = get_last_report(node_id)
            if isinstance(rep, dict) and isinstance(rep.get("pool"), dict):
                return {
                    "ok": True,
                    "pool": _filter_pool_for_user(user, rep.get("pool")),
                    "source": "report_cache",
                    "stale": (not bool(is_report_fresh(node))),
                }
            continue
        try:
            target_base_url, target_verify_tls, _target_route = node_agent_request_target(node)
            data = await agent_get(target_base_url, node["api_key"], "/api/v1/pool", target_verify_tls)
            if isinstance(data, dict):
                return _pool_like_response_with_filter(user, data)
            return data
        except Exception as exc:
            last_pull_err = str(exc)
            continue

    if isinstance(rep, dict) and isinstance(rep.get("pool"), dict):
        return {
            "ok": True,
            "pool": _filter_pool_for_user(user, rep.get("pool")),
            "source": "report_cache",
            "stale": True,
        }
    return JSONResponse({"ok": False, "error": last_pull_err or "暂无可用规则快照"}, status_code=502)


@router.get("/api/nodes/{node_id}/backup")
async def api_backup(request: Request, node_id: int, user: str = Depends(require_login)):
    node = get_node(node_id)
    if not node:
        return JSONResponse({"ok": False, "error": "节点不存在"}, status_code=404)
    try:
        data = await get_pool_for_backup(node)
        if isinstance(data, dict):
            data = _pool_like_response_with_filter(user, data)
        # 规则文件名包含节点名，便于区分
        safe = safe_filename_part(node.get("name") or f"node-{node_id}")
        filename = f"realm-rules-{safe}-id{node_id}.json"
        payload = json.dumps(data, ensure_ascii=False, indent=2, default=str)
    except Exception as exc:
        return JSONResponse({"ok": False, "error": f"备份失败：{exc}"}, status_code=500)
    try:
        headers = {"Content-Disposition": _download_content_disposition(filename, fallback=f"realm-rules-node-{node_id}.json")}
        return Response(content=payload, media_type="application/json", headers=headers)
    except Exception as exc:
        return JSONResponse({"ok": False, "error": f"备份响应构造失败：{exc}"}, status_code=500)


@router.get("/api/backup/full")
async def api_backup_full(request: Request, user: str = Depends(require_login)):
    """Direct download full backup zip (legacy one-shot behavior)."""
    visible_nodes = filter_nodes_for_user(user, list_nodes())
    panel_public_url = panel_public_base_url(request)

    def _run_sync() -> Dict[str, Any]:
        return asyncio.run(
            _build_full_backup_bundle(
                request=None,
                nodes_override=visible_nodes,
                include_content=False,
                panel_public_url_override=panel_public_url,
            )
        )

    bundle = await asyncio.to_thread(_run_sync)
    filename = str(bundle.get("filename") or f"nexus-backup-{datetime.now().strftime('%Y%m%d-%H%M%S')}.zip")
    bundle_path = str(bundle.get("zip_path") or "").strip()
    if not bundle_path or not os.path.exists(bundle_path):
        return JSONResponse({"ok": False, "error": "备份文件生成失败"}, status_code=500)
    return FileResponse(
        path=bundle_path,
        media_type="application/zip",
        filename=filename,
        background=BackgroundTask(_remove_file_quiet, bundle_path),
    )


@router.post("/api/backup/full/start")
async def api_backup_full_start(request: Request, user: str = Depends(require_login)):
    """Start full backup in background and return a job id for progress polling."""
    visible_nodes = filter_nodes_for_user(user, list_nodes())
    panel_public_url = panel_public_base_url(request)
    _prune_full_backup_jobs()
    active_ids = _active_full_backup_job_ids()
    logger.info(
        "full backup start requested user=%s visible_nodes=%d active_jobs=%d",
        str(user or ""),
        len(visible_nodes),
        len(active_ids),
    )
    if active_ids and int(_FULL_BACKUP_MAX_CONCURRENT) <= 1:
        # Reuse newest active job to avoid duplicate heavy backup tasks.
        reuse_id = str(active_ids[-1] or "").strip()
        snap = _backup_job_snapshot(reuse_id) if reuse_id else None
        if snap:
            return {"ok": True, "reused": True, **snap}
    if len(active_ids) >= int(_FULL_BACKUP_MAX_CONCURRENT):
        return JSONResponse(
            {"ok": False, "error": f"当前已有 {len(active_ids)} 个备份任务进行中，请稍后再试"},
            status_code=429,
        )
    job_id = uuid.uuid4().hex
    now = time.time()

    with _FULL_BACKUP_LOCK:
        _FULL_BACKUP_JOBS[job_id] = {
            "status": "running",
            "progress": 1,
            "stage": "准备备份任务",
            "error": "",
            "created_at": now,
            "updated_at": now,
            "size_bytes": 0,
            "filename": "",
            "steps": _backup_steps_template(),
            "counts": {
                "nodes": 0,
                "rules": 0,
                "sites": 0,
                "site_files": 0,
                "remote_storage_profiles": 0,
                "certificates": 0,
                "netmon_monitors": 0,
                "netmon_samples": 0,
                "files": 0,
            },
            "content": b"",
            "file_path": "",
            "events": [
                {
                    "ts_ms": int(max(0.0, now) * 1000.0),
                    "stage": "准备备份任务",
                    "progress": 1,
                    "level": "info",
                    "detail": "任务已创建，等待后台执行",
                }
            ],
            "event_total": 1,
        }

    async def _progress_cb(payload: Dict[str, Any]) -> None:
        if not isinstance(payload, dict):
            return
        stage_s = str(payload.get("stage") or "").strip()
        detail_s = str(payload.get("step_detail") or "").strip()
        event_text = str(payload.get("event_text") or "").strip()
        if not event_text:
            if stage_s and detail_s:
                event_text = f"{stage_s} · {detail_s}"
            elif stage_s:
                event_text = stage_s
            elif detail_s:
                event_text = detail_s
        event_level = str(payload.get("event_level") or "").strip().lower()
        if not event_level:
            event_level = "error" if str(payload.get("step_status") or "").strip().lower() == "failed" else "info"
        _touch_backup_job(
            job_id,
            progress=payload.get("progress"),
            stage=payload.get("stage"),
            counts=payload.get("counts") if isinstance(payload.get("counts"), dict) else None,
            step_key=payload.get("step_key"),
            step_status=payload.get("step_status"),
            step_detail=payload.get("step_detail"),
            event_text=event_text,
            event_level=event_level,
        )

    async def _run() -> None:
        bundle_path = ""
        started_at = time.time()
        try:
            bundle = await _build_full_backup_bundle(
                None,
                _progress_cb,
                nodes_override=visible_nodes,
                include_content=False,
                panel_public_url_override=panel_public_url,
            )
            meta = bundle.get("meta") if isinstance(bundle.get("meta"), dict) else {}
            counts = {
                "nodes": int(meta.get("nodes") or 0),
                "rules": int(meta.get("rules") or 0),
                "sites": int(meta.get("sites") or 0),
                "site_files": int(meta.get("site_files") or 0),
                "remote_storage_profiles": int(meta.get("remote_storage_profiles") or 0),
                "certificates": int(meta.get("certificates") or 0),
                "netmon_monitors": int(meta.get("netmon_monitors") or 0),
                "netmon_samples": int(meta.get("netmon_samples") or 0),
                "files": int(meta.get("files") or 0),
            }
            bundle_path = str(bundle.get("zip_path") or "").strip()
            if not bundle_path or not os.path.exists(bundle_path):
                raise RuntimeError("备份文件生成失败")
            try:
                size_bytes = int(os.path.getsize(bundle_path))
            except Exception:
                size_bytes = int(bundle.get("size_bytes") or 0)
            _touch_backup_job(
                job_id,
                status="done",
                progress=100,
                stage="备份完成",
                filename=str(bundle.get("filename") or ""),
                size_bytes=size_bytes,
                counts=counts,
                file_path=bundle_path,
                event_text=f"备份完成，生成 {int(size_bytes)} bytes",
                event_level="info",
            )
            logger.info(
                "full backup done job_id=%s size_bytes=%d files=%d duration_sec=%.2f",
                str(job_id),
                int(size_bytes),
                int(counts.get("files") or 0),
                max(0.0, time.time() - started_at),
            )
            bundle_path = ""
        except Exception as exc:
            logger.exception("full backup failed job_id=%s", str(job_id))
            if bundle_path:
                _remove_file_quiet(bundle_path)
            _touch_backup_job(
                job_id,
                status="failed",
                progress=100,
                stage="备份失败",
                error=str(exc),
                event_text=f"备份失败：{exc}",
                event_level="error",
            )

    def _thread_entry() -> None:
        try:
            asyncio.run(_run())
        except Exception as exc:
            logger.exception("backup-job thread crashed job_id=%s", job_id)
            _touch_backup_job(
                job_id,
                status="failed",
                progress=100,
                stage="备份失败",
                error=f"任务线程崩溃：{exc}",
                event_text=f"任务线程崩溃：{exc}",
                event_level="error",
            )

    try:
        t = threading.Thread(target=_thread_entry, name=f"backup-job-{job_id}", daemon=True)
        t.start()
        logger.info("full backup worker started job_id=%s thread=%s", str(job_id), str(t.name))
    except Exception as exc:
        _touch_backup_job(
            job_id,
            status="failed",
            progress=100,
            stage="备份失败",
            error=f"任务调度失败：{exc}",
            event_text=f"任务调度失败：{exc}",
            event_level="error",
        )
        return JSONResponse({"ok": False, "error": f"创建备份任务失败：{exc}"}, status_code=500)
    snap = _backup_job_snapshot(job_id)
    if not snap:
        return JSONResponse({"ok": False, "error": "创建备份任务失败"}, status_code=500)
    return {"ok": True, **snap}


@router.get("/api/backup/full/progress")
async def api_backup_full_progress(job_id: str = "", user: str = Depends(require_login)):
    """Get backup job progress."""
    _ = user
    jid = str(job_id or "").strip()
    try:
        _prune_full_backup_jobs()
        if not jid:
            return JSONResponse({"ok": False, "error": "缺少 job_id"}, status_code=400)
        snap = _backup_job_snapshot(jid)
        if not snap:
            return JSONResponse({"ok": False, "error": "备份任务不存在或已过期"}, status_code=404)
        return {"ok": True, **snap}
    except Exception as exc:
        logger.exception("backup progress query failed job_id=%s", jid)
        return JSONResponse({"ok": False, "error": f"进度查询异常：{exc}"}, status_code=500)


@router.get("/api/backup/full/download")
async def api_backup_full_download(job_id: str = "", user: str = Depends(require_login)):
    """Download finished backup by job id."""
    _prune_full_backup_jobs()
    jid = str(job_id or "").strip()
    if not jid:
        return JSONResponse({"ok": False, "error": "缺少 job_id"}, status_code=400)

    with _FULL_BACKUP_LOCK:
        job = _FULL_BACKUP_JOBS.get(jid)
        if not isinstance(job, dict):
            return JSONResponse({"ok": False, "error": "备份任务不存在或已过期"}, status_code=404)
        status = str(job.get("status") or "")
        filename = str(job.get("filename") or "")
        file_path = str(job.get("file_path") or "").strip()
        content = bytes(job.get("content") or b"")

    if status != "done":
        return JSONResponse({"ok": False, "error": "备份尚未完成，请稍候再试"}, status_code=409)

    if not filename:
        filename = f"nexus-backup-{datetime.now().strftime('%Y%m%d-%H%M%S')}.zip"
    if file_path:
        if not os.path.exists(file_path):
            return JSONResponse({"ok": False, "error": "备份文件已失效，请重新生成"}, status_code=410)
        return FileResponse(path=file_path, media_type="application/zip", filename=filename)
    if not content:
        return JSONResponse({"ok": False, "error": "备份文件不可用，请重新生成"}, status_code=410)
    try:
        headers = {"Content-Disposition": _download_content_disposition(filename, fallback="nexus-backup.zip")}
        return Response(content=content, media_type="application/zip", headers=headers)
    except Exception as exc:
        return JSONResponse({"ok": False, "error": f"备份下载响应失败：{exc}"}, status_code=500)


@router.post("/api/restore/nodes")
async def api_restore_nodes(
    request: Request,
    file: UploadFile = File(...),
    user: str = Depends(require_login),
):
    """Restore nodes list from nodes.json or full backup zip."""
    try:
        await file.seek(0)
    except Exception:
        pass
    total = 0
    buf = bytearray()
    try:
        while True:
            chunk = await file.read(_RESTORE_UPLOAD_CHUNK_SIZE)
            if not chunk:
                break
            total += len(chunk)
            if total > _NODES_RESTORE_MAX_BYTES:
                return JSONResponse(
                    {
                        "ok": False,
                        "error": f"上传文件过大（当前限制 {_format_bytes(_NODES_RESTORE_MAX_BYTES)}）",
                    },
                    status_code=413,
                )
            buf.extend(chunk)
    except Exception as exc:
        return JSONResponse({"ok": False, "error": f"读取文件失败：{exc}"}, status_code=400)
    raw = bytes(buf)
    if not raw:
        return JSONResponse({"ok": False, "error": "上传文件为空"}, status_code=400)

    payload = None
    # Zip?
    if raw[:2] == b"PK":
        try:
            with zipfile.ZipFile(io.BytesIO(raw)) as z:
                # find nodes.json
                name = None
                for n in z.namelist():
                    if n.lower().endswith("nodes.json"):
                        name = n
                        break
                if not name:
                    return JSONResponse({"ok": False, "error": "压缩包中未找到 nodes.json"}, status_code=400)
                payload = json.loads(z.read(name).decode("utf-8"))
        except Exception as exc:
            return JSONResponse({"ok": False, "error": f"压缩包解析失败：{exc}"}, status_code=400)
    else:
        try:
            payload = json.loads(raw.decode("utf-8"))
        except Exception as exc:
            return JSONResponse({"ok": False, "error": f"JSON 解析失败：{exc}"}, status_code=400)

    # Accept: {nodes:[...]} or plain list
    nodes_list = None
    if isinstance(payload, dict) and isinstance(payload.get("nodes"), list):
        nodes_list = payload.get("nodes")
    elif isinstance(payload, list):
        nodes_list = payload

    if not isinstance(nodes_list, list):
        return JSONResponse({"ok": False, "error": "备份内容缺少 nodes 列表"}, status_code=400)

    # Optional: restore group orders (UI sorting)
    try:
        go = payload.get("group_orders") if isinstance(payload, dict) else None
        items: List[Dict[str, Any]] = []
        if isinstance(go, dict):
            items = [{"group_name": k, "sort_order": v} for k, v in go.items()]
        elif isinstance(go, list):
            items = [x for x in go if isinstance(x, dict)]
        for it in items:
            gname = str(it.get("group_name") or it.get("name") or "").strip() or "默认分组"
            try:
                s = int(it.get("sort_order", it.get("order", 1000)))
            except Exception:
                continue
            upsert_group_order(gname, s)
    except Exception:
        pass

    added = 0
    updated = 0
    skipped = 0
    mapping: Dict[str, int] = {}
    baseurl_to_nodeid: Dict[str, int] = {}

    for item in nodes_list:
        if not isinstance(item, dict):
            skipped += 1
            continue
        name = (item.get("name") or "").strip()
        base_url = (item.get("base_url") or "").strip().rstrip("/")
        api_key = (item.get("api_key") or "").strip()
        verify_tls = bool(item.get("verify_tls", False))
        is_private = bool(item.get("is_private", False))
        role = str(item.get("role") or "normal").strip().lower() or "normal"
        if role not in ("normal", "website"):
            role = "normal"
        capabilities = item.get("capabilities") if isinstance(item.get("capabilities"), dict) else {}
        website_root_base = str(item.get("website_root_base") or "").strip()
        group_name = (
            (item.get("group_name") or "默认分组").strip()
            if isinstance(item.get("group_name"), str)
            else (
                "默认分组" if not item.get("group_name") else str(item.get("group_name"))
            )
        )
        group_name = (group_name or "默认分组").strip() or "默认分组"
        system_type = normalize_node_system_type(item.get("system_type"), default="auto")
        source_id = item.get("source_id")
        try:
            source_id_i = int(source_id) if source_id is not None else None
        except Exception:
            source_id_i = None

        if not base_url or not api_key:
            skipped += 1
            continue

        existing = get_node_by_api_key(api_key) or get_node_by_base_url(base_url)
        if source_id_i is not None and source_id_i > 0:
            by_source = get_node(source_id_i)
            if by_source:
                existing = by_source
        if existing:
            update_node_basic(
                existing["id"],
                name or existing.get("name") or extract_ip_for_display(base_url),
                base_url,
                api_key,
                verify_tls=verify_tls,
                is_private=is_private,
                group_name=group_name,
                role=role,
                capabilities=capabilities,
                website_root_base=website_root_base,
                system_type=system_type,
            )
            updated += 1
            node_id = int(existing["id"])
            baseurl_to_nodeid[base_url] = int(node_id)
            if source_id_i is not None and source_id_i > 0:
                mapping[str(source_id_i)] = node_id
        else:
            node_name = name or extract_ip_for_display(base_url)
            preferred_id = source_id_i if source_id_i is not None and source_id_i > 0 else None
            node_id: Optional[int] = None
            try:
                node_id = int(
                    add_node(
                        node_name,
                        base_url,
                        api_key,
                        verify_tls=verify_tls,
                        is_private=is_private,
                        group_name=group_name,
                        role=role,
                        capabilities=capabilities,
                        website_root_base=website_root_base,
                        preferred_id=preferred_id,
                        system_type=system_type,
                    )
                )
                added += 1
            except Exception:
                fallback = None
                if preferred_id:
                    fallback = get_node(preferred_id)
                if not fallback:
                    fallback = get_node_by_api_key(api_key) or get_node_by_base_url(base_url)
                if fallback:
                    update_node_basic(
                        fallback["id"],
                        node_name,
                        base_url,
                        api_key,
                        verify_tls=verify_tls,
                        is_private=is_private,
                        group_name=group_name,
                        role=role,
                        capabilities=capabilities,
                        website_root_base=website_root_base,
                        system_type=system_type,
                    )
                    updated += 1
                    node_id = int(fallback["id"])
                    baseurl_to_nodeid[base_url] = int(node_id)
                else:
                    skipped += 1
                    continue

            if source_id_i is not None and source_id_i > 0 and node_id is not None:
                mapping[str(source_id_i)] = int(node_id)
            if node_id is not None:
                baseurl_to_nodeid[base_url] = int(node_id)

    node_features = _restore_node_feature_configs(nodes_list, mapping, baseurl_to_nodeid)

    return {
        "ok": True,
        "added": added,
        "updated": updated,
        "skipped": skipped,
        "mapping": mapping,
        "node_features": node_features,
    }


@router.post("/api/restore/full/start")
async def api_restore_full_start(
    file: UploadFile = File(...),
    user: str = Depends(require_login),
):
    """Start full restore in background and return a job id for polling."""
    _prune_full_restore_jobs()
    try:
        raw, read_err, read_status = await _read_full_restore_upload(file)
    except asyncio.CancelledError as exc:
        msg = _restore_cancel_message(exc, "读取上传文件失败")
        return JSONResponse({"ok": False, "error": msg}, status_code=499)
    if raw is None:
        return JSONResponse({"ok": False, "error": str(read_err or "上传文件无效")}, status_code=int(read_status or 400))

    job_id = uuid.uuid4().hex
    now = time.time()
    with _FULL_RESTORE_LOCK:
        _FULL_RESTORE_JOBS[job_id] = {
            "status": "running",
            "progress": 8,
            "stage": "上传完成，准备恢复",
            "error": "",
            "created_at": now,
            "updated_at": now,
            "steps": _restore_steps_template(),
            "result": {},
        }
    _touch_restore_job(job_id, step_key="upload", step_status="done", step_detail="上传完成")
    _touch_restore_job(job_id, step_key="parse", step_status="running", step_detail="准备解析")

    async def _run() -> None:
        nonlocal raw
        ticker: Optional[asyncio.Task] = None
        upf: Optional[UploadFile] = None
        try:
            ticker = asyncio.create_task(_restore_progress_ticker(job_id))
            upf = UploadFile(filename=str(file.filename or "restore.zip"), file=io.BytesIO(raw))
            # Release original buffer as soon as UploadFile wrapper is prepared.
            raw = b""
            restore_resp = await asyncio.wait_for(
                api_restore_full(file=upf, user=user),
                timeout=float(_FULL_RESTORE_EXEC_TIMEOUT_SEC),
            )
            if isinstance(restore_resp, JSONResponse):
                payload = _parse_json_response_obj(restore_resp)
            elif isinstance(restore_resp, dict):
                payload = dict(restore_resp)
            else:
                payload = {"ok": False, "error": "恢复返回异常"}

            if not bool(payload.get("ok")):
                msg = str(payload.get("error") or "恢复失败")
                pos = _restore_stage_by_progress(int((_restore_job_snapshot(job_id) or {}).get("progress") or 0))
                _touch_restore_job(
                    job_id,
                    status="failed",
                    progress=min(99, int((_restore_job_snapshot(job_id) or {}).get("progress") or 90)),
                    stage=msg,
                    error=msg,
                    result=payload,
                    step_key=pos.get("key"),
                    step_status="failed",
                    step_detail="执行失败",
                )
                return

            for k in ("upload", "parse", "rules", "sites_files", "certs_netmon", "panel_state", "finalize"):
                _touch_restore_job(job_id, step_key=k, step_status="done")
            _touch_restore_job(
                job_id,
                status="done",
                progress=100,
                stage="恢复完成",
                result=payload,
                step_key="finalize",
                step_status="done",
                step_detail="恢复完成",
            )
        except asyncio.TimeoutError:
            pos = _restore_stage_by_progress(int((_restore_job_snapshot(job_id) or {}).get("progress") or 95))
            timeout_sec = int(max(120, round(float(_FULL_RESTORE_EXEC_TIMEOUT_SEC))))
            msg = (
                f"恢复执行超时（>{timeout_sec} 秒），已终止。"
                "请检查目标节点连通性与站点文件接口后重试。"
            )
            _touch_restore_job(
                job_id,
                status="failed",
                progress=99,
                stage="恢复超时",
                error=msg,
                step_key=pos.get("key"),
                step_status="failed",
                step_detail="执行超时",
            )
        except asyncio.CancelledError as exc:
            pos = _restore_stage_by_progress(int((_restore_job_snapshot(job_id) or {}).get("progress") or 0))
            _touch_restore_job(
                job_id,
                status="failed",
                progress=min(99, int((_restore_job_snapshot(job_id) or {}).get("progress") or 90)),
                stage="恢复已取消",
                error=_restore_cancel_message(exc, "恢复任务被取消"),
                step_key=pos.get("key"),
                step_status="failed",
                step_detail="任务取消",
            )
        except Exception as exc:
            pos = _restore_stage_by_progress(int((_restore_job_snapshot(job_id) or {}).get("progress") or 0))
            _touch_restore_job(
                job_id,
                status="failed",
                progress=min(99, int((_restore_job_snapshot(job_id) or {}).get("progress") or 90)),
                stage="恢复失败",
                error=str(exc),
                step_key=pos.get("key"),
                step_status="failed",
                step_detail="执行异常",
            )
        finally:
            if ticker:
                ticker.cancel()
                try:
                    await ticker
                except BaseException:
                    pass
            if upf:
                try:
                    await upf.close()
                except Exception:
                    pass
            raw = b""

    try:
        spawn_background_task(_run(), label="restore-job")
    except Exception as exc:
        _touch_restore_job(
            job_id,
            status="failed",
            progress=100,
            stage="恢复失败",
            error=f"任务调度失败：{exc}",
            step_key="finalize",
            step_status="failed",
            step_detail="任务调度失败",
        )
        return JSONResponse({"ok": False, "error": f"创建恢复任务失败：{exc}"}, status_code=500)
    snap = _restore_job_snapshot(job_id)
    if not snap:
        return JSONResponse({"ok": False, "error": "创建恢复任务失败"}, status_code=500)
    return {"ok": True, **snap}


@router.get("/api/restore/full/progress")
async def api_restore_full_progress(job_id: str = "", user: str = Depends(require_login)):
    _prune_full_restore_jobs()
    jid = str(job_id or "").strip()
    if not jid:
        return JSONResponse({"ok": False, "error": "缺少 job_id"}, status_code=400)
    snap = _restore_job_snapshot(jid)
    if not snap:
        return JSONResponse({"ok": False, "error": "恢复任务不存在或已过期"}, status_code=404)
    return {"ok": True, **snap}


@router.post("/api/restore/full")
async def api_restore_full(
    file: UploadFile = File(...),
    user: str = Depends(require_login),
):
    """Restore nodes list + per-node rules from full backup zip."""
    try:
        raw, read_err, read_status = await _read_full_restore_upload(file)
    except asyncio.CancelledError as exc:
        msg = _restore_cancel_message(exc, "读取上传文件失败")
        return JSONResponse({"ok": False, "error": msg}, status_code=499)
    if raw is None:
        return JSONResponse({"ok": False, "error": str(read_err or "上传文件无效")}, status_code=int(read_status or 400))

    try:
        z = zipfile.ZipFile(io.BytesIO(raw))
    except Exception as exc:
        return JSONResponse({"ok": False, "error": f"压缩包解析失败：{exc}"}, status_code=400)
    zip_names = z.namelist()

    def _zip_norm_path(raw_path: Any) -> str:
        p = str(raw_path or "").replace("\\", "/").strip()
        while p.startswith("./"):
            p = p[2:]
        return p.lstrip("/").lower()

    zip_table: Dict[str, str] = {}
    zip_index_rows: List[Tuple[str, str]] = []
    for _raw_name in zip_names:
        _norm_name = _zip_norm_path(_raw_name)
        if not _norm_name:
            continue
        if _norm_name not in zip_table:
            zip_table[_norm_name] = _raw_name
        zip_index_rows.append((_norm_name, _raw_name))

    def _find_zip_path(*candidates: str) -> Optional[str]:
        for c in candidates:
            cand_norm = _zip_norm_path(c)
            if not cand_norm:
                continue
            hit = zip_table.get(cand_norm)
            if hit:
                return hit
            suffix = f"/{cand_norm}"
            fallback_hits: List[Tuple[int, int, str]] = []
            for row_norm, row_raw in zip_index_rows:
                if row_norm.endswith(suffix):
                    fallback_hits.append((row_norm.count("/"), len(row_norm), row_raw))
            if fallback_hits:
                fallback_hits.sort(key=lambda x: (x[0], x[1]))
                return fallback_hits[0][2]
        return None

    # ---- read nodes.json ----
    nodes_payload = None
    nodes_name = _find_zip_path("nodes.json")
    if not nodes_name:
        return JSONResponse({"ok": False, "error": "压缩包中未找到 nodes.json"}, status_code=400)

    try:
        nodes_payload = json.loads(z.read(nodes_name).decode("utf-8"))
    except Exception as exc:
        return JSONResponse({"ok": False, "error": f"nodes.json 解析失败：{exc}"}, status_code=400)

    # Accept: {nodes:[...]} or plain list
    nodes_list = None
    if isinstance(nodes_payload, dict) and isinstance(nodes_payload.get("nodes"), list):
        nodes_list = nodes_payload.get("nodes")
    elif isinstance(nodes_payload, list):
        nodes_list = nodes_payload

    if not isinstance(nodes_list, list):
        return JSONResponse({"ok": False, "error": "备份内容缺少 nodes 列表"}, status_code=400)

    # Optional: restore group orders (UI sorting)
    try:
        go = nodes_payload.get("group_orders") if isinstance(nodes_payload, dict) else None
        items: List[Dict[str, Any]] = []
        if isinstance(go, dict):
            items = [{"group_name": k, "sort_order": v} for k, v in go.items()]
        elif isinstance(go, list):
            items = [x for x in go if isinstance(x, dict)]
        for it in items:
            gname = str(it.get("group_name") or it.get("name") or "").strip() or "默认分组"
            try:
                s = int(it.get("sort_order", it.get("order", 1000)))
            except Exception:
                continue
            upsert_group_order(gname, s)
    except Exception:
        pass

    # ---- restore nodes ----
    added = 0
    updated = 0
    skipped = 0
    mapping: Dict[str, int] = {}
    srcid_to_baseurl: Dict[str, str] = {}
    baseurl_to_nodeid: Dict[str, int] = {}

    for item in nodes_list:
        if not isinstance(item, dict):
            skipped += 1
            continue
        name = (item.get("name") or "").strip()
        base_url = (item.get("base_url") or "").strip().rstrip("/")
        api_key = (item.get("api_key") or "").strip()
        verify_tls = bool(item.get("verify_tls", False))
        is_private = bool(item.get("is_private", False))
        role = str(item.get("role") or "normal").strip().lower() or "normal"
        if role not in ("normal", "website"):
            role = "normal"
        capabilities = item.get("capabilities") if isinstance(item.get("capabilities"), dict) else {}
        website_root_base = str(item.get("website_root_base") or "").strip()
        group_name = item.get("group_name") or "默认分组"
        group_name = str(group_name).strip() or "默认分组"
        system_type = normalize_node_system_type(item.get("system_type"), default="auto")
        source_id = item.get("source_id")
        try:
            source_id_i = int(source_id) if source_id is not None else None
        except Exception:
            source_id_i = None

        if base_url and source_id_i is not None and source_id_i > 0:
            srcid_to_baseurl[str(source_id_i)] = base_url

        if not base_url or not api_key:
            skipped += 1
            continue

        existing = None
        if source_id_i is not None and source_id_i > 0:
            existing = get_node(source_id_i)
        if not existing:
            existing = get_node_by_api_key(api_key) or get_node_by_base_url(base_url)
        if existing:
            update_node_basic(
                existing["id"],
                name or existing.get("name") or extract_ip_for_display(base_url),
                base_url,
                api_key,
                verify_tls=verify_tls,
                is_private=is_private,
                group_name=group_name,
                role=role,
                capabilities=capabilities,
                website_root_base=website_root_base,
                system_type=system_type,
            )
            updated += 1
            node_id = int(existing["id"])
        else:
            node_name = name or extract_ip_for_display(base_url)
            preferred_id = source_id_i if source_id_i is not None and source_id_i > 0 else None
            try:
                node_id = int(
                    add_node(
                        node_name,
                        base_url,
                        api_key,
                        verify_tls=verify_tls,
                        is_private=is_private,
                        group_name=group_name,
                        role=role,
                        capabilities=capabilities,
                        website_root_base=website_root_base,
                        preferred_id=preferred_id,
                        system_type=system_type,
                    )
                )
                added += 1
            except Exception:
                fallback = None
                if preferred_id:
                    fallback = get_node(preferred_id)
                if not fallback:
                    fallback = get_node_by_api_key(api_key) or get_node_by_base_url(base_url)
                if fallback:
                    update_node_basic(
                        fallback["id"],
                        node_name,
                        base_url,
                        api_key,
                        verify_tls=verify_tls,
                        is_private=is_private,
                        group_name=group_name,
                        role=role,
                        capabilities=capabilities,
                        website_root_base=website_root_base,
                        system_type=system_type,
                    )
                    updated += 1
                    node_id = int(fallback["id"])
                else:
                    skipped += 1
                    continue

        baseurl_to_nodeid[base_url] = node_id
        if source_id_i is not None and source_id_i > 0:
            mapping[str(source_id_i)] = node_id

    node_features = _restore_node_feature_configs(nodes_list, mapping, baseurl_to_nodeid)

    # ---- restore rules (batch) ----
    rule_paths: List[str] = []
    for n in zip_names:
        rule_key = _zip_norm_path(n)
        if not rule_key or not rule_key.endswith(".json"):
            continue
        if rule_key.startswith("rules/") or "/rules/" in rule_key:
            rule_paths.append(n)

    import re as _re

    async def apply_pool_to_node(target_id: int, pool: Dict[str, Any]) -> Dict[str, Any]:
        node = get_node(int(target_id))
        if not node:
            raise RuntimeError("节点不存在")

        # store desired on panel
        desired_ver, _ = set_desired_pool(int(target_id), pool)

        # best-effort immediate apply
        applied = False
        try:
            target_base_url, target_verify_tls, _target_route = node_agent_request_target(node)
            data = await agent_post(
                target_base_url,
                node["api_key"],
                "/api/v1/pool",
                {"pool": pool},
                target_verify_tls,
            )
            if isinstance(data, dict) and data.get("ok", True):
                await agent_post(target_base_url, node["api_key"], "/api/v1/apply", {}, target_verify_tls)
                applied = True
        except Exception:
            applied = False

        return {"node_id": int(target_id), "desired_version": desired_ver, "applied": applied}

    sem = asyncio.Semaphore(6)

    async def guarded_apply(target_id: int, pool: Dict[str, Any]) -> Dict[str, Any]:
        async with sem:
            return await apply_pool_to_node(target_id, pool)

    total_rules = len(rule_paths)
    restored_rules = 0
    failed_rules = 0
    unmatched_rules = 0
    rule_failed: List[Dict[str, Any]] = []
    rule_unmatched: List[Dict[str, Any]] = []

    tasks = []
    task_meta = []

    for p in rule_paths:
        try:
            payload = json.loads(z.read(p).decode("utf-8"))
        except Exception as exc:
            failed_rules += 1
            rule_failed.append({"path": p, "error": f"JSON 解析失败：{exc}"})
            continue

        pool = payload.get("pool") if isinstance(payload, dict) else None
        if pool is None:
            pool = payload
        if not isinstance(pool, dict):
            failed_rules += 1
            rule_failed.append({"path": p, "error": "备份内容缺少 pool 数据"})
            continue

        sanitize_pool(pool)

        # resolve source_id / base_url
        node_meta = payload.get("node") if isinstance(payload, dict) else None
        source_id = None
        base_url = None
        if isinstance(node_meta, dict):
            try:
                if node_meta.get("id") is not None:
                    source_id = int(node_meta.get("id"))
            except Exception:
                source_id = None
            base_url = (node_meta.get("base_url") or "").strip().rstrip("/") or None

        if source_id is None:
            m = _re.search(r"id(\d+)\.json$", p)
            if m:
                try:
                    source_id = int(m.group(1))
                except Exception:
                    source_id = None

        if base_url is None and source_id is not None:
            base_url = srcid_to_baseurl.get(str(source_id))

        target_id = None
        if source_id is not None:
            target_id = mapping.get(str(source_id))
        if target_id is None and base_url:
            target_id = baseurl_to_nodeid.get(base_url)
        if target_id is None and base_url:
            ex = get_node_by_base_url(base_url)
            if ex:
                target_id = int(ex.get("id"))

        if target_id is None:
            unmatched_rules += 1
            rule_unmatched.append(
                {"path": p, "source_id": source_id, "base_url": base_url, "error": "未找到对应节点"}
            )
            continue

        tasks.append(guarded_apply(int(target_id), pool))
        task_meta.append({"path": p, "target_id": int(target_id), "source_id": source_id, "base_url": base_url})

    if tasks:
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for meta, res in zip(task_meta, results):
            if isinstance(res, Exception):
                failed_rules += 1
                rule_failed.append({"path": meta.get("path"), "target_id": meta.get("target_id"), "error": str(res)})
            else:
                restored_rules += 1

    def _as_int(v: Any, default: int = 0) -> int:
        try:
            return int(v)
        except Exception:
            return int(default)

    def _as_bool(v: Any, default: bool = False) -> bool:
        if v is None:
            return bool(default)
        if isinstance(v, bool):
            return v
        s = str(v).strip().lower()
        if s in ("1", "true", "yes", "y", "on"):
            return True
        if s in ("0", "false", "no", "n", "off"):
            return False
        return bool(v)

    def _norm_domains(val: Any) -> List[str]:
        if not isinstance(val, list):
            return []
        out: List[str] = []
        seen = set()
        for x in val:
            d = str(x or "").strip().lower().strip(".")
            if not d or d in seen:
                continue
            seen.add(d)
            out.append(d)
        return out

    def _primary_domain(domains: List[str]) -> str:
        for d in domains or []:
            dd = str(d or "").strip().lower()
            if dd:
                return dd
        return ""

    def _resolve_node_id(source_id: Optional[int], base_url: Optional[str]) -> Optional[int]:
        if source_id is not None:
            hit = mapping.get(str(source_id))
            if hit:
                return int(hit)
        bu = str(base_url or "").strip().rstrip("/")
        if bu:
            hit2 = baseurl_to_nodeid.get(bu)
            if hit2:
                return int(hit2)
            ex = get_node_by_base_url(bu)
            if ex:
                return int(ex.get("id") or 0)
        if source_id is not None:
            b2 = srcid_to_baseurl.get(str(source_id))
            if b2:
                hit3 = baseurl_to_nodeid.get(str(b2).rstrip("/"))
                if hit3:
                    return int(hit3)
        return None

    # ---- restore websites (site config) ----
    site_added = 0
    site_updated = 0
    site_skipped = 0
    site_mapping: Dict[str, int] = {}
    site_unmatched: List[Dict[str, Any]] = []

    site_primary_index: Dict[tuple[int, str], int] = {}
    try:
        for s in list_sites():
            nid = _as_int(s.get("node_id"), 0)
            sid = _as_int(s.get("id"), 0)
            pd = _primary_domain(_norm_domains(s.get("domains") or []))
            if nid > 0 and sid > 0 and pd:
                site_primary_index[(nid, pd)] = sid
    except Exception:
        site_primary_index = {}

    sites_path = _find_zip_path("websites/sites.json")
    if sites_path:
        try:
            sites_payload = json.loads(z.read(sites_path).decode("utf-8"))
            site_items = (
                sites_payload.get("sites")
                if isinstance(sites_payload, dict) and isinstance(sites_payload.get("sites"), list)
                else (sites_payload if isinstance(sites_payload, list) else [])
            )
        except Exception as exc:
            site_items = []
            site_unmatched.append({"path": sites_path, "error": f"sites.json 解析失败：{exc}"})

        for item in site_items:
            if not isinstance(item, dict):
                site_skipped += 1
                continue

            source_site_id_raw = item.get("source_id")
            source_site_id = _as_int(source_site_id_raw, 0) if source_site_id_raw is not None else None

            source_node_id_raw = item.get("node_source_id")
            source_node_id = _as_int(source_node_id_raw, 0) if source_node_id_raw is not None else None
            node_base_url = str(item.get("node_base_url") or "").strip().rstrip("/")
            target_node_id = _resolve_node_id(source_node_id, node_base_url)
            if not target_node_id:
                site_skipped += 1
                site_unmatched.append(
                    {
                        "source_site_id": source_site_id,
                        "source_node_id": source_node_id,
                        "node_base_url": node_base_url,
                        "error": "站点未匹配到节点",
                    }
                )
                continue

            domains = _norm_domains(item.get("domains"))
            primary = _primary_domain(domains)
            key = (int(target_node_id), primary) if primary else None

            site_name = str(item.get("name") or "").strip() or (domains[0] if domains else f"site-{int(target_node_id)}")
            site_type = str(item.get("type") or "static").strip().lower() or "static"
            if site_type not in ("static", "php", "reverse_proxy"):
                site_type = "static"
            web_server = str(item.get("web_server") or "nginx").strip() or "nginx"
            root_path = str(item.get("root_path") or "").strip()
            proxy_target = str(item.get("proxy_target") or "").strip()
            nginx_tpl = str(item.get("nginx_tpl") or "")
            https_redirect = _as_bool(item.get("https_redirect"), False)
            gzip_enabled = _as_bool(item.get("gzip_enabled"), True)
            status = str(item.get("status") or "running").strip() or "running"

            site_id = 0
            if key and key in site_primary_index:
                site_id = int(site_primary_index[key] or 0)

            if site_id > 0:
                update_site(
                    site_id,
                    name=site_name,
                    domains=domains,
                    root_path=root_path,
                    proxy_target=proxy_target,
                    site_type=site_type,
                    web_server=web_server,
                    nginx_tpl=nginx_tpl,
                    https_redirect=https_redirect,
                    gzip_enabled=gzip_enabled,
                    status=status,
                )
                site_updated += 1
            else:
                site_id = int(
                    add_site(
                        node_id=int(target_node_id),
                        name=site_name,
                        domains=domains,
                        root_path=root_path,
                        proxy_target=proxy_target,
                        site_type=site_type,
                        web_server=web_server,
                        nginx_tpl=nginx_tpl,
                        https_redirect=https_redirect,
                        gzip_enabled=gzip_enabled,
                        status=status,
                    )
                )
                site_added += 1

            update_site_health(
                site_id,
                str(item.get("health_status") or "").strip(),
                health_code=_as_int(item.get("health_code"), 0),
                health_latency_ms=_as_int(item.get("health_latency_ms"), 0),
                health_error=str(item.get("health_error") or "").strip(),
                health_checked_at=item.get("health_checked_at"),
            )

            if key:
                site_primary_index[key] = int(site_id)
            if source_site_id is not None:
                site_mapping[str(source_site_id)] = int(site_id)

    # ---- restore website files ----
    site_file_restored = 0
    site_file_failed = 0
    site_file_skipped = 0
    site_file_unmatched = 0
    site_dir_restored = 0
    site_dir_failed = 0
    site_dir_skipped = 0
    site_dir_unmatched = 0
    site_file_bytes = 0
    site_file_failed_items: List[Dict[str, Any]] = []

    files_manifest_path = _find_zip_path("websites/files_manifest.json")
    if files_manifest_path:
        try:
            files_manifest = json.loads(z.read(files_manifest_path).decode("utf-8"))
            site_file_items = (
                files_manifest.get("sites")
                if isinstance(files_manifest, dict) and isinstance(files_manifest.get("sites"), list)
                else (files_manifest if isinstance(files_manifest, list) else [])
            )
        except Exception as exc:
            site_file_items = []
            site_file_failed_items.append({"path": files_manifest_path, "error": f"files_manifest 解析失败：{exc}"})

        current_sites: Dict[int, Dict[str, Any]] = {}
        try:
            for s in list_sites():
                sid = _as_int(s.get("id"), 0)
                if sid > 0:
                    current_sites[sid] = s
        except Exception:
            current_sites = {}

        async def _upload_site_file_bytes(
            node: Dict[str, Any],
            root_path: str,
            rel_path: str,
            raw: bytes,
        ) -> None:
            clean_rel = _clean_site_rel_path(rel_path)
            if not clean_rel:
                raise RuntimeError("非法文件路径")
            if "/" in clean_rel:
                dir_path, filename = clean_rel.rsplit("/", 1)
            else:
                dir_path, filename = "", clean_rel
            filename = filename.strip()
            if not filename:
                raise RuntimeError("文件名为空")
            root_base = str(node.get("website_root_base") or "").strip()
            upload_id = uuid.uuid4().hex
            target_base_url, target_verify_tls, _target_route = node_agent_request_target(node)
            if not raw:
                payload_empty = {
                    "root": root_path,
                    "path": dir_path,
                    "filename": filename,
                    "upload_id": upload_id,
                    "offset": 0,
                    "done": True,
                    "allow_empty": True,
                    "root_base": root_base,
                }
                resp_empty = await agent_post(
                    target_base_url,
                    node["api_key"],
                    "/api/v1/website/files/upload_chunk",
                    payload_empty,
                    target_verify_tls,
                    timeout=20,
                )
                if not resp_empty.get("ok", True):
                    raise RuntimeError(str(resp_empty.get("error") or "空文件上传失败"))
                return

            chunk_size = 512 * 1024
            offset = 0
            total = len(raw)
            while offset < total:
                chunk = raw[offset : offset + chunk_size]
                done = (offset + len(chunk)) >= total
                payload_chunk = {
                    "root": root_path,
                    "path": dir_path,
                    "filename": filename,
                    "upload_id": upload_id,
                    "offset": offset,
                    "done": done,
                    "content_b64": base64.b64encode(chunk).decode("ascii"),
                    "chunk_sha256": hashlib.sha256(chunk).hexdigest(),
                    "root_base": root_base,
                }
                resp_chunk = await agent_post(
                    target_base_url,
                    node["api_key"],
                    "/api/v1/website/files/upload_chunk",
                    payload_chunk,
                    target_verify_tls,
                    timeout=45,
                )
                if not resp_chunk.get("ok", True):
                    raise RuntimeError(str(resp_chunk.get("error") or "文件上传失败"))
                offset += len(chunk)

        async def _ensure_site_dir(
            node: Dict[str, Any],
            root_path: str,
            rel_dir: str,
        ) -> None:
            clean_rel = _clean_site_rel_path(rel_dir)
            if not clean_rel:
                raise RuntimeError("非法目录路径")
            if "/" in clean_rel:
                parent_path, dirname = clean_rel.rsplit("/", 1)
            else:
                parent_path, dirname = "", clean_rel
            dirname = dirname.strip()
            if not dirname:
                raise RuntimeError("目录名为空")
            payload_dir = {
                "root": root_path,
                "path": parent_path,
                "name": dirname,
                "root_base": str(node.get("website_root_base") or "").strip(),
            }
            target_base_url, target_verify_tls, _target_route = node_agent_request_target(node)
            resp_dir = await agent_post(
                target_base_url,
                node["api_key"],
                "/api/v1/website/files/mkdir",
                payload_dir,
                target_verify_tls,
                timeout=20,
            )
            if not resp_dir.get("ok", True):
                raise RuntimeError(str(resp_dir.get("error") or "创建目录失败"))

        file_restore_probe_cache: Dict[Tuple[int, str], Tuple[bool, str]] = {}

        async def _probe_site_file_restore(node: Dict[str, Any], root_path: str) -> Tuple[bool, str]:
            node_id = _as_int(node.get("id"), 0)
            key = (node_id, str(root_path or ""))
            cached = file_restore_probe_cache.get(key)
            if cached is not None:
                return cached

            payload_probe = {
                "root": root_path,
                "path": "",
                "filename": ".nexus-restore-probe",
                "upload_id": f"probe-{uuid.uuid4().hex}",
                "root_base": str(node.get("website_root_base") or "").strip(),
            }
            try:
                target_base_url, target_verify_tls, _target_route = node_agent_request_target(node)
                resp_probe = await agent_post(
                    target_base_url,
                    node["api_key"],
                    "/api/v1/website/files/upload_status",
                    payload_probe,
                    target_verify_tls,
                    timeout=8,
                )
                if not bool(resp_probe.get("ok", False)):
                    msg = str(resp_probe.get("error") or "站点文件接口不可用")
                    file_restore_probe_cache[key] = (False, msg)
                else:
                    file_restore_probe_cache[key] = (True, "")
            except Exception as exc:
                file_restore_probe_cache[key] = (False, str(exc))
            return file_restore_probe_cache[key]

        for sitem in site_file_items:
            if not isinstance(sitem, dict):
                continue
            source_site_id_raw = sitem.get("source_site_id")
            source_site_id = _as_int(source_site_id_raw, 0) if source_site_id_raw is not None else None
            target_site_id = None
            if source_site_id is not None and str(source_site_id) in site_mapping:
                target_site_id = _as_int(site_mapping.get(str(source_site_id)), 0) or None
            if not target_site_id:
                # fallback: if source id happens to exist after restore
                if source_site_id is not None and source_site_id in current_sites:
                    target_site_id = int(source_site_id)

            dirs_arr = sitem.get("dirs")
            dir_items = dirs_arr if isinstance(dirs_arr, list) else []
            files_arr = sitem.get("files")
            file_items = files_arr if isinstance(files_arr, list) else []
            if not target_site_id:
                site_file_unmatched += len(file_items)
                site_dir_unmatched += len(dir_items)
                continue

            site_obj = current_sites.get(int(target_site_id))
            if not site_obj:
                site_obj = next((x for x in list_sites() if _as_int(x.get("id"), 0) == int(target_site_id)), None)
                if site_obj:
                    current_sites[int(target_site_id)] = site_obj
            if not isinstance(site_obj, dict):
                site_file_unmatched += len(file_items)
                site_dir_unmatched += len(dir_items)
                continue

            target_node = get_node(_as_int(site_obj.get("node_id"), 0))
            root_path = str(site_obj.get("root_path") or "").strip()
            if not target_node or not root_path:
                site_file_skipped += len(file_items)
                site_dir_skipped += len(dir_items)
                continue
            probe_ok, probe_err = await _probe_site_file_restore(target_node, root_path)
            if not probe_ok:
                site_file_failed += len(file_items)
                site_dir_failed += len(dir_items)
                site_file_failed_items.append(
                    {
                        "site_id": target_site_id,
                        "path": "/",
                        "error": f"站点文件接口不可达，已跳过该站点文件恢复：{probe_err}",
                    }
                )
                continue

            for ditem in dir_items:
                rel_dir = ""
                if isinstance(ditem, dict):
                    rel_dir = _clean_site_rel_path(ditem.get("path"))
                else:
                    rel_dir = _clean_site_rel_path(ditem)
                if not rel_dir:
                    site_dir_skipped += 1
                    continue
                try:
                    await _ensure_site_dir(target_node, root_path, rel_dir)
                    site_dir_restored += 1
                except Exception as exc:
                    site_dir_failed += 1
                    site_file_failed_items.append(
                        {"site_id": target_site_id, "path": f"{rel_dir}/", "error": f"目录恢复失败：{exc}"}
                    )

            pkg_dir = str(sitem.get("package_dir") or "")
            for fitem in file_items:
                if not isinstance(fitem, dict):
                    site_file_skipped += 1
                    continue
                rel_path = _clean_site_rel_path(fitem.get("path"))
                if not rel_path:
                    site_file_skipped += 1
                    continue
                zip_hint = str(fitem.get("zip_path") or "").strip()
                if not zip_hint:
                    zip_hint = f"websites/files/{pkg_dir}/{rel_path}" if pkg_dir else ""
                if not zip_hint:
                    site_file_failed += 1
                    site_file_failed_items.append(
                        {"site_id": target_site_id, "path": rel_path, "error": "缺少 zip_path"}
                    )
                    continue
                zpath = _find_zip_path(zip_hint)
                if not zpath:
                    site_file_failed += 1
                    site_file_failed_items.append(
                        {"site_id": target_site_id, "path": rel_path, "error": "备份包缺少对应文件"}
                    )
                    continue
                try:
                    raw_bytes = bytes(z.read(zpath))
                    await _upload_site_file_bytes(target_node, root_path, rel_path, raw_bytes)
                    site_file_restored += 1
                    site_file_bytes += len(raw_bytes)
                except Exception as exc:
                    site_file_failed += 1
                    site_file_failed_items.append(
                        {"site_id": target_site_id, "path": rel_path, "error": str(exc)}
                    )

    # ---- restore website certificates ----
    cert_added = 0
    cert_updated = 0
    cert_skipped = 0
    cert_unmatched: List[Dict[str, Any]] = []

    cert_index: Dict[tuple[int, int, str], int] = {}
    try:
        for c in list_certificates():
            nid = _as_int(c.get("node_id"), 0)
            sid = _as_int(c.get("site_id"), 0) if c.get("site_id") is not None else 0
            pd = _primary_domain(_norm_domains(c.get("domains") or []))
            cid = _as_int(c.get("id"), 0)
            if nid > 0 and cid > 0 and pd:
                cert_index[(nid, sid, pd)] = cid
    except Exception:
        cert_index = {}

    certs_path = _find_zip_path("websites/certificates.json")
    if certs_path:
        try:
            certs_payload = json.loads(z.read(certs_path).decode("utf-8"))
            cert_items = (
                certs_payload.get("certificates")
                if isinstance(certs_payload, dict) and isinstance(certs_payload.get("certificates"), list)
                else (certs_payload if isinstance(certs_payload, list) else [])
            )
        except Exception as exc:
            cert_items = []
            cert_unmatched.append({"path": certs_path, "error": f"certificates.json 解析失败：{exc}"})

        for item in cert_items:
            if not isinstance(item, dict):
                cert_skipped += 1
                continue

            source_node_id_raw = item.get("node_source_id")
            source_node_id = _as_int(source_node_id_raw, 0) if source_node_id_raw is not None else None
            node_base_url = str(item.get("node_base_url") or "").strip().rstrip("/")
            target_node_id = _resolve_node_id(source_node_id, node_base_url)
            if not target_node_id:
                cert_skipped += 1
                cert_unmatched.append(
                    {
                        "source_id": item.get("source_id"),
                        "source_node_id": source_node_id,
                        "node_base_url": node_base_url,
                        "error": "证书未匹配到节点",
                    }
                )
                continue

            source_site_id_raw = item.get("site_source_id")
            source_site_id = _as_int(source_site_id_raw, 0) if source_site_id_raw is not None else None
            target_site_id: Optional[int] = None
            if source_site_id is not None and str(source_site_id) in site_mapping:
                target_site_id = _as_int(site_mapping.get(str(source_site_id)), 0) or None

            domains = _norm_domains(item.get("domains"))
            pd = _primary_domain(domains)
            if target_site_id is None and pd:
                sid2 = site_primary_index.get((int(target_node_id), pd))
                if sid2:
                    target_site_id = int(sid2)

            key = (int(target_node_id), int(target_site_id or 0), pd)
            cert_id = cert_index.get(key) if pd else None

            status = str(item.get("status") or "pending").strip() or "pending"
            not_before = item.get("not_before")
            not_after = item.get("not_after")
            renew_at = item.get("renew_at")
            last_error = str(item.get("last_error") or "").strip()

            if cert_id:
                update_certificate(
                    int(cert_id),
                    domains=domains,
                    status=status,
                    not_before=not_before,
                    not_after=not_after,
                    renew_at=renew_at,
                    last_error=last_error,
                )
                cert_updated += 1
            else:
                cert_id = int(
                    add_certificate(
                        node_id=int(target_node_id),
                        site_id=int(target_site_id) if target_site_id is not None else None,
                        domains=domains,
                        issuer=str(item.get("issuer") or "letsencrypt"),
                        challenge=str(item.get("challenge") or "http-01"),
                        status=status,
                        not_before=not_before,
                        not_after=not_after,
                        renew_at=renew_at,
                        last_error=last_error,
                    )
                )
                cert_added += 1

            if pd:
                cert_index[key] = int(cert_id)

    # ---- restore netmon monitor configs ----
    mon_added = 0
    mon_updated = 0
    mon_skipped = 0
    mon_samples_restored = 0
    mon_samples_skipped = 0
    mon_samples_failed = 0
    mon_samples_cleared = 0

    def _monitor_key(target: str, mode: str, tcp_port: int, node_ids: List[int]) -> tuple[str, str, int, tuple[int, ...]]:
        cleaned = sorted(set([int(x) for x in (node_ids or []) if int(x) > 0]))
        return ((target or "").strip().lower(), (mode or "ping").strip().lower(), int(tcp_port or 443), tuple(cleaned))

    monitor_index: Dict[tuple[str, str, int, tuple[int, ...]], int] = {}
    source_monitor_mapping: Dict[str, int] = {}
    try:
        for m in list_netmon_monitors():
            mid = _as_int(m.get("id"), 0)
            if mid <= 0:
                continue
            mk = _monitor_key(
                str(m.get("target") or ""),
                str(m.get("mode") or "ping"),
                _as_int(m.get("tcp_port"), 443),
                [int(x) for x in (m.get("node_ids") or []) if _as_int(x, 0) > 0],
            )
            monitor_index[mk] = mid
    except Exception:
        monitor_index = {}

    monitors_path = _find_zip_path("netmon/monitors.json", "netmon/config.json")
    if monitors_path:
        try:
            monitors_payload = json.loads(z.read(monitors_path).decode("utf-8"))
            monitor_items = (
                monitors_payload.get("monitors")
                if isinstance(monitors_payload, dict) and isinstance(monitors_payload.get("monitors"), list)
                else (monitors_payload if isinstance(monitors_payload, list) else [])
            )
        except Exception:
            monitor_items = []

        for item in monitor_items:
            if not isinstance(item, dict):
                mon_skipped += 1
                continue

            target = str(item.get("target") or "").strip()
            if not target:
                mon_skipped += 1
                continue
            mode = str(item.get("mode") or "ping").strip().lower() or "ping"
            if mode not in ("ping", "tcping"):
                mode = "ping"
            tcp_port = _as_int(item.get("tcp_port"), 443)
            interval_sec = _as_int(item.get("interval_sec"), 5)
            warn_ms = _as_int(item.get("warn_ms"), 0)
            crit_ms = _as_int(item.get("crit_ms"), 0)
            enabled = _as_bool(item.get("enabled"), True)

            src_node_ids_raw = item.get("node_source_ids", item.get("node_ids"))
            src_node_ids = src_node_ids_raw if isinstance(src_node_ids_raw, list) else []
            base_urls_raw = item.get("node_base_urls")
            base_urls = base_urls_raw if isinstance(base_urls_raw, list) else []

            resolved_ids: List[int] = []
            for sid in src_node_ids:
                nid = _resolve_node_id(_as_int(sid, 0), None)
                if nid and nid > 0 and nid not in resolved_ids:
                    resolved_ids.append(int(nid))
            for bu in base_urls:
                nid = _resolve_node_id(None, str(bu or "").strip().rstrip("/"))
                if nid and nid > 0 and nid not in resolved_ids:
                    resolved_ids.append(int(nid))

            if not resolved_ids:
                mon_skipped += 1
                continue

            src_mid = _as_int(item.get("source_id"), 0)
            mk = _monitor_key(target, mode, tcp_port, resolved_ids)
            mid = monitor_index.get(mk)
            if mid:
                update_netmon_monitor(
                    int(mid),
                    target=target,
                    mode=mode,
                    tcp_port=tcp_port,
                    interval_sec=interval_sec,
                    node_ids=resolved_ids,
                    warn_ms=warn_ms,
                    crit_ms=crit_ms,
                    enabled=enabled,
                    last_run_ts_ms=_as_int(item.get("last_run_ts_ms"), 0),
                    last_run_msg=str(item.get("last_run_msg") or ""),
                )
                mon_updated += 1
                target_mid = int(mid)
            else:
                target_mid = int(
                    add_netmon_monitor(
                        target=target,
                        mode=mode,
                        tcp_port=tcp_port,
                        interval_sec=interval_sec,
                        node_ids=resolved_ids,
                        warn_ms=warn_ms,
                        crit_ms=crit_ms,
                        enabled=enabled,
                    )
                )
                monitor_index[mk] = target_mid
                mon_added += 1
            if src_mid > 0:
                source_monitor_mapping[str(src_mid)] = int(target_mid)

    samples_path = _find_zip_path("netmon/samples.json")
    if samples_path:
        sample_items: List[Any] = []
        try:
            samples_payload = json.loads(z.read(samples_path).decode("utf-8"))
            sample_items = (
                samples_payload.get("samples")
                if isinstance(samples_payload, dict) and isinstance(samples_payload.get("samples"), list)
                else (samples_payload if isinstance(samples_payload, list) else [])
            )
        except Exception:
            sample_items = []

        rows_to_insert: List[Tuple[int, int, int, int, Optional[float], Optional[str]]] = []
        clear_monitor_ids: set[int] = set()
        for item in sample_items:
            if not isinstance(item, dict):
                mon_samples_skipped += 1
                continue

            src_mid = _as_int(
                item.get("source_monitor_id", item.get("monitor_source_id", item.get("monitor_id"))),
                0,
            )
            target_mid = source_monitor_mapping.get(str(src_mid)) if src_mid > 0 else None
            if not target_mid:
                mon_samples_skipped += 1
                continue

            src_node_id = _as_int(
                item.get("source_node_id", item.get("node_source_id", item.get("node_id"))),
                0,
            )
            node_base_url = str(item.get("node_base_url") or "").strip().rstrip("/") or None
            target_node_id = _resolve_node_id(src_node_id if src_node_id > 0 else None, node_base_url)
            if not target_node_id:
                mon_samples_skipped += 1
                continue

            ts_ms = _as_int(item.get("ts_ms"), 0)
            if ts_ms <= 0:
                mon_samples_skipped += 1
                continue

            latency_raw = item.get("latency_ms")
            latency_val: Optional[float] = None
            if latency_raw is not None and str(latency_raw).strip() != "":
                try:
                    latency_val = float(latency_raw)
                except Exception:
                    latency_val = None

            err_s = str(item.get("error") or "").strip()
            rows_to_insert.append(
                (
                    int(target_mid),
                    int(target_node_id),
                    int(ts_ms),
                    1 if _as_bool(item.get("ok"), False) else 0,
                    latency_val,
                    err_s or None,
                )
            )
            clear_monitor_ids.add(int(target_mid))

        if clear_monitor_ids:
            mids = sorted(clear_monitor_ids)
            placeholders = ",".join(["?"] * len(mids))
            with connect() as conn:
                conn.execute(f"DELETE FROM netmon_samples WHERE monitor_id IN ({placeholders})", tuple(mids))
                conn.commit()
            mon_samples_cleared = len(mids)

        if rows_to_insert:
            chunk_size = 2000
            for i in range(0, len(rows_to_insert), chunk_size):
                chunk = rows_to_insert[i : i + chunk_size]
                try:
                    mon_samples_restored += int(insert_netmon_samples(chunk))
                except Exception:
                    mon_samples_failed += len(chunk)

    # ---- restore panel state (users/roles/share/favorites/events) ----
    panel_state_result: Dict[str, Any] = {
        "panel_settings": {"added": 0, "updated": 0, "skipped": 0},
        "roles": {"added": 0, "updated": 0, "skipped": 0},
        "users": {"added": 0, "updated": 0, "skipped": 0},
        "user_tokens": {"added": 0, "updated": 0, "skipped": 0},
        "rule_owner_map": {"added": 0, "updated": 0, "skipped": 0},
        "site_file_favorites": {"added": 0, "updated": 0, "skipped": 0},
        "site_file_share_short_links": {"added": 0, "updated": 0, "skipped": 0},
        "site_file_share_revocations": {"added": 0, "updated": 0, "skipped": 0},
        "site_events": {"restored": 0, "skipped": 0},
        "site_checks": {"restored": 0, "skipped": 0},
        "audit_logs": {"restored": 0, "skipped": 0},
        "tasks": {"added": 0, "updated": 0, "skipped": 0},
        "rule_stats_samples": {"restored": 0, "updated": 0, "skipped": 0},
        "errors": [],
    }

    def _norm_str_list(val: Any) -> List[str]:
        if not isinstance(val, list):
            return []
        out: List[str] = []
        seen: set[str] = set()
        for item in val:
            s = str(item or "").strip()
            if not s or s in seen:
                continue
            seen.add(s)
            out.append(s)
        return out

    def _stable_json(val: Any, default_obj: Any) -> str:
        obj = val
        if not isinstance(obj, (dict, list)):
            obj = default_obj
        try:
            return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        except Exception:
            return json.dumps(default_obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))

    remote_profiles_override_json = ""
    remote_profiles_restored = 0
    remote_profiles_skipped = 0
    remote_profiles_source = ""
    remote_profiles_path = _find_zip_path("remote_storage/profiles.json")
    if remote_profiles_path:
        remote_profiles_source = str(remote_profiles_path or "")
        try:
            remote_profiles_payload = json.loads(z.read(remote_profiles_path).decode("utf-8"))
            if isinstance(remote_profiles_payload, dict):
                remote_profiles_items = (
                    remote_profiles_payload.get("profiles")
                    if isinstance(remote_profiles_payload.get("profiles"), list)
                    else []
                )
            elif isinstance(remote_profiles_payload, list):
                remote_profiles_items = remote_profiles_payload
            else:
                remote_profiles_items = []
            normalized_profiles, invalid_remote_profiles = _normalize_remote_profiles_list(remote_profiles_items)
            remote_profiles_override_json = json.dumps(normalized_profiles, ensure_ascii=False, separators=(",", ":"))
            remote_profiles_restored = len(normalized_profiles)
            remote_profiles_skipped = int(invalid_remote_profiles)
            if invalid_remote_profiles > 0:
                panel_state_result["errors"].append(
                    f"remote_storage/profiles.json 含 {int(invalid_remote_profiles)} 条非法条目，已跳过"
                )
        except Exception as exc:
            panel_state_result["errors"].append(f"remote_storage/profiles.json 解析失败：{exc}")

    existing_settings = list_panel_settings()
    panel_state_payload: Dict[str, Any] = {}
    panel_state_path = _find_zip_path("panel/state.json")
    if panel_state_path:
        try:
            panel_state_payload = json.loads(z.read(panel_state_path).decode("utf-8"))
            if not isinstance(panel_state_payload, dict):
                panel_state_payload = {}
        except Exception as exc:
            panel_state_payload = {}
            panel_state_result["errors"].append(f"panel/state.json 解析失败：{exc}")

        settings_items = panel_state_payload.get("panel_settings")
        if not isinstance(settings_items, list):
            settings_items = []
        for item in settings_items:
            if not isinstance(item, dict):
                panel_state_result["panel_settings"]["skipped"] += 1
                continue
            key_s = str(item.get("key") or "").strip()
            if not key_s:
                panel_state_result["panel_settings"]["skipped"] += 1
                continue
            if key_s == "remote_storage_profiles" and remote_profiles_override_json:
                continue
            existed = key_s in existing_settings
            try:
                set_panel_setting(key_s, str(item.get("value") or ""))
                if existed:
                    panel_state_result["panel_settings"]["updated"] += 1
                else:
                    panel_state_result["panel_settings"]["added"] += 1
                existing_settings[key_s] = str(item.get("value") or "")
            except Exception as exc:
                panel_state_result["panel_settings"]["skipped"] += 1
                panel_state_result["errors"].append(f"面板设置恢复失败[{key_s}]：{exc}")

    if remote_profiles_override_json:
        existed = "remote_storage_profiles" in existing_settings
        try:
            set_panel_setting("remote_storage_profiles", remote_profiles_override_json)
            if existed:
                panel_state_result["panel_settings"]["updated"] += 1
            else:
                panel_state_result["panel_settings"]["added"] += 1
            existing_settings["remote_storage_profiles"] = remote_profiles_override_json
        except Exception as exc:
            panel_state_result["panel_settings"]["skipped"] += 1
            panel_state_result["errors"].append(f"远程存储配置恢复失败[remote_storage_profiles]：{exc}")

    role_source_to_target: Dict[str, int] = {}
    role_name_to_target: Dict[str, int] = {}
    user_source_to_target: Dict[str, int] = {}
    username_to_target: Dict[str, int] = {}

    for role in list_roles():
        rid = _as_int(role.get("id"), 0)
        rname = str(role.get("name") or "").strip()
        if rid > 0 and rname:
            role_name_to_target[rname] = rid

    role_items = panel_state_payload.get("roles")
    if not isinstance(role_items, list):
        role_items = []
    for item in role_items:
        if not isinstance(item, dict):
            panel_state_result["roles"]["skipped"] += 1
            continue
        role_name = str(item.get("name") or "").strip()
        if not role_name:
            panel_state_result["roles"]["skipped"] += 1
            continue
        existed = role_name in role_name_to_target
        try:
            rid = int(
                upsert_role(
                    role_name,
                    permissions=_norm_str_list(item.get("permissions")),
                    description=str(item.get("description") or ""),
                    builtin=bool(item.get("builtin") or False),
                )
            )
        except Exception as exc:
            panel_state_result["roles"]["skipped"] += 1
            panel_state_result["errors"].append(f"角色恢复失败[{role_name}]：{exc}")
            continue
        role_name_to_target[role_name] = rid
        src_rid = item.get("source_id")
        if src_rid is not None:
            role_source_to_target[str(_as_int(src_rid, 0))] = rid
        if existed:
            panel_state_result["roles"]["updated"] += 1
        else:
            panel_state_result["roles"]["added"] += 1

    with connect() as conn:
        existing_users = conn.execute(
            "SELECT id, username FROM users ORDER BY id ASC"
        ).fetchall()
        for row in existing_users:
            d = dict(row)
            uid = _as_int(d.get("id"), 0)
            uname = str(d.get("username") or "").strip()
            if uid > 0 and uname:
                username_to_target[uname] = uid

    user_items = panel_state_payload.get("users")
    if not isinstance(user_items, list):
        user_items = []
    for item in user_items:
        if not isinstance(item, dict):
            panel_state_result["users"]["skipped"] += 1
            continue
        username = str(item.get("username") or "").strip()
        if not username:
            panel_state_result["users"]["skipped"] += 1
            continue

        target_role_id = 0
        src_role_id = item.get("source_role_id")
        if src_role_id is not None:
            target_role_id = _as_int(role_source_to_target.get(str(_as_int(src_role_id, 0))), 0)
        if target_role_id <= 0:
            role_name = str(item.get("role_name") or "").strip()
            if role_name:
                target_role_id = _as_int(role_name_to_target.get(role_name), 0)
        if target_role_id <= 0:
            fallback_role = get_role_by_name("viewer") or get_role_by_name("owner")
            target_role_id = _as_int((fallback_role or {}).get("id"), 0)
        if target_role_id <= 0:
            panel_state_result["users"]["skipped"] += 1
            panel_state_result["errors"].append(f"用户恢复失败[{username}]：缺少可用角色")
            continue

        policy = item.get("policy") if isinstance(item.get("policy"), dict) else {}
        salt_b64 = str(item.get("salt_b64") or "").strip()
        hash_b64 = str(item.get("hash_b64") or "").strip()
        iterations = max(1, _as_int(item.get("iterations"), 120000))
        enabled = _as_bool(item.get("enabled"), True)
        expires_at = str(item.get("expires_at") or "").strip() or None

        existing_uid = _as_int(username_to_target.get(username), 0)
        try:
            if existing_uid > 0:
                update_user_record(
                    existing_uid,
                    username=username,
                    salt_b64=salt_b64 if salt_b64 else None,
                    hash_b64=hash_b64 if hash_b64 else None,
                    iterations=iterations if (salt_b64 and hash_b64) else None,
                    role_id=target_role_id,
                    enabled=enabled,
                    expires_at=expires_at,
                    policy=policy,
                )
                target_uid = existing_uid
                panel_state_result["users"]["updated"] += 1
            else:
                if not salt_b64 or not hash_b64:
                    panel_state_result["users"]["skipped"] += 1
                    panel_state_result["errors"].append(f"用户恢复失败[{username}]：缺少密码哈希")
                    continue
                target_uid = int(
                    create_user_record(
                        username=username,
                        salt_b64=salt_b64,
                        hash_b64=hash_b64,
                        iterations=iterations,
                        role_id=target_role_id,
                        enabled=enabled,
                        expires_at=expires_at,
                        policy=policy,
                        created_by=str(item.get("created_by") or ""),
                    )
                )
                panel_state_result["users"]["added"] += 1
            username_to_target[username] = target_uid
        except Exception as exc:
            panel_state_result["users"]["skipped"] += 1
            panel_state_result["errors"].append(f"用户恢复失败[{username}]：{exc}")
            continue

        src_uid = item.get("source_id")
        if src_uid is not None:
            user_source_to_target[str(_as_int(src_uid, 0))] = int(target_uid)

    token_items = panel_state_payload.get("user_tokens")
    if not isinstance(token_items, list):
        token_items = []
    with connect() as conn:
        for item in token_items:
            if not isinstance(item, dict):
                panel_state_result["user_tokens"]["skipped"] += 1
                continue
            token_sha256 = str(item.get("token_sha256") or "").strip().lower()
            if not token_sha256:
                panel_state_result["user_tokens"]["skipped"] += 1
                continue
            target_uid = 0
            src_user_id = item.get("source_user_id")
            if src_user_id is not None:
                target_uid = _as_int(user_source_to_target.get(str(_as_int(src_user_id, 0))), 0)
            if target_uid <= 0:
                target_uid = _as_int(username_to_target.get(str(item.get("source_username") or "").strip()), 0)
            if target_uid <= 0:
                panel_state_result["user_tokens"]["skipped"] += 1
                continue
            scopes = _norm_str_list(item.get("scopes"))
            scopes_json = json.dumps(scopes, ensure_ascii=False)
            exists = conn.execute(
                "SELECT id FROM user_tokens WHERE token_sha256=? LIMIT 1",
                (token_sha256,),
            ).fetchone()
            if exists:
                conn.execute(
                    "UPDATE user_tokens SET user_id=?, name=?, scopes_json=?, expires_at=?, last_used_at=?, created_by=?, created_at=COALESCE(?, created_at), revoked_at=? "
                    "WHERE id=?",
                    (
                        int(target_uid),
                        str(item.get("name") or ""),
                        scopes_json,
                        str(item.get("expires_at") or "").strip() or None,
                        str(item.get("last_used_at") or "").strip() or None,
                        str(item.get("created_by") or ""),
                        str(item.get("created_at") or "").strip() or None,
                        str(item.get("revoked_at") or "").strip() or None,
                        int(exists["id"]),
                    ),
                )
                panel_state_result["user_tokens"]["updated"] += 1
            else:
                conn.execute(
                    "INSERT INTO user_tokens("
                    "user_id, token_sha256, name, scopes_json, expires_at, last_used_at, created_by, created_at, revoked_at"
                    ") VALUES(?,?,?,?,?,?,?,?,?)",
                    (
                        int(target_uid),
                        token_sha256,
                        str(item.get("name") or ""),
                        scopes_json,
                        str(item.get("expires_at") or "").strip() or None,
                        str(item.get("last_used_at") or "").strip() or None,
                        str(item.get("created_by") or ""),
                        str(item.get("created_at") or "").strip() or None,
                        str(item.get("revoked_at") or "").strip() or None,
                    ),
                )
                panel_state_result["user_tokens"]["added"] += 1
        conn.commit()

    owner_items = panel_state_payload.get("rule_owner_map")
    if not isinstance(owner_items, list):
        owner_items = []
    with connect() as conn:
        for item in owner_items:
            if not isinstance(item, dict):
                panel_state_result["rule_owner_map"]["skipped"] += 1
                continue
            source_node_id = _as_int(item.get("source_node_id"), 0)
            target_node_id = _resolve_node_id(source_node_id if source_node_id > 0 else None, None)
            rule_key = str(item.get("rule_key") or "").strip()
            if not target_node_id or not rule_key:
                panel_state_result["rule_owner_map"]["skipped"] += 1
                continue
            owner_uid = 0
            src_owner_uid = item.get("owner_source_user_id")
            if src_owner_uid is not None:
                owner_uid = _as_int(user_source_to_target.get(str(_as_int(src_owner_uid, 0))), 0)
            owner_username = str(item.get("owner_username") or "").strip()
            if owner_uid <= 0 and owner_username:
                owner_uid = _as_int(username_to_target.get(owner_username), 0)
            active = 1 if _as_bool(item.get("active"), True) else 0
            first_seen_at = str(item.get("first_seen_at") or "").strip() or None
            last_seen_at = str(item.get("last_seen_at") or "").strip() or None
            exists = conn.execute(
                "SELECT id FROM rule_owner_map WHERE node_id=? AND rule_key=? LIMIT 1",
                (int(target_node_id), rule_key),
            ).fetchone()
            if exists:
                conn.execute(
                    "UPDATE rule_owner_map SET owner_user_id=?, owner_username=?, first_seen_at=COALESCE(?, first_seen_at), "
                    "last_seen_at=COALESCE(?, last_seen_at), active=? WHERE id=?",
                    (
                        int(owner_uid),
                        owner_username,
                        first_seen_at,
                        last_seen_at,
                        int(active),
                        int(exists["id"]),
                    ),
                )
                panel_state_result["rule_owner_map"]["updated"] += 1
            else:
                conn.execute(
                    "INSERT INTO rule_owner_map("
                    "node_id, rule_key, owner_user_id, owner_username, first_seen_at, last_seen_at, active"
                    ") VALUES(?,?,?,?,COALESCE(?, datetime('now')),COALESCE(?, datetime('now')),?)",
                    (
                        int(target_node_id),
                        rule_key,
                        int(owner_uid),
                        owner_username,
                        first_seen_at,
                        last_seen_at,
                        int(active),
                    ),
                )
                panel_state_result["rule_owner_map"]["added"] += 1
        conn.commit()

    current_site_ids: Dict[int, int] = {}
    try:
        for s in list_sites():
            sid = _as_int(s.get("id"), 0)
            if sid > 0:
                current_site_ids[sid] = sid
    except Exception:
        current_site_ids = {}

    def _resolve_site_id(source_site_id: Any) -> Optional[int]:
        sid = _as_int(source_site_id, 0)
        if sid <= 0:
            return None
        if str(sid) in site_mapping:
            return _as_int(site_mapping.get(str(sid)), 0) or None
        if sid in current_site_ids:
            return sid
        return None

    fav_items = panel_state_payload.get("site_file_favorites")
    if not isinstance(fav_items, list):
        fav_items = []
    favorite_existing: set[tuple[int, str, str]] = set()
    with connect() as conn:
        fav_rows = conn.execute(
            "SELECT site_id, owner, path FROM site_file_favorites"
        ).fetchall()
        for row in fav_rows:
            d = dict(row)
            sid = _as_int(d.get("site_id"), 0)
            owner = str(d.get("owner") or "").strip()
            path = str(d.get("path") or "").strip()
            if sid > 0 and owner and path:
                favorite_existing.add((sid, owner, path))
    for item in fav_items:
        if not isinstance(item, dict):
            panel_state_result["site_file_favorites"]["skipped"] += 1
            continue
        target_site_id = _resolve_site_id(item.get("source_site_id"))
        owner = str(item.get("owner") or "").strip()
        path = str(item.get("path") or "").strip()
        if not target_site_id or not owner or not path:
            panel_state_result["site_file_favorites"]["skipped"] += 1
            continue
        existed = (int(target_site_id), owner, path) in favorite_existing
        try:
            upsert_site_file_favorite(
                int(target_site_id),
                owner=owner,
                path=path,
                is_dir=_as_bool(item.get("is_dir"), False),
            )
            favorite_existing.add((int(target_site_id), owner, path))
            if existed:
                panel_state_result["site_file_favorites"]["updated"] += 1
            else:
                panel_state_result["site_file_favorites"]["added"] += 1
        except Exception as exc:
            panel_state_result["site_file_favorites"]["skipped"] += 1
            panel_state_result["errors"].append(f"文件收藏恢复失败[{target_site_id}:{path}]：{exc}")

    rev_items = panel_state_payload.get("site_file_share_revocations")
    if not isinstance(rev_items, list):
        rev_items = []
    with connect() as conn:
        for item in rev_items:
            if not isinstance(item, dict):
                panel_state_result["site_file_share_revocations"]["skipped"] += 1
                continue
            target_site_id = _resolve_site_id(item.get("source_site_id"))
            digest = str(item.get("token_sha256") or "").strip().lower()
            if not target_site_id or not digest:
                panel_state_result["site_file_share_revocations"]["skipped"] += 1
                continue
            exists = conn.execute(
                "SELECT id FROM site_file_share_revocations WHERE site_id=? AND token_sha256=? LIMIT 1",
                (int(target_site_id), digest),
            ).fetchone()
            if exists:
                conn.execute(
                    "UPDATE site_file_share_revocations SET revoked_by=?, reason=?, revoked_at=COALESCE(?, revoked_at) WHERE id=?",
                    (
                        str(item.get("revoked_by") or ""),
                        str(item.get("reason") or ""),
                        str(item.get("revoked_at") or "").strip() or None,
                        int(exists["id"]),
                    ),
                )
                panel_state_result["site_file_share_revocations"]["updated"] += 1
            else:
                conn.execute(
                    "INSERT INTO site_file_share_revocations(site_id, token_sha256, revoked_by, reason, revoked_at) "
                    "VALUES(?,?,?,?,COALESCE(?, datetime('now')))",
                    (
                        int(target_site_id),
                        digest,
                        str(item.get("revoked_by") or ""),
                        str(item.get("reason") or ""),
                        str(item.get("revoked_at") or "").strip() or None,
                    ),
                )
                panel_state_result["site_file_share_revocations"]["added"] += 1
        conn.commit()

    share_items = panel_state_payload.get("site_file_share_short_links")
    if not isinstance(share_items, list):
        share_items = []
    with connect() as conn:
        for item in share_items:
            if not isinstance(item, dict):
                panel_state_result["site_file_share_short_links"]["skipped"] += 1
                continue
            code = str(item.get("code") or "").strip()
            token = str(item.get("token") or "").strip()
            digest = str(item.get("token_sha256") or "").strip().lower()
            if token and (not digest):
                digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
            target_site_id = _resolve_site_id(item.get("source_site_id"))
            if not code or not target_site_id or not token or not digest:
                panel_state_result["site_file_share_short_links"]["skipped"] += 1
                continue
            exists = conn.execute(
                "SELECT code FROM site_file_share_short_links WHERE code=? LIMIT 1",
                (code,),
            ).fetchone()
            if exists:
                conn.execute(
                    "UPDATE site_file_share_short_links SET site_id=?, token=?, token_sha256=?, created_by=?, created_at=COALESCE(?, created_at) "
                    "WHERE code=?",
                    (
                        int(target_site_id),
                        token,
                        digest,
                        str(item.get("created_by") or ""),
                        str(item.get("created_at") or "").strip() or None,
                        code,
                    ),
                )
                panel_state_result["site_file_share_short_links"]["updated"] += 1
            else:
                conn.execute(
                    "INSERT INTO site_file_share_short_links(code, site_id, token, token_sha256, created_by, created_at) "
                    "VALUES(?,?,?,?,?,COALESCE(?, datetime('now')))",
                    (
                        code,
                        int(target_site_id),
                        token,
                        digest,
                        str(item.get("created_by") or ""),
                        str(item.get("created_at") or "").strip() or None,
                    ),
                )
                panel_state_result["site_file_share_short_links"]["added"] += 1
        conn.commit()

    event_items = panel_state_payload.get("site_events")
    if not isinstance(event_items, list):
        event_items = []
    with connect() as conn:
        for item in event_items:
            if not isinstance(item, dict):
                panel_state_result["site_events"]["skipped"] += 1
                continue
            target_site_id = _resolve_site_id(item.get("source_site_id"))
            if not target_site_id:
                panel_state_result["site_events"]["skipped"] += 1
                continue
            payload_obj = item.get("payload") if isinstance(item.get("payload"), dict) else {}
            result_obj = item.get("result") if isinstance(item.get("result"), dict) else {}
            conn.execute(
                "INSERT INTO site_events(site_id, action, status, actor, payload_json, result_json, error, created_at) "
                "VALUES(?,?,?,?,?,?,?,COALESCE(?, datetime('now')))",
                (
                    int(target_site_id),
                    str(item.get("action") or ""),
                    str(item.get("status") or "success"),
                    str(item.get("actor") or ""),
                    json.dumps(payload_obj, ensure_ascii=False),
                    json.dumps(result_obj, ensure_ascii=False),
                    str(item.get("error") or ""),
                    str(item.get("created_at") or "").strip() or None,
                ),
            )
            panel_state_result["site_events"]["restored"] += 1
        conn.commit()

    check_items = panel_state_payload.get("site_checks")
    if not isinstance(check_items, list):
        check_items = []
    with connect() as conn:
        for item in check_items:
            if not isinstance(item, dict):
                panel_state_result["site_checks"]["skipped"] += 1
                continue
            target_site_id = _resolve_site_id(item.get("source_site_id"))
            if not target_site_id:
                panel_state_result["site_checks"]["skipped"] += 1
                continue
            conn.execute(
                "INSERT INTO site_checks(site_id, ok, status_code, latency_ms, error, checked_at) "
                "VALUES(?,?,?,?,?,COALESCE(?, datetime('now')))",
                (
                    int(target_site_id),
                    1 if _as_bool(item.get("ok"), False) else 0,
                    _as_int(item.get("status_code"), 0),
                    _as_int(item.get("latency_ms"), 0),
                    str(item.get("error") or ""),
                    str(item.get("checked_at") or "").strip() or None,
                ),
            )
            panel_state_result["site_checks"]["restored"] += 1
        conn.commit()

    audit_items = panel_state_payload.get("audit_logs")
    if not isinstance(audit_items, list):
        audit_items = []
    with connect() as conn:
        for item in audit_items:
            if not isinstance(item, dict):
                panel_state_result["audit_logs"]["skipped"] += 1
                continue
            src_node_id = _as_int(item.get("source_node_id"), 0)
            node_base_url = str(item.get("node_base_url") or "").strip().rstrip("/") or None
            target_node_id = 0
            if src_node_id > 0 or node_base_url:
                hit_node = _resolve_node_id(src_node_id if src_node_id > 0 else None, node_base_url)
                if not hit_node:
                    panel_state_result["audit_logs"]["skipped"] += 1
                    continue
                target_node_id = int(hit_node)

            actor = str(item.get("actor") or "")
            action = str(item.get("action") or "")
            node_name = str(item.get("node_name") or "")
            source_ip = str(item.get("source_ip") or "")
            created_at_raw = str(item.get("created_at") or "").strip()
            created_at = created_at_raw or None
            created_key = created_at_raw
            detail_json = _stable_json(item.get("detail"), {})

            exists = conn.execute(
                "SELECT id FROM audit_logs "
                "WHERE actor=? AND action=? AND node_id=? AND node_name=? AND source_ip=? AND detail_json=? AND COALESCE(created_at, '')=? "
                "LIMIT 1",
                (
                    actor,
                    action,
                    int(target_node_id),
                    node_name,
                    source_ip,
                    detail_json,
                    created_key,
                ),
            ).fetchone()
            if exists:
                panel_state_result["audit_logs"]["skipped"] += 1
                continue
            conn.execute(
                "INSERT INTO audit_logs(actor, action, node_id, node_name, source_ip, detail_json, created_at) "
                "VALUES(?,?,?,?,?,?,COALESCE(?, datetime('now')))",
                (
                    actor,
                    action,
                    int(target_node_id),
                    node_name,
                    source_ip,
                    detail_json,
                    created_at,
                ),
            )
            panel_state_result["audit_logs"]["restored"] += 1
        conn.commit()

    task_items = panel_state_payload.get("tasks")
    if not isinstance(task_items, list):
        task_items = []
    with connect() as conn:
        for item in task_items:
            if not isinstance(item, dict):
                panel_state_result["tasks"]["skipped"] += 1
                continue
            src_node_id = _as_int(item.get("source_node_id"), 0)
            node_base_url = str(item.get("node_base_url") or "").strip().rstrip("/") or None
            target_node_id = _resolve_node_id(src_node_id if src_node_id > 0 else None, node_base_url)
            if not target_node_id:
                panel_state_result["tasks"]["skipped"] += 1
                continue

            task_type = str(item.get("type") or "").strip()
            if not task_type:
                panel_state_result["tasks"]["skipped"] += 1
                continue
            payload_json = _stable_json(item.get("payload"), {})
            result_json = _stable_json(item.get("result"), {})
            status = str(item.get("status") or "queued").strip() or "queued"
            progress = _as_int(item.get("progress"), 0)
            if progress < 0:
                progress = 0
            if progress > 100:
                progress = 100
            err = str(item.get("error") or "")
            created_at_raw = str(item.get("created_at") or "").strip()
            created_at = created_at_raw or None
            created_key = created_at_raw
            updated_at = str(item.get("updated_at") or "").strip() or None

            exists = conn.execute(
                "SELECT id FROM tasks WHERE node_id=? AND type=? AND payload_json=? AND COALESCE(created_at, '')=? LIMIT 1",
                (
                    int(target_node_id),
                    task_type,
                    payload_json,
                    created_key,
                ),
            ).fetchone()
            if exists:
                conn.execute(
                    "UPDATE tasks SET status=?, progress=?, result_json=?, error=?, updated_at=COALESCE(?, updated_at) WHERE id=?",
                    (
                        status,
                        int(progress),
                        result_json,
                        err,
                        updated_at,
                        int(exists["id"]),
                    ),
                )
                panel_state_result["tasks"]["updated"] += 1
            else:
                conn.execute(
                    "INSERT INTO tasks(node_id, type, payload_json, status, progress, result_json, error, created_at, updated_at) "
                    "VALUES(?,?,?,?,?,?,?,COALESCE(?, datetime('now')),COALESCE(?, datetime('now')))",
                    (
                        int(target_node_id),
                        task_type,
                        payload_json,
                        status,
                        int(progress),
                        result_json,
                        err,
                        created_at,
                        updated_at,
                    ),
                )
                panel_state_result["tasks"]["added"] += 1
        conn.commit()

    stat_items = panel_state_payload.get("rule_stats_samples")
    if not isinstance(stat_items, list):
        stat_items = []
    with connect() as conn:
        for item in stat_items:
            if not isinstance(item, dict):
                panel_state_result["rule_stats_samples"]["skipped"] += 1
                continue
            src_node_id = _as_int(item.get("source_node_id"), 0)
            node_base_url = str(item.get("node_base_url") or "").strip().rstrip("/") or None
            target_node_id = _resolve_node_id(src_node_id if src_node_id > 0 else None, node_base_url)
            if not target_node_id:
                panel_state_result["rule_stats_samples"]["skipped"] += 1
                continue
            rule_key = str(item.get("rule_key") or "").strip()
            ts_ms = _as_int(item.get("ts_ms"), 0)
            if not rule_key or ts_ms <= 0:
                panel_state_result["rule_stats_samples"]["skipped"] += 1
                continue
            rx_bytes = max(0, _as_int(item.get("rx_bytes"), 0))
            tx_bytes = max(0, _as_int(item.get("tx_bytes"), 0))
            conn_active = max(0, _as_int(item.get("connections_active"), 0))
            conn_total = max(0, _as_int(item.get("connections_total"), 0))

            cur = conn.execute(
                "INSERT OR IGNORE INTO rule_stats_samples("
                "node_id, rule_key, ts_ms, rx_bytes, tx_bytes, connections_active, connections_total"
                ") VALUES(?,?,?,?,?,?,?)",
                (
                    int(target_node_id),
                    rule_key,
                    int(ts_ms),
                    int(rx_bytes),
                    int(tx_bytes),
                    int(conn_active),
                    int(conn_total),
                ),
            )
            if int(cur.rowcount or 0) > 0:
                panel_state_result["rule_stats_samples"]["restored"] += 1
            else:
                conn.execute(
                    "UPDATE rule_stats_samples SET rx_bytes=?, tx_bytes=?, connections_active=?, connections_total=? "
                    "WHERE node_id=? AND rule_key=? AND ts_ms=?",
                    (
                        int(rx_bytes),
                        int(tx_bytes),
                        int(conn_active),
                        int(conn_total),
                        int(target_node_id),
                        rule_key,
                        int(ts_ms),
                    ),
                )
                panel_state_result["rule_stats_samples"]["updated"] += 1
        conn.commit()

    return {
        "ok": True,
        "nodes": {
            "added": added,
            "updated": updated,
            "skipped": skipped,
            "mapping": mapping,
            "node_features": node_features,
        },
        "rules": {
            "total": total_rules,
            "restored": restored_rules,
            "unmatched": unmatched_rules,
            "failed": failed_rules,
        },
        "sites": {
            "added": site_added,
            "updated": site_updated,
            "skipped": site_skipped,
            "mapped": len(site_mapping),
        },
        "site_files": {
            "restored": site_file_restored,
            "failed": site_file_failed,
            "skipped": site_file_skipped,
            "unmatched": site_file_unmatched,
            "dirs_restored": site_dir_restored,
            "dirs_failed": site_dir_failed,
            "dirs_skipped": site_dir_skipped,
            "dirs_unmatched": site_dir_unmatched,
            "bytes": site_file_bytes,
        },
        "certificates": {
            "added": cert_added,
            "updated": cert_updated,
            "skipped": cert_skipped,
        },
        "netmon": {
            "added": mon_added,
            "updated": mon_updated,
            "skipped": mon_skipped,
            "samples_restored": mon_samples_restored,
            "samples_skipped": mon_samples_skipped,
            "samples_failed": mon_samples_failed,
            "sample_monitors_cleared": mon_samples_cleared,
        },
        "panel_state": {
            "panel_settings": panel_state_result["panel_settings"],
            "roles": panel_state_result["roles"],
            "users": panel_state_result["users"],
            "user_tokens": panel_state_result["user_tokens"],
            "rule_owner_map": panel_state_result["rule_owner_map"],
            "site_file_favorites": panel_state_result["site_file_favorites"],
            "site_file_share_short_links": panel_state_result["site_file_share_short_links"],
            "site_file_share_revocations": panel_state_result["site_file_share_revocations"],
            "site_events": panel_state_result["site_events"],
            "site_checks": panel_state_result["site_checks"],
            "audit_logs": panel_state_result["audit_logs"],
            "tasks": panel_state_result["tasks"],
            "rule_stats_samples": panel_state_result["rule_stats_samples"],
        },
        "remote_storage_profiles": {
            "source": remote_profiles_source,
            "restored": int(remote_profiles_restored),
            "skipped": int(remote_profiles_skipped),
        },
        "site_unmatched": site_unmatched[:50],
        "site_file_failed": site_file_failed_items[:50],
        "cert_unmatched": cert_unmatched[:50],
        "rule_unmatched": rule_unmatched[:50],
        "rule_failed": rule_failed[:50],
        "panel_state_errors": (panel_state_result.get("errors") or [])[:50],
    }


@router.post("/api/nodes/{node_id}/restore")
async def api_restore(
    request: Request,
    node_id: int,
    file: UploadFile = File(...),
    user: str = Depends(require_login),
):
    node = get_node(node_id)
    if not node:
        return JSONResponse({"ok": False, "error": "节点不存在"}, status_code=404)
    try:
        await file.seek(0)
    except Exception:
        pass
    total = 0
    buf = bytearray()
    try:
        while True:
            chunk = await file.read(_RESTORE_UPLOAD_CHUNK_SIZE)
            if not chunk:
                break
            total += len(chunk)
            if total > _RULE_RESTORE_MAX_BYTES:
                return JSONResponse(
                    {
                        "ok": False,
                        "error": f"上传文件过大（当前限制 {_format_bytes(_RULE_RESTORE_MAX_BYTES)}）",
                    },
                    status_code=413,
                )
            buf.extend(chunk)
        raw = bytes(buf)
        if not raw:
            return JSONResponse({"ok": False, "error": "上传文件为空"}, status_code=400)
        payload = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        return JSONResponse({"ok": False, "error": f"备份文件解析失败：{exc}"}, status_code=400)

    pool = payload.get("pool") if isinstance(payload, dict) else None
    if pool is None:
        pool = payload
    if not isinstance(pool, dict):
        return JSONResponse({"ok": False, "error": "备份内容缺少 pool 数据"}, status_code=400)

    sanitize_pool(pool)
    try:
        job = _enqueue_pool_job(
            node_id=int(node_id),
            kind="rule_restore",
            payload={"pool": pool},
            user=user,
            meta={
                "action": "rule_restore",
                "filename": str(file.filename or ""),
                "upload_bytes": int(total),
            },
        )
    except Exception as exc:
        return JSONResponse({"ok": False, "error": f"创建恢复任务失败：{exc}"}, status_code=500)
    _audit_log_node_action(
        action="rule.restore_async_enqueue",
        user=user,
        node_id=int(node_id),
        node_name=str(node.get("name") or ""),
        detail={
            "job_id": str(job.get("job_id") or ""),
            "filename": str(file.filename or ""),
            "upload_bytes": int(total),
        },
        request=request,
    )
    return {"ok": True, "job": job, "queued": True}


def _append_precheck_issue(
    issues: List[PoolValidationIssue],
    seen: set[str],
    issue: PoolValidationIssue,
    limit: int,
) -> None:
    key = f"{issue.path}|{issue.code}|{issue.severity}|{issue.message}"
    if key in seen:
        return
    if len(issues) >= limit:
        return
    seen.add(key)
    issues.append(issue)


def _safe_error_text(data: Any, default: str = "unknown") -> str:
    if isinstance(data, dict):
        msg = str(data.get("error") or "").strip()
        return msg or default
    msg = str(data or "").strip()
    return msg or default


def _trace_route_target(raw_target: Any) -> str:
    s = str(raw_target or "").strip()
    if len(s) > 256:
        s = s[:256].strip()
    return s


def _trace_route_max_hops(raw_hops: Any) -> int:
    try:
        v = int(raw_hops) if raw_hops is not None else 20
    except Exception:
        v = 20
    if v < 3:
        v = 3
    if v > 64:
        v = 64
    return v


def _trace_route_timeout(raw_timeout: Any) -> float:
    try:
        v = float(raw_timeout) if raw_timeout is not None else 1.0
    except Exception:
        v = 1.0
    if v < 0.3:
        v = 0.3
    if v > 5.0:
        v = 5.0
    return float(v)


def _trace_route_probes(raw_probes: Any) -> int:
    try:
        v = int(raw_probes) if raw_probes is not None else 3
    except Exception:
        v = 3
    if v < 1:
        v = 1
    if v > 5:
        v = 5
    return int(v)


async def _run_pool_save_precheck(node: Dict[str, Any], pool: Dict[str, Any]) -> Dict[str, Any]:
    """Save-time runtime precheck via agent /api/v1/netprobe (mode=rules)."""
    out_issues: List[PoolValidationIssue] = []
    seen: set[str] = set()
    precheck_enabled = _save_precheck_enabled()
    probe_timeout = _save_precheck_probe_timeout()
    http_timeout = _save_precheck_http_timeout()
    issues_limit = _save_precheck_max_issues()

    eps = pool.get("endpoints") if isinstance(pool.get("endpoints"), list) else []
    if not isinstance(eps, list) or not eps:
        return {
            "ok": True,
            "issues": out_issues,
            "summary": {"enabled": precheck_enabled, "rules_total": 0, "issues": 0, "source": "save_precheck"},
        }

    if not precheck_enabled:
        return {
            "ok": True,
            "issues": out_issues,
            "summary": {"enabled": False, "rules_total": len(eps), "issues": 0, "source": "save_precheck"},
        }

    rules_payload: List[Dict[str, Any]] = []
    for ep in eps[:160]:
        if not isinstance(ep, dict):
            continue
        item: Dict[str, Any] = {
            "id": str(ep.get("id") or ""),
            "listen": str(ep.get("listen") or ""),
            "protocol": str(ep.get("protocol") or ""),
            "disabled": bool(ep.get("disabled")),
            "remote": ep.get("remote"),
            "remotes": ep.get("remotes") if isinstance(ep.get("remotes"), list) else [],
            "extra_remotes": ep.get("extra_remotes") if isinstance(ep.get("extra_remotes"), list) else [],
        }
        if ep.get("listen_transport") is not None:
            item["listen_transport"] = ep.get("listen_transport")
        if ep.get("remote_transport") is not None:
            item["remote_transport"] = ep.get("remote_transport")
        ex = ep.get("extra_config")
        if isinstance(ex, dict):
            item["extra_config"] = ex
        rules_payload.append(item)

    body = {"mode": "rules", "rules": rules_payload, "timeout": probe_timeout}
    try:
        target_base_url, target_verify_tls, _target_route = node_agent_request_target(node)
        data = await agent_post(
            target_base_url,
            node.get("api_key", ""),
            "/api/v1/netprobe",
            body,
            target_verify_tls,
            timeout=http_timeout,
        )
    except Exception as exc:
        _append_precheck_issue(
            out_issues,
            seen,
            PoolValidationIssue(
                path="endpoints",
                message=f"预检失败：无法连接 Agent 执行规则探测（{exc}）",
                severity="warning",
                code="precheck_unreachable",
            ),
            issues_limit,
        )
        return {
            "ok": False,
            "issues": out_issues,
            "summary": {
                "enabled": True,
                "rules_total": len(rules_payload),
                "issues": len(out_issues),
                "source": "agent_netprobe_rules",
                "error": "agent_unreachable",
            },
        }

    if not isinstance(data, dict) or data.get("ok") is not True:
        _append_precheck_issue(
            out_issues,
            seen,
            PoolValidationIssue(
                path="endpoints",
                message=f"预检失败：Agent rules 探测返回异常（{_safe_error_text(data)}）",
                severity="warning",
                code="precheck_failed",
            ),
            issues_limit,
        )
        return {
            "ok": False,
            "issues": out_issues,
            "summary": {
                "enabled": True,
                "rules_total": len(rules_payload),
                "issues": len(out_issues),
                "source": "agent_netprobe_rules",
                "error": "probe_failed",
            },
        }

    # deps
    deps = data.get("deps") if isinstance(data.get("deps"), dict) else {}
    if isinstance(deps, dict):
        if deps.get("sysctl") is False:
            _append_precheck_issue(
                out_issues,
                seen,
                PoolValidationIssue(
                    path="endpoints",
                    message="依赖提示：节点缺少 sysctl 命令，性能优化提示可能不完整",
                    severity="warning",
                    code="dependency_missing",
                ),
                issues_limit,
            )
        if deps.get("ss") is False:
            _append_precheck_issue(
                out_issues,
                seen,
                PoolValidationIssue(
                    path="endpoints",
                    message="依赖提示：节点缺少 ss 命令，端口占用检查可能不完整",
                    severity="warning",
                    code="dependency_missing",
                ),
                issues_limit,
            )

    # perf hints
    perf_hints = data.get("perf_hints") if isinstance(data.get("perf_hints"), list) else []
    for hint in perf_hints[:8]:
        msg = str(hint or "").strip()
        if not msg:
            continue
        _append_precheck_issue(
            out_issues,
            seen,
            PoolValidationIssue(path="endpoints", message=f"性能风险提示：{msg}", severity="warning", code="sysctl_tuning_recommended"),
            issues_limit,
        )

    # per-rule warnings / unreachable
    rules = data.get("rules") if isinstance(data.get("rules"), list) else []
    for r in rules[:200]:
        if not isinstance(r, dict):
            continue
        try:
            idx = int(r.get("idx"))
        except Exception:
            idx = -1
        nth = idx + 1 if idx >= 0 else 0
        path = f"endpoints[{idx}]" if idx >= 0 else "endpoints"

        unreach = r.get("unreachable") if isinstance(r.get("unreachable"), list) else []
        if unreach:
            targets = [str(x).strip() for x in unreach if str(x).strip()]
            if targets:
                show = ", ".join(targets[:3])
                if len(targets) > 3:
                    show += f" 等 {len(targets)} 个"
                prefix = f"第 {nth} 条规则" if nth > 0 else "规则"
                _append_precheck_issue(
                    out_issues,
                    seen,
                    PoolValidationIssue(
                        path=path,
                        message=f"{prefix}目标不可达：{show}",
                        severity="warning",
                        code="target_unreachable",
                    ),
                    issues_limit,
                )

        warns = r.get("warnings") if isinstance(r.get("warnings"), list) else []
        for w in warns[:6]:
            msg = str(w or "").strip()
            if not msg:
                continue
            prefix = f"第 {nth} 条规则预检提示：" if nth > 0 else "规则预检提示："
            _append_precheck_issue(
                out_issues,
                seen,
                PoolValidationIssue(path=path, message=f"{prefix}{msg}", severity="warning", code="runtime_warning"),
                issues_limit,
            )

    summary = data.get("summary") if isinstance(data.get("summary"), dict) else {}
    return {
        "ok": True,
        "issues": out_issues,
        "summary": {
            "enabled": True,
            "source": "agent_netprobe_rules",
            "rules_total": int(summary.get("rules_total") or len(rules_payload)),
            "targets_total": int(summary.get("targets_total") or 0),
            "rules_unreachable": int(summary.get("rules_unreachable") or 0),
            "targets_unreachable": int(summary.get("targets_unreachable") or 0),
            "issues": len(out_issues),
        },
    }


@router.post("/api/nodes/{node_id}/pool")
async def api_pool_set(request: Request, node_id: int, payload: Dict[str, Any], user: str = Depends(require_login)):
    node = get_node(node_id)
    if not node:
        return JSONResponse({"ok": False, "error": "节点不存在"}, status_code=404)

    pool = payload.get("pool") if isinstance(payload, dict) else None
    if pool is None and isinstance(payload, dict):
        # some callers may post the pool dict directly
        pool = payload
    if not isinstance(pool, dict):
        return JSONResponse({"ok": False, "error": "请求缺少 pool 字段"}, status_code=400)
    is_async_job = bool(isinstance(payload, dict) and payload.get("_async_job") is True)

    unlock_sync_ids: set[str] = set()
    if isinstance(payload, dict):
        raw_unlock = payload.get("unlock_sync_ids")
        if isinstance(raw_unlock, list):
            for x in raw_unlock[:256]:
                sid = str(x or "").strip()
                if sid:
                    unlock_sync_ids.add(sid)

    sanitize_pool(pool)
    existing_pool: Dict[str, Any]
    try:
        existing_pool = await load_pool_for_node(node)
    except Exception:
        existing_pool = {}
    existing_pool = _normalize_pool_dict(existing_pool)
    pool = _merge_submitted_pool_for_user(user, existing_pool, pool)
    sanitize_pool(pool)

    # Prevent editing/deleting synced receiver rules from UI
    try:
        locked: Dict[str, Any] = {}
        for ep in existing_pool.get("endpoints") or []:
            if not isinstance(ep, dict):
                continue
            ex0 = ep.get("extra_config") or {}
            if not isinstance(ex0, dict):
                ex0 = {}
            sid = ex0.get("sync_id")
            if sid and (
                ex0.get("sync_lock") is True
                or ex0.get("sync_role") == "receiver"
                or (
                    (not _is_relay_sync_rule(ex0))
                    and (ex0.get("intranet_lock") is True or ex0.get("intranet_role") == "client")
                )
            ):
                locked[str(sid)] = ep

        if locked:
            posted: Dict[str, Any] = {}
            for ep in pool.get("endpoints") or []:
                if not isinstance(ep, dict):
                    continue
                ex0 = ep.get("extra_config") or {}
                if not isinstance(ex0, dict):
                    ex0 = {}
                sid = ex0.get("sync_id")
                if sid:
                    posted[str(sid)] = ep

            def _canon(e: Dict[str, Any]) -> Dict[str, Any]:
                ex_raw = e.get("extra_config")
                ex = dict(ex_raw) if isinstance(ex_raw, dict) else {}
                ex.pop("last_sync_at", None)
                ex.pop("sync_updated_at", None)
                ex.pop("intranet_updated_at", None)
                return {
                    "listen": e.get("listen"),
                    "remotes": e.get("remotes") or [],
                    "disabled": bool(e.get("disabled", False)),
                    "balance": e.get("balance"),
                    "protocol": e.get("protocol"),
                    "extra_config": ex,
                }

            for sid, old_ep in locked.items():
                if str(sid) in unlock_sync_ids:
                    # 临时解锁：允许本次请求修改/删除该同步规则
                    continue
                new_ep = posted.get(sid)
                if not new_ep:
                    return JSONResponse(
                        {"ok": False, "error": "该节点存在由发送机同步的锁定规则，无法手动删除/修改（请在发送机上操作）"},
                        status_code=403,
                    )
                if _canon(old_ep) != _canon(new_ep):
                    return JSONResponse(
                        {"ok": False, "error": "该节点存在由发送机同步的锁定规则，无法手动删除/修改（请在发送机上操作）"},
                        status_code=403,
                    )
    except Exception:
        pass

    # Save-time validation: format/conflict errors + static warnings
    static_warnings: List[PoolValidationIssue] = []
    try:
        static_warnings = validate_pool_inplace(pool)
    except PoolValidationError as exc:
        return JSONResponse({"ok": False, "error": str(exc), "issues": [i.__dict__ for i in exc.issues]}, status_code=400)
    except Exception as exc:
        return JSONResponse({"ok": False, "error": f"保存失败：规则校验异常（{exc}）"}, status_code=500)

    runtime_precheck: Dict[str, Any]
    # Async jobs should return quickly; runtime netprobe is kept for sync path only.
    skip_runtime_precheck = bool(is_async_job)
    save_precheck_enabled = _save_precheck_enabled()
    save_precheck_issues_limit = _save_precheck_max_issues()
    if save_precheck_enabled and (not skip_runtime_precheck):
        try:
            runtime_precheck = await _run_pool_save_precheck(node, pool)
        except Exception as exc:
            runtime_precheck = {
                "issues": [
                    PoolValidationIssue(
                        path="endpoints",
                        message=f"预检失败：保存前探测发生异常（{exc}）",
                        severity="warning",
                        code="precheck_exception",
                    )
                ],
                "summary": {"enabled": True, "source": "save_precheck", "error": "exception"},
            }
    elif skip_runtime_precheck:
        runtime_precheck = {
            "issues": [],
            "summary": {"enabled": False, "source": "save_precheck_skipped_async", "skipped": True},
        }
    else:
        runtime_precheck = {
            "issues": [],
            "summary": {"enabled": False, "source": "save_precheck_disabled"},
        }
    precheck_issues: List[PoolValidationIssue] = []
    precheck_seen: set[str] = set()
    for i in static_warnings:
        _append_precheck_issue(precheck_issues, precheck_seen, i, save_precheck_issues_limit)
    for i in (runtime_precheck.get("issues") or []):
        if isinstance(i, PoolValidationIssue):
            _append_precheck_issue(precheck_issues, precheck_seen, i, save_precheck_issues_limit)

    try:
        upsert_rule_owner_map(node_id=node_id, pool=pool)
    except Exception:
        # Ownership map is best-effort; do not block save path.
        pass

    # Store desired pool on panel. Agent will pull it on next report.
    try:
        desired_ver, _ = set_desired_pool(node_id, pool)
    except Exception as exc:
        return JSONResponse({"ok": False, "error": f"保存失败：写入面板配置时异常（{exc}）"}, status_code=500)

    # Apply in background: do not block HTTP response
    try:
        schedule_apply_pool(node, pool)
    except Exception as exc:
        return JSONResponse({"ok": False, "error": f"保存失败：下发任务创建失败（{exc}）"}, status_code=500)

    audit_detail = _pool_change_summary(existing_pool, pool)
    audit_detail.update(
        {
            "desired_version": int(desired_ver),
            "queued": True,
            "precheck_issues": int(len(precheck_issues)),
            "async_job": bool(is_async_job),
        }
    )
    if int(audit_detail.get("created_rules") or 0) > 0 and int(audit_detail.get("deleted_rules") or 0) == 0:
        audit_action = "rule.create"
    elif int(audit_detail.get("deleted_rules") or 0) > 0 and int(audit_detail.get("created_rules") or 0) == 0:
        audit_action = "rule.delete"
    elif int(audit_detail.get("created_rules") or 0) > 0 and int(audit_detail.get("deleted_rules") or 0) > 0:
        audit_action = "rule.batch_change"
    else:
        audit_action = "pool.save"
    _audit_log_node_action(
        action=audit_action,
        user=user,
        node_id=int(node_id),
        node_name=str(node.get("name") or ""),
        detail=audit_detail,
        request=request,
    )

    return {
        "ok": True,
        "pool": _filter_pool_for_user(user, pool),
        "desired_version": desired_ver,
        "queued": True,
        "note": "waiting agent report",
        "precheck": {
            "issues": [i.__dict__ for i in precheck_issues],
            "summary": runtime_precheck.get("summary") if isinstance(runtime_precheck.get("summary"), dict) else {},
        },
    }


@router.post("/api/nodes/{node_id}/pool_async")
async def api_pool_set_async(request: Request, node_id: int, payload: Dict[str, Any], user: str = Depends(require_login)):
    node = get_node(node_id)
    if not node:
        return JSONResponse({"ok": False, "error": "节点不存在"}, status_code=404)
    if not isinstance(payload, dict):
        return JSONResponse({"ok": False, "error": "payload 无效"}, status_code=400)

    pool = payload.get("pool")
    if pool is None:
        pool = payload
    if not isinstance(pool, dict):
        return JSONResponse({"ok": False, "error": "请求缺少 pool 字段"}, status_code=400)

    unlock_ids: List[str] = []
    raw_unlock = payload.get("unlock_sync_ids")
    if isinstance(raw_unlock, list):
        for x in raw_unlock[:256]:
            sid = str(x or "").strip()
            if sid:
                unlock_ids.append(sid)

    job_payload: Dict[str, Any] = {"pool": pool}
    if unlock_ids:
        job_payload["unlock_sync_ids"] = unlock_ids

    job = _enqueue_pool_job(
        node_id=int(node_id),
        kind="pool_save",
        payload=job_payload,
        user=user,
        meta={"action": "pool_save"},
    )
    _audit_log_node_action(
        action="pool.save_async_enqueue",
        user=user,
        node_id=int(node_id),
        node_name=str(node.get("name") or ""),
        detail={"job_id": str(job.get("job_id") or ""), "has_unlock_ids": bool(unlock_ids)},
        request=request,
    )
    return {"ok": True, "job": job}


@router.post("/api/nodes/{node_id}/rule_delete")
async def api_rule_delete(
    request: Request,
    node_id: int,
    payload: Dict[str, Any],
    user: str = Depends(require_login),
):
    """Delete one endpoint by index (best-effort immediate queue).

    This endpoint is intentionally lightweight and does not run full save-time precheck,
    so UI single-rule delete won't be blocked by unrelated validation/precheck noise.
    """
    node = get_node(node_id)
    if not node:
        return JSONResponse({"ok": False, "error": "节点不存在"}, status_code=404)

    try:
        idx = int((payload or {}).get("idx"))
    except Exception:
        idx = -1
    if idx < 0:
        return JSONResponse({"ok": False, "error": "idx 无效"}, status_code=400)

    unlock_sync_ids: set[str] = set()
    raw_unlock = (payload or {}).get("unlock_sync_ids")
    if isinstance(raw_unlock, list):
        for x in raw_unlock[:256]:
            sid = str(x or "").strip()
            if sid:
                unlock_sync_ids.add(sid)

    user_ref = _resolve_rule_user(user)
    scoped = is_rule_owner_scoped(user_ref)
    pool = _normalize_pool_dict(await load_pool_for_node(node))
    eps = pool.get("endpoints")
    if not isinstance(eps, list):
        eps = []
    if scoped:
        visible = _visible_endpoint_tuples(user_ref, pool)
        if idx >= len(visible):
            return JSONResponse({"ok": False, "error": "规则不存在或已删除"}, status_code=404)
        idx = int(visible[idx][0])
    if idx >= len(eps):
        return JSONResponse({"ok": False, "error": "规则不存在或已删除"}, status_code=404)

    ep = eps[idx] if isinstance(eps[idx], dict) else {}
    if scoped and not can_access_rule_endpoint(user_ref, ep):
        return JSONResponse({"ok": False, "error": "规则不存在或已删除"}, status_code=404)
    ex = ep.get("extra_config") if isinstance(ep.get("extra_config"), dict) else {}

    expected_key = str((payload or {}).get("expected_key") or "").strip()
    if expected_key:
        actual_key = _rule_key_for_endpoint(ep)
        if actual_key != expected_key:
            return JSONResponse(
                {
                    "ok": False,
                    "error": "规则索引已过期，请刷新后重试",
                    "code": "stale_index",
                    "actual_key": actual_key,
                },
                status_code=409,
            )

    sid = str(ex.get("sync_id") or "").strip() if isinstance(ex, dict) else ""
    allow_unlock = bool(sid and sid in unlock_sync_ids)
    if isinstance(ex, dict):
        if (ex.get("sync_lock") is True or ex.get("sync_role") == "receiver") and not allow_unlock:
            return JSONResponse(
                {"ok": False, "error": "该规则由发送机同步生成，已锁定不可删除，请在发送机节点操作。"},
                status_code=403,
            )
        if (
            (not _is_relay_sync_rule(ex))
            and (ex.get("intranet_lock") is True or ex.get("intranet_role") == "client")
            and (not allow_unlock)
        ):
            return JSONResponse(
                {"ok": False, "error": "该规则由公网入口同步生成，已锁定不可删除，请在公网入口节点操作。"},
                status_code=403,
            )

    deleted_rule_key = ""
    deleted_listen = ""
    try:
        deleted_rule_key = _rule_key_for_endpoint(ep)
    except Exception:
        deleted_rule_key = ""
    try:
        deleted_listen = str(ep.get("listen") or "").strip() if isinstance(ep, dict) else ""
    except Exception:
        deleted_listen = ""

    del eps[idx]
    pool["endpoints"] = eps

    try:
        desired_ver, _ = set_desired_pool(node_id, pool)
    except Exception as exc:
        return JSONResponse({"ok": False, "error": f"删除失败：写入面板配置时异常（{exc}）"}, status_code=500)
    try:
        schedule_apply_pool(node, pool)
    except Exception as exc:
        return JSONResponse({"ok": False, "error": f"删除失败：下发任务创建失败（{exc}）"}, status_code=500)

    _audit_log_node_action(
        action="rule.delete",
        user=user,
        node_id=int(node_id),
        node_name=str(node.get("name") or ""),
        detail={
            "rule_idx": int(idx),
            "rule_key": deleted_rule_key,
            "listen": deleted_listen,
            "desired_version": int(desired_ver),
            "rules_after": int(len(eps)),
        },
        request=request,
    )
    return {
        "ok": True,
        "pool": _filter_pool_for_user(user, pool),
        "desired_version": desired_ver,
        "queued": True,
        "note": "waiting agent report",
    }


@router.post("/api/nodes/{node_id}/rule_delete_async")
async def api_rule_delete_async(request: Request, node_id: int, payload: Dict[str, Any], user: str = Depends(require_login)):
    node = get_node(node_id)
    if not node:
        return JSONResponse({"ok": False, "error": "节点不存在"}, status_code=404)
    if not isinstance(payload, dict):
        return JSONResponse({"ok": False, "error": "payload 无效"}, status_code=400)

    idx_meta = -1
    try:
        idx_meta = int((payload or {}).get("idx"))
    except Exception:
        idx_meta = -1

    job = _enqueue_pool_job(
        node_id=int(node_id),
        kind="rule_delete",
        payload=dict(payload),
        user=user,
        meta={
            "action": "rule_delete",
            "idx": int(idx_meta),
        },
    )
    _audit_log_node_action(
        action="rule.delete_async_enqueue",
        user=user,
        node_id=int(node_id),
        node_name=str(node.get("name") or ""),
        detail={"job_id": str(job.get("job_id") or ""), "idx": int(idx_meta)},
        request=request,
    )
    return {"ok": True, "job": job}


@router.get("/api/nodes/{node_id}/pool_jobs/{job_id}")
async def api_pool_job_get(node_id: int, job_id: str, user: str = Depends(require_login)):
    jid = str(job_id or "").strip()
    if not jid:
        return JSONResponse({"ok": False, "error": "job_id 不能为空"}, status_code=400)
    node = get_node(int(node_id))
    if not node:
        return JSONResponse({"ok": False, "error": "节点不存在"}, status_code=404)
    if not _user_can_access_node(user, node):
        return JSONResponse({"ok": False, "error": "无权访问该节点"}, status_code=403)
    with _POOL_JOBS_LOCK:
        _prune_pool_jobs_locked()
        job = _POOL_JOBS.get(jid)
        if not isinstance(job, dict) or int(job.get("node_id") or 0) != int(node_id):
            return JSONResponse({"ok": False, "error": "任务不存在或已过期"}, status_code=404)
        return {"ok": True, "job": _pool_job_view(job, include_result=True)}


@router.post("/api/nodes/{node_id}/pool_jobs/{job_id}/retry")
async def api_pool_job_retry(node_id: int, job_id: str, user: str = Depends(require_login)):
    jid = str(job_id or "").strip()
    if not jid:
        return JSONResponse({"ok": False, "error": "job_id 不能为空"}, status_code=400)
    node = get_node(int(node_id))
    if not node:
        return JSONResponse({"ok": False, "error": "节点不存在"}, status_code=404)
    if not _user_can_access_node(user, node):
        return JSONResponse({"ok": False, "error": "无权访问该节点"}, status_code=403)

    kind = ""
    payload: Dict[str, Any] = {}
    meta: Dict[str, Any] = {}
    with _POOL_JOBS_LOCK:
        _prune_pool_jobs_locked()
        job = _POOL_JOBS.get(jid)
        if not isinstance(job, dict) or int(job.get("node_id") or 0) != int(node_id):
            return JSONResponse({"ok": False, "error": "任务不存在或已过期"}, status_code=404)
        st = str(job.get("status") or "")
        if st not in ("error", "success"):
            return JSONResponse({"ok": False, "error": "任务仍在执行中，请稍后再试"}, status_code=409)
        kind = str(job.get("kind") or "")
        if kind not in ("pool_save", "rule_restore", "rule_delete", "direct_tunnel_configure", "direct_tunnel_disable"):
            return JSONResponse({"ok": False, "error": "不支持该任务类型重试"}, status_code=400)
        payload0 = job.get("_payload")
        if not isinstance(payload0, dict):
            return JSONResponse({"ok": False, "error": "原任务缺少可重试参数"}, status_code=400)
        payload = dict(payload0)
        meta0 = job.get("meta")
        if isinstance(meta0, dict):
            meta = dict(meta0)

    nj = _enqueue_pool_job(node_id=int(node_id), kind=kind, payload=payload, user=user, meta=meta)
    return {"ok": True, "job": nj}


@router.post("/api/nodes/{node_id}/purge")
async def api_node_purge(
    request: Request,
    node_id: int,
    payload: Dict[str, Any],
    user: str = Depends(require_login),
):
    """Dangerous: clear all endpoints on a node (including locked/synced rules)."""

    confirm_text = str((payload or {}).get("confirm_text") or "").strip()
    if confirm_text != "确认删除":
        return JSONResponse({"ok": False, "error": "确认文本不匹配（需要完整输入：确认删除）"}, status_code=400)

    node = get_node(node_id)
    if not node:
        return JSONResponse({"ok": False, "error": "节点不存在"}, status_code=404)

    # Load current pool snapshot (desired > report > agent)
    cur_pool = await load_pool_for_node(node)

    # Collect sync pairs so we can remove peer rules too (avoid leaving orphaned locked rules)
    peer_tasks: List[tuple[int, str]] = []  # (peer_node_id, sync_id)
    seen_pairs: set[tuple[int, str]] = set()

    for ep in (cur_pool.get("endpoints") or []):
        if not isinstance(ep, dict):
            continue
        ex = ep.get("extra_config") or {}
        if not isinstance(ex, dict):
            continue
        sid = str(ex.get("sync_id") or "").strip()
        if not sid:
            continue

        peer_id = 0

        # WSS node-to-node sync
        role = str(ex.get("sync_role") or "").strip()
        if role == "sender":
            try:
                peer_id = int(ex.get("sync_peer_node_id") or 0)
            except Exception:
                peer_id = 0
        elif role == "receiver":
            try:
                peer_id = int(ex.get("sync_from_node_id") or 0)
            except Exception:
                peer_id = 0

        # Intranet tunnel sync (server/client)
        if peer_id <= 0:
            irole = str(ex.get("intranet_role") or "").strip()
            if irole in ("server", "client"):
                try:
                    peer_id = int(ex.get("intranet_peer_node_id") or 0)
                except Exception:
                    peer_id = 0

        if peer_id > 0 and peer_id != int(node_id):
            key = (peer_id, sid)
            if key not in seen_pairs:
                seen_pairs.add(key)
                peer_tasks.append((peer_id, sid))

    # Remove peers first (best effort). We do not block purge if peers fail.
    peers_cleared: List[int] = []
    for peer_id, sid in peer_tasks:
        peer = get_node(int(peer_id))
        if not peer:
            continue
        try:
            peer_pool = await load_pool_for_node(peer)
            remove_endpoints_by_sync_id(peer_pool, sid)
            set_desired_pool(int(peer_id), peer_pool)
            schedule_apply_pool(peer, peer_pool)
            peers_cleared.append(int(peer_id))
        except Exception:
            continue

    # Clear local endpoints (keep other pool keys as-is)
    new_pool = dict(cur_pool)
    new_pool["endpoints"] = []

    desired_ver, _ = set_desired_pool(node_id, new_pool)
    schedule_apply_pool(node, new_pool)

    _audit_log_node_action(
        action="rule.purge_all",
        user=user,
        node_id=int(node_id),
        node_name=str(node.get("name") or ""),
        detail={
            "rules_before": int(len(cur_pool.get("endpoints") or [])) if isinstance(cur_pool.get("endpoints"), list) else 0,
            "rules_after": 0,
            "peer_nodes_touched": sorted(set(peers_cleared)),
            "desired_version": int(desired_ver),
        },
        request=request,
    )

    return {
        "ok": True,
        "node_id": int(node_id),
        "cleared": True,
        "peer_nodes_touched": sorted(set(peers_cleared)),
        "desired_version": desired_ver,
        "queued": True,
    }


def _jsonresponse_payload(resp: JSONResponse) -> Dict[str, Any]:
    try:
        body = resp.body
        if isinstance(body, (bytes, bytearray)):
            txt = body.decode("utf-8", errors="ignore")
        else:
            txt = str(body or "")
        data = json.loads(txt) if txt else {}
        return data if isinstance(data, dict) else {"ok": False, "error": str(data)}
    except Exception:
        return {"ok": False, "error": "unknown_response"}


def _node_base_scheme(node: Dict[str, Any]) -> str:
    raw = str((node or {}).get("base_url") or "").strip()
    if not raw:
        return "http"
    if "://" not in raw:
        raw = "http://" + raw
    try:
        sch = str(urlparse(raw).scheme or "http").strip().lower()
    except Exception:
        sch = "http"
    if sch not in ("http", "https"):
        sch = "http"
    return sch


def _node_agent_port(node: Dict[str, Any]) -> int:
    raw = str((node or {}).get("base_url") or "").strip()
    if not raw:
        return int(DEFAULT_AGENT_PORT)
    if "://" not in raw:
        raw = "http://" + raw
    try:
        p = int(urlparse(raw).port or DEFAULT_AGENT_PORT)
    except Exception:
        p = int(DEFAULT_AGENT_PORT)
    if p < 1 or p > 65535:
        p = int(DEFAULT_AGENT_PORT)
    return int(p)


def _direct_tunnel_sync_id_for_node(node_id: int, existing: Any = "") -> str:
    cur = str(existing or "").strip()
    if cur:
        return cur
    return f"node-direct-{int(node_id)}"


def _direct_tunnel_public_host(relay: Optional[Dict[str, Any]], fallback: Any = "") -> str:
    host = ""
    if isinstance(relay, dict):
        host = node_host_for_realm(relay)
        if host.startswith("[") and host.endswith("]"):
            host = host[1:-1]
    if not host:
        host = str(fallback or "").strip()
    return host


def _user_can_access_node(user: str, node: Optional[Dict[str, Any]]) -> bool:
    if not isinstance(node, dict):
        return False
    nid = _to_int_loose(node.get("id"), 0)
    if nid <= 0:
        return False
    try:
        visible = filter_nodes_for_user(user, [node])
    except Exception:
        return False
    return any(_to_int_loose((x or {}).get("id"), 0) == nid for x in visible)


def _node_direct_tunnel_view(node: Dict[str, Any], relay: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    dt = (node or {}).get("direct_tunnel") if isinstance(node, dict) else {}
    if not isinstance(dt, dict):
        dt = {}
    enabled = bool(dt.get("enabled"))
    relay_id = _to_int_loose(dt.get("relay_node_id"), 0)
    listen_port = _to_int_loose(dt.get("listen_port"), 0)
    host = _direct_tunnel_public_host(relay, dt.get("public_host"))
    scheme = str(dt.get("scheme") or "").strip().lower() or _node_base_scheme(node)
    if scheme not in ("http", "https"):
        scheme = "http"
    direct_base_url = ""
    if enabled and host and 1 <= listen_port <= 65535:
        direct_base_url = f"{scheme}://{format_host_for_url(host)}:{int(listen_port)}"
    out = {
        "enabled": enabled,
        "sync_id": str(dt.get("sync_id") or "").strip(),
        "relay_node_id": int(relay_id),
        "listen_port": int(listen_port if 1 <= listen_port <= 65535 else 0),
        "public_host": str(host or ""),
        "scheme": scheme,
        "verify_tls": bool(dt.get("verify_tls")),
        "updated_at": str(dt.get("updated_at") or ""),
        "direct_base_url": direct_base_url,
    }
    if isinstance(relay, dict):
        out["relay_node"] = {
            "id": _to_int_loose(relay.get("id"), 0),
            "name": str(relay.get("name") or ""),
            "base_url": str(relay.get("base_url") or ""),
            "display_ip": extract_ip_for_display(str(relay.get("base_url") or "")),
            "online": bool(is_report_fresh(relay)),
        }
    return out


async def _suggest_direct_tunnel_port(node: Dict[str, Any], relay: Dict[str, Any], preferred: Optional[int]) -> int:
    relay_pool = await load_pool_for_node(relay)
    dt = node.get("direct_tunnel") if isinstance(node, dict) else {}
    sync_id = _direct_tunnel_sync_id_for_node(
        _to_int_loose(node.get("id"), 0),
        (dt or {}).get("sync_id") if isinstance(dt, dict) else "",
    )
    p = _to_int_loose(preferred, 0)
    if p < 1 or p > 65535:
        p = 0
    return int(choose_receiver_port(relay_pool, p or None, ignore_sync_id=sync_id))


@router.get("/api/nodes/{node_id}/direct_tunnel/options")
async def api_node_direct_tunnel_options(node_id: int, user: str = Depends(require_login)):
    node = get_node(int(node_id))
    if not node:
        return JSONResponse({"ok": False, "error": "节点不存在"}, status_code=404)
    if not _user_can_access_node(user, node):
        return JSONResponse({"ok": False, "error": "无权访问该节点"}, status_code=403)
    if not bool(node.get("is_private") or False):
        return JSONResponse({"ok": False, "error": "仅内网节点支持直连隧道配置"}, status_code=400)

    all_nodes = filter_nodes_for_user(user, list_nodes())
    relay_nodes: List[Dict[str, Any]] = []
    for n in all_nodes:
        nid = _to_int_loose((n or {}).get("id"), 0)
        if nid <= 0 or nid == int(node_id):
            continue
        host = _direct_tunnel_public_host(n)
        if not host:
            continue
        relay_nodes.append(
            {
                "id": nid,
                "name": str(n.get("name") or f"节点-{nid}"),
                "base_url": str(n.get("base_url") or ""),
                "display_ip": extract_ip_for_display(str(n.get("base_url") or "")),
                "is_private": bool(n.get("is_private") or 0),
                "online": bool(is_report_fresh(n)),
            }
        )
    relay_nodes.sort(
        key=lambda x: (
            1 if bool(x.get("is_private")) else 0,
            0 if bool(x.get("online")) else 1,
            _to_int_loose((x or {}).get("id"), 0),
        )
    )

    dt = node.get("direct_tunnel") if isinstance(node, dict) else {}
    relay_id = _to_int_loose((dt or {}).get("relay_node_id"), 0) if isinstance(dt, dict) else 0
    relay = get_node(relay_id) if relay_id > 0 else None
    if relay is not None and not _user_can_access_node(user, relay):
        relay = None
    current = _node_direct_tunnel_view(node, relay=relay)

    recommended = 0
    for row in relay_nodes:
        if bool(row.get("is_private")):
            continue
        recommended = _to_int_loose((row or {}).get("id"), 0)
        if bool(row.get("online")):
            break
    if recommended <= 0 and relay_nodes:
        recommended = _to_int_loose((relay_nodes[0] or {}).get("id"), 0)

    return {
        "ok": True,
        "node_id": int(node_id),
        "current": current,
        "relay_nodes": relay_nodes,
        "recommended_relay_node_id": int(recommended or 0),
    }


@router.post("/api/nodes/{node_id}/direct_tunnel/suggest_port")
async def api_node_direct_tunnel_suggest_port(node_id: int, request: Request, user: str = Depends(require_login)):
    try:
        payload = await request.json()
    except Exception:
        payload = {}

    node = get_node(int(node_id))
    if not node:
        return JSONResponse({"ok": False, "error": "节点不存在"}, status_code=404)
    if not _user_can_access_node(user, node):
        return JSONResponse({"ok": False, "error": "无权访问该节点"}, status_code=403)
    if not bool(node.get("is_private") or False):
        return JSONResponse({"ok": False, "error": "仅内网节点支持直连隧道配置"}, status_code=400)

    try:
        relay_node_id = int(payload.get("relay_node_id") or 0)
    except Exception:
        relay_node_id = 0
    if relay_node_id <= 0:
        return JSONResponse({"ok": False, "error": "relay_node_id 无效"}, status_code=400)

    relay = get_node(int(relay_node_id))
    if not relay:
        return JSONResponse({"ok": False, "error": "中继节点不存在"}, status_code=404)
    if _to_int_loose(relay.get("id"), 0) == int(node_id):
        return JSONResponse({"ok": False, "error": "中继节点不能是当前节点"}, status_code=400)
    if not _user_can_access_node(user, relay):
        return JSONResponse({"ok": False, "error": "无权访问中继节点"}, status_code=403)

    preferred = 0
    try:
        preferred = int(payload.get("preferred_port") or 0)
    except Exception:
        preferred = 0
    port = await _suggest_direct_tunnel_port(node, relay, preferred if preferred > 0 else None)
    return {"ok": True, "listen_port": int(port)}


async def _direct_tunnel_configure_impl(
    node_id: int,
    payload: Dict[str, Any],
    *,
    user: str,
    request: Optional[Request] = None,
    audit_action: str = "node.direct_tunnel.configure",
) -> Any:
    node = get_node(int(node_id))
    if not node:
        return JSONResponse({"ok": False, "error": "节点不存在"}, status_code=404)
    if not _user_can_access_node(user, node):
        return JSONResponse({"ok": False, "error": "无权访问该节点"}, status_code=403)
    if not bool(node.get("is_private") or False):
        return JSONResponse({"ok": False, "error": "仅内网节点支持直连隧道配置"}, status_code=400)

    data = payload if isinstance(payload, dict) else {}
    try:
        relay_node_id = int(data.get("relay_node_id") or 0)
    except Exception:
        relay_node_id = 0
    if relay_node_id <= 0:
        return JSONResponse({"ok": False, "error": "请选择中继节点"}, status_code=400)

    relay = get_node(int(relay_node_id))
    if not relay:
        return JSONResponse({"ok": False, "error": "中继节点不存在"}, status_code=404)
    if _to_int_loose(relay.get("id"), 0) == int(node_id):
        return JSONResponse({"ok": False, "error": "中继节点不能是当前节点"}, status_code=400)
    if not _user_can_access_node(user, relay):
        return JSONResponse({"ok": False, "error": "无权访问中继节点"}, status_code=403)

    dt_cur = node.get("direct_tunnel") if isinstance(node, dict) else {}
    sync_id = _direct_tunnel_sync_id_for_node(int(node_id), (dt_cur or {}).get("sync_id") if isinstance(dt_cur, dict) else "")
    listen_port = 0
    try:
        listen_port = int(data.get("listen_port") or 0)
    except Exception:
        listen_port = 0
    if listen_port <= 0:
        listen_port = await _suggest_direct_tunnel_port(node, relay, None)
    if listen_port < 1 or listen_port > 65535:
        return JSONResponse({"ok": False, "error": "监听端口无效"}, status_code=400)

    verify_tls = bool(data.get("verify_tls") or False)
    scheme = _node_base_scheme(node)
    agent_port = _node_agent_port(node)

    # Reuse existing intranet sync pipeline: sender(relay) <-> receiver(private node).
    intranet_payload = {
        "sender_node_id": int(relay_node_id),
        "receiver_node_id": int(node_id),
        "sync_id": sync_id,
        "listen": f"0.0.0.0:{int(listen_port)}",
        "remotes": [f"127.0.0.1:{int(agent_port)}"],
        "protocol": "tcp",
        "balance": "roundrobin",
        "disabled": False,
        "remark": f"[NodeDirect] 节点#{int(node_id)} 管理直连隧道",
    }
    from .api_sync import api_intranet_tunnel_save  # lazy import to avoid hard cycle at module load time

    ret = await api_intranet_tunnel_save(intranet_payload, user=user)
    if isinstance(ret, JSONResponse):
        body = _jsonresponse_payload(ret)
        status = int(getattr(ret, "status_code", 500) or 500)
        return JSONResponse({"ok": False, "error": str(body.get("error") or "隧道配置失败"), "detail": body}, status_code=status)
    if not isinstance(ret, dict) or not bool(ret.get("ok")):
        return JSONResponse({"ok": False, "error": "隧道配置失败"}, status_code=500)

    public_host = _direct_tunnel_public_host(relay)
    if not public_host:
        return JSONResponse({"ok": False, "error": "中继节点公网入口地址为空，请检查中继节点 base_url"}, status_code=400)

    set_node_direct_tunnel(
        int(node_id),
        enabled=True,
        sync_id=sync_id,
        relay_node_id=int(relay_node_id),
        listen_port=int(listen_port),
        public_host=public_host,
        scheme=scheme,
        verify_tls=bool(verify_tls),
    )
    updated = get_node(int(node_id)) or node
    relay2 = get_node(int(relay_node_id)) or relay
    current = _node_direct_tunnel_view(updated, relay=relay2)

    _audit_log_node_action(
        action=str(audit_action or "node.direct_tunnel.configure"),
        user=user,
        node_id=int(node_id),
        node_name=str(updated.get("name") or node.get("name") or ""),
        detail={
            "relay_node_id": int(relay_node_id),
            "sync_id": str(sync_id),
            "listen_port": int(listen_port),
            "verify_tls": bool(verify_tls),
            "direct_base_url": str(current.get("direct_base_url") or ""),
        },
        request=request,
    )

    return {"ok": True, "current": current, "sync_result": ret}


async def _direct_tunnel_disable_impl(
    node_id: int,
    *,
    user: str,
    request: Optional[Request] = None,
    audit_action: str = "node.direct_tunnel.disable",
) -> Any:
    node = get_node(int(node_id))
    if not node:
        return JSONResponse({"ok": False, "error": "节点不存在"}, status_code=404)
    if not _user_can_access_node(user, node):
        return JSONResponse({"ok": False, "error": "无权访问该节点"}, status_code=403)

    dt = node.get("direct_tunnel") if isinstance(node, dict) else {}
    if not isinstance(dt, dict):
        dt = {}
    sync_id = str(dt.get("sync_id") or "").strip()
    relay_node_id = int(dt.get("relay_node_id") or 0)

    delete_result: Dict[str, Any] = {"ok": True, "skipped": True}
    if sync_id and relay_node_id > 0:
        from .api_sync import api_intranet_tunnel_delete  # lazy import

        ret = await api_intranet_tunnel_delete(
            {
                "sender_node_id": int(relay_node_id),
                "receiver_node_id": int(node_id),
                "sync_id": sync_id,
            },
            user=user,
        )
        if isinstance(ret, JSONResponse):
            body = _jsonresponse_payload(ret)
            if int(getattr(ret, "status_code", 500) or 500) not in (200, 404):
                return JSONResponse({"ok": False, "error": str(body.get("error") or "关闭隧道失败"), "detail": body}, status_code=400)
            delete_result = body if isinstance(body, dict) else {"ok": False, "error": "delete_failed"}
        elif isinstance(ret, dict):
            delete_result = ret

    clear_node_direct_tunnel(int(node_id))
    updated = get_node(int(node_id)) or node
    current = _node_direct_tunnel_view(updated, relay=None)

    _audit_log_node_action(
        action=str(audit_action or "node.direct_tunnel.disable"),
        user=user,
        node_id=int(node_id),
        node_name=str(updated.get("name") or node.get("name") or ""),
        detail={"sync_id": sync_id, "relay_node_id": int(relay_node_id)},
        request=request,
    )

    return {"ok": True, "current": current, "delete_result": delete_result}


@router.post("/api/nodes/{node_id}/direct_tunnel/configure")
async def api_node_direct_tunnel_configure(node_id: int, request: Request, user: str = Depends(require_login)):
    try:
        payload = await request.json()
    except Exception:
        payload = {}
    return await _direct_tunnel_configure_impl(
        int(node_id),
        payload if isinstance(payload, dict) else {},
        user=user,
        request=request,
        audit_action="node.direct_tunnel.configure",
    )


@router.post("/api/nodes/{node_id}/direct_tunnel/disable")
async def api_node_direct_tunnel_disable(node_id: int, request: Request, user: str = Depends(require_login)):
    return await _direct_tunnel_disable_impl(
        int(node_id),
        user=user,
        request=request,
        audit_action="node.direct_tunnel.disable",
    )


@router.post("/api/nodes/{node_id}/direct_tunnel/configure_async")
async def api_node_direct_tunnel_configure_async(node_id: int, request: Request, user: str = Depends(require_login)):
    try:
        payload = await request.json()
    except Exception:
        payload = {}
    data = payload if isinstance(payload, dict) else {}
    node = get_node(int(node_id))
    if not node:
        return JSONResponse({"ok": False, "error": "节点不存在"}, status_code=404)
    if not _user_can_access_node(user, node):
        return JSONResponse({"ok": False, "error": "无权访问该节点"}, status_code=403)
    if not bool(node.get("is_private") or False):
        return JSONResponse({"ok": False, "error": "仅内网节点支持直连隧道配置"}, status_code=400)
    try:
        relay_meta = int(data.get("relay_node_id") or 0)
    except Exception:
        relay_meta = 0
    if relay_meta <= 0:
        return JSONResponse({"ok": False, "error": "请选择中继节点"}, status_code=400)
    relay = get_node(int(relay_meta))
    if not relay:
        return JSONResponse({"ok": False, "error": "中继节点不存在"}, status_code=404)
    if _to_int_loose(relay.get("id"), 0) == int(node_id):
        return JSONResponse({"ok": False, "error": "中继节点不能是当前节点"}, status_code=400)
    if not _user_can_access_node(user, relay):
        return JSONResponse({"ok": False, "error": "无权访问中继节点"}, status_code=403)
    try:
        listen_meta = int(data.get("listen_port") or 0)
    except Exception:
        listen_meta = 0

    job = _enqueue_pool_job(
        node_id=int(node_id),
        kind="direct_tunnel_configure",
        payload=data,
        user=user,
        meta={
            "action": "direct_tunnel_configure",
            "relay_node_id": int(relay_meta),
            "listen_port": int(listen_meta),
            "verify_tls": bool(data.get("verify_tls") or False),
        },
    )
    _audit_log_node_action(
        action="node.direct_tunnel.configure_async_enqueue",
        user=user,
        node_id=int(node_id),
        node_name=str(node.get("name") or ""),
        detail={
            "job_id": str(job.get("job_id") or ""),
            "relay_node_id": int(relay_meta),
            "listen_port": int(listen_meta),
            "verify_tls": bool(data.get("verify_tls") or False),
        },
        request=request,
    )
    return {"ok": True, "job": job}


@router.post("/api/nodes/{node_id}/direct_tunnel/disable_async")
async def api_node_direct_tunnel_disable_async(node_id: int, request: Request, user: str = Depends(require_login)):
    node = get_node(int(node_id))
    if not node:
        return JSONResponse({"ok": False, "error": "节点不存在"}, status_code=404)
    if not _user_can_access_node(user, node):
        return JSONResponse({"ok": False, "error": "无权访问该节点"}, status_code=403)
    job = _enqueue_pool_job(
        node_id=int(node_id),
        kind="direct_tunnel_disable",
        payload={},
        user=user,
        meta={"action": "direct_tunnel_disable"},
    )
    _audit_log_node_action(
        action="node.direct_tunnel.disable_async_enqueue",
        user=user,
        node_id=int(node_id),
        node_name=str(node.get("name") or ""),
        detail={"job_id": str(job.get("job_id") or "")},
        request=request,
    )
    return {"ok": True, "job": job}


@router.post("/api/nodes/create")
async def api_nodes_create(request: Request, user: str = Depends(require_login)):
    """Dashboard 快速接入节点（弹窗模式）。返回 JSON，前端可直接跳转节点详情页。"""
    try:
        data = await request.json()
    except Exception:
        data = {}

    name = str(data.get("name") or "").strip()
    ip_address = str(data.get("ip_address") or "").strip()
    scheme = str(data.get("scheme") or "http").strip().lower()
    verify_tls = bool(data.get("verify_tls")) if "verify_tls" in data else None
    is_private = bool(data.get("is_private") or False)
    is_website = data.get("is_website")
    website_root_base = str(data.get("website_root_base") or "").strip()
    group_name = str(data.get("group_name") or "").strip() or "默认分组"
    system_type = normalize_node_system_type(data.get("system_type"), default="auto")

    if scheme not in ("http", "https"):
        return JSONResponse({"ok": False, "error": "协议仅支持 http 或 https"}, status_code=400)
    if not ip_address:
        return JSONResponse({"ok": False, "error": "节点地址不能为空"}, status_code=400)

    # 端口在 UI 中隐藏：默认 18700；如用户自带 :port 则兼容解析（仍不展示）
    if "://" not in ip_address:
        ip_address = f"{scheme}://{ip_address}"

    port_value = DEFAULT_AGENT_PORT
    host, parsed_port, has_port, scheme = split_host_and_port(ip_address, port_value)
    if verify_tls is None:
        verify_tls = scheme == "https"
    if not host:
        return JSONResponse({"ok": False, "error": "节点地址不能为空"}, status_code=400)
    if has_port:
        port_value = parsed_port

    base_url = f"{scheme}://{format_host_for_url(host)}:{port_value}"
    api_key = generate_api_key()

    display_name = name or extract_ip_for_display(base_url)
    role = "website" if bool(is_website) else "normal"
    root_base = website_root_base.strip()
    if system_type == "macos":
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
        verify_tls=bool(verify_tls),
        is_private=is_private,
        group_name=group_name,
        role=role,
        website_root_base=root_base,
        system_type=system_type,
    )

    _audit_log_node_action(
        action="node.create",
        user=user,
        node_id=int(node_id),
        node_name=str(display_name or ""),
        detail={
            "base_url": str(base_url),
            "group_name": str(group_name),
            "is_private": bool(is_private),
            "role": str(role),
            "website_root_base": str(root_base or ""),
            "system_type": str(system_type),
        },
        request=request,
    )

    # 创建完成后，进入节点详情页时自动弹出“接入命令”窗口
    try:
        request.session["show_install_cmd"] = True
    except Exception:
        pass

    return JSONResponse({"ok": True, "node_id": node_id, "redirect_url": f"/nodes/{node_id}"})


@router.post("/api/nodes/{node_id}/update")
async def api_nodes_update(node_id: int, request: Request, user: str = Depends(require_login)):
    """编辑节点：修改名称 / 地址 / 分组（不改 api_key）。"""
    try:
        data = await request.json()
    except Exception:
        data = {}

    node = get_node(int(node_id))
    if not node:
        return JSONResponse({"ok": False, "error": "节点不存在"}, status_code=404)

    name_in = data.get("name", None)
    ip_in = data.get("ip_address", None)
    scheme_in = data.get("scheme", None)
    group_in = data.get("group_name", None)
    system_type_in = data.get("system_type", None)

    # is_private: only update when provided
    if "is_private" in data:
        is_private = bool(data.get("is_private") or False)
    else:
        is_private = bool(node.get("is_private", 0))

    # verify_tls: only update when provided
    if "verify_tls" in data:
        verify_tls = bool(data.get("verify_tls")) if "verify_tls" in data else None
    else:
        verify_tls = bool(node.get("verify_tls", 0))

    # role: only update when provided
    if "is_website" in data:
        role = "website" if bool(data.get("is_website")) else "normal"
    else:
        role = str(node.get("role") or "normal").strip().lower() or "normal"
        if role not in ("normal", "website"):
            role = "normal"

    # website root base
    if "website_root_base" in data:
        website_root_base = str(data.get("website_root_base") or "").strip()
    else:
        website_root_base = str(node.get("website_root_base") or "").strip()

    # group name
    if group_in is None:
        group_name = str(node.get("group_name") or "默认分组").strip() or "默认分组"
    else:
        group_name = str(group_in or "").strip() or "默认分组"

    # system type
    if system_type_in is None:
        system_type = None
    else:
        system_type = normalize_node_system_type(system_type_in, default="auto")
    effective_system_type = normalize_node_system_type(
        system_type if system_type is not None else node.get("system_type"),
        default="auto",
    )
    if effective_system_type == "macos":
        role = "normal"
        website_root_base = ""
    elif role == "website" and not website_root_base:
        website_root_base = "/www"
    elif role != "website":
        website_root_base = ""

    policy_has_any, policy_in = _normalize_auto_restart_policy_from_payload(data, node)
    policy_apply = False
    if policy_has_any:
        policy_base = node_auto_restart_policy_from_row(node if isinstance(node, dict) else {})
        policy_apply = any(
            policy_in.get(k) != policy_base.get(k)
            for k in ("enabled", "schedule_type", "interval", "hour", "minute", "weekdays", "monthdays")
        )

    # parse existing base_url
    raw_old = str(node.get("base_url") or "").strip()
    if not raw_old:
        return JSONResponse({"ok": False, "error": "节点地址异常"}, status_code=400)
    if "://" not in raw_old:
        raw_old = "http://" + raw_old

    try:
        parsed_old = urlparse(raw_old)
        old_scheme = str(parsed_old.scheme or "http").strip().lower()
    except Exception:
        old_scheme = "http"
    if old_scheme not in ("http", "https"):
        old_scheme = "http"

    old_host, old_port_parsed, old_has_port, parsed_old_scheme = split_host_and_port(raw_old, DEFAULT_AGENT_PORT)
    if parsed_old_scheme in ("http", "https"):
        old_scheme = parsed_old_scheme
    old_host = str(old_host or "").strip()
    if old_host.startswith("[") and not old_host.endswith("]"):
        old_host = old_host.lstrip("[")
    if old_host.endswith("]") and not old_host.startswith("["):
        old_host = old_host.rstrip("]")
    old_port = int(old_port_parsed) if old_has_port else None

    scheme = str(scheme_in or old_scheme).strip().lower() or "http"
    if scheme not in ("http", "https"):
        return JSONResponse({"ok": False, "error": "协议仅支持 http 或 https"}, status_code=400)

    host = old_host
    port_value = old_port
    has_port = old_has_port

    if ip_in is not None:
        ip_address = str(ip_in or "").strip()
        if not ip_address:
            return JSONResponse({"ok": False, "error": "节点地址不能为空"}, status_code=400)

        # allow user paste full url
        ip_full = ip_address
        if "://" not in ip_full:
            ip_full = f"{scheme}://{ip_full}"

        fallback_port = int(old_port) if old_has_port and old_port else DEFAULT_AGENT_PORT
        h, p, has_p, parsed_scheme = split_host_and_port(ip_full, fallback_port)
        if not h:
            return JSONResponse({"ok": False, "error": "节点地址不能为空"}, status_code=400)

        # only override scheme when user explicitly provided scheme
        if "://" in ip_address:
            scheme = (parsed_scheme or scheme).lower()
        host = h

        if has_p:
            port_value = int(p)
            has_port = True
        else:
            # preserve old explicit port; otherwise keep no-port
            if old_has_port and old_port:
                port_value = int(old_port)
                has_port = True
            else:
                port_value = None
                has_port = False

    if not str(host or "").strip():
        return JSONResponse({"ok": False, "error": "节点地址不能为空"}, status_code=400)

    base_url = f"{scheme}://{format_host_for_url(host)}"
    if has_port and port_value:
        base_url += f":{int(port_value)}"

    # prevent duplicates
    other = get_node_by_base_url(base_url)
    if other and int(other.get("id") or 0) != int(node_id):
        return JSONResponse({"ok": False, "error": "该节点地址已被其他节点使用"}, status_code=400)

    # name
    if name_in is None:
        name = str(node.get("name") or "").strip() or extract_ip_for_display(base_url)
    else:
        name = str(name_in or "").strip() or extract_ip_for_display(base_url)

    update_node_basic(
        int(node_id),
        name,
        base_url,
        str(node.get("api_key") or ""),
        verify_tls=bool(verify_tls),
        is_private=is_private,
        group_name=group_name,
        role=role,
        website_root_base=website_root_base,
        system_type=system_type,
    )

    policy_ver = int(node.get("desired_auto_restart_policy_version") or 0)
    if policy_apply:
        policy_ver, _ = set_node_auto_restart_policy(
            int(node_id),
            enabled=bool(policy_in.get("enabled")),
            schedule_type=str(policy_in.get("schedule_type") or "daily"),
            interval=int(policy_in.get("interval") or 1),
            hour=int(policy_in.get("hour")) if policy_in.get("hour") is not None else 4,
            minute=int(policy_in.get("minute")) if policy_in.get("minute") is not None else 8,
            weekdays=list(policy_in.get("weekdays") or [1, 2, 3, 4, 5, 6, 7]),
            monthdays=list(policy_in.get("monthdays") or [1]),
        )

    # Return updated fields for client-side UI refresh
    updated = get_node(int(node_id)) or {}
    display_ip = extract_ip_for_display(str(updated.get("base_url") or base_url))
    policy_out = node_auto_restart_policy_from_row(updated if isinstance(updated, dict) else node)
    if policy_apply:
        policy_out["desired_version"] = int(policy_ver)
    dt_relay_id = int(((updated.get("direct_tunnel") if isinstance(updated, dict) else {}) or {}).get("relay_node_id") or 0)
    dt_relay = get_node(dt_relay_id) if dt_relay_id > 0 else None
    direct_tunnel_out = _node_direct_tunnel_view(updated if isinstance(updated, dict) else node, relay=dt_relay)

    _audit_log_node_action(
        action="node.update",
        user=user,
        node_id=int(node_id),
        node_name=str(updated.get("name") or name),
        detail={
            "old_name": str(node.get("name") or ""),
            "new_name": str(updated.get("name") or name),
            "old_base_url": str(node.get("base_url") or ""),
            "new_base_url": str(updated.get("base_url") or base_url),
            "old_group_name": str(node.get("group_name") or ""),
            "new_group_name": str(updated.get("group_name") or group_name),
            "old_verify_tls": bool(node.get("verify_tls") or 0),
            "new_verify_tls": bool(updated.get("verify_tls") or verify_tls),
            "old_is_private": bool(node.get("is_private") or 0),
            "new_is_private": bool(updated.get("is_private") or is_private),
            "old_role": str(node.get("role") or "normal"),
            "new_role": str(updated.get("role") or role),
            "old_system_type": normalize_node_system_type(node.get("system_type"), default="auto"),
            "new_system_type": normalize_node_system_type(
                updated.get("system_type"),
                default=system_type if system_type is not None else normalize_node_system_type(node.get("system_type"), default="auto"),
            ),
            "policy_changed": bool(policy_apply),
        },
        request=request,
    )

    return JSONResponse(
        {
            "ok": True,
            "node": {
                "id": int(node_id),
                "name": str(updated.get("name") or name),
                "base_url": str(updated.get("base_url") or base_url),
                "group_name": str(updated.get("group_name") or group_name),
                "display_ip": display_ip,
                "verify_tls": bool(updated.get("verify_tls") or verify_tls),
                "is_private": bool(updated.get("is_private") or is_private),
                "role": str(updated.get("role") or role),
                "website_root_base": str(updated.get("website_root_base") or website_root_base),
                "system_type": normalize_node_system_type(
                    updated.get("system_type"),
                    default=system_type if system_type is not None else normalize_node_system_type(node.get("system_type"), default="auto"),
                ),
                "auto_restart_policy": policy_out,
                "direct_tunnel": direct_tunnel_out,
            },
        }
    )


@router.get("/api/nodes")
async def api_nodes_list(user: str = Depends(require_login)):
    out = []
    for n in filter_nodes_for_user(user, list_nodes()):
        pol = node_auto_restart_policy_from_row(n if isinstance(n, dict) else {})
        online = bool(is_report_fresh(n if isinstance(n, dict) else {}))
        out.append(
            {
                "id": int(n["id"]),
                "name": n["name"],
                "base_url": n["base_url"],
                "display_ip": extract_ip_for_display(str(n.get("base_url") or "")),
                "group_name": n.get("group_name"),
                "is_private": bool(n.get("is_private") or 0),
                "online": online,
                "is_online": online,
                "last_seen_at": str(n.get("last_seen_at") or ""),
                "role": n.get("role") or "normal",
                "website_root_base": n.get("website_root_base") or "",
                "system_type": normalize_node_system_type(n.get("system_type"), default="auto"),
                "auto_restart_policy": pol,
                "direct_tunnel": _node_direct_tunnel_view(n if isinstance(n, dict) else {}, relay=None),
            }
        )
    return {"ok": True, "nodes": out}


@router.post("/api/nodes/{node_id}/apply")
async def api_apply(request: Request, node_id: int, user: str = Depends(require_login)):
    node = get_node(node_id)
    if not node:
        return JSONResponse({"ok": False, "error": "节点不存在"}, status_code=404)
    target_base_url, target_verify_tls, target_route = node_agent_request_target(node)
    try:
        data = await agent_post(target_base_url, node["api_key"], "/api/v1/apply", {}, target_verify_tls)
        if not data.get("ok", True):
            return JSONResponse({"ok": False, "error": data.get("error", "Agent 应用配置失败")}, status_code=502)
        _audit_log_node_action(
            action="pool.apply",
            user=user,
            node_id=int(node_id),
            node_name=str(node.get("name") or ""),
            detail={"queued": False, "mode": str(target_route or "direct")},
            request=request,
        )
        return data
    except Exception:
        # Push-report fallback: bump desired version to trigger a re-sync/apply on agent
        desired_ver, desired_pool = get_desired_pool(node_id)
        if isinstance(desired_pool, dict):
            new_ver, _ = set_desired_pool(node_id, desired_pool)
            _audit_log_node_action(
                action="pool.apply_queued",
                user=user,
                node_id=int(node_id),
                node_name=str(node.get("name") or ""),
                detail={"queued": True, "mode": "fallback", "desired_version": int(new_ver)},
                request=request,
            )
            return {"ok": True, "queued": True, "desired_version": new_ver}
        return {"ok": False, "error": "Agent 无法访问，且面板无缓存规则（请检查网络或等待 Agent 上报）"}



@router.post("/api/nodes/{node_id}/traffic/reset")
async def api_reset_traffic(request: Request, node_id: int, user: str = Depends(require_login)):
    """Reset rule traffic counters on a node."""
    node = get_node(node_id)
    if not node:
        return JSONResponse({"ok": False, "error": "节点不存在"}, status_code=404)
    target_base_url, target_verify_tls, target_route = node_agent_request_target(node)
    try:
        data = await agent_post(
            target_base_url,
            node["api_key"],
            "/api/v1/traffic/reset",
            {},
            target_verify_tls,
            timeout=10.0,
        )
        if isinstance(data, dict) and bool(data.get("ok", False)):
            _audit_log_node_action(
                action="traffic.reset",
                user=user,
                node_id=int(node_id),
                node_name=str(node.get("name") or ""),
                detail={"queued": False, "mode": str(target_route or "direct")},
                request=request,
            )
        return data
    except Exception as exc:
        # Fallback: queue via agent push-report (works for private/unreachable nodes)
        try:
            new_ver = bump_traffic_reset_version(int(node_id))
            _audit_log_node_action(
                action="traffic.reset_queued",
                user=user,
                node_id=int(node_id),
                node_name=str(node.get("name") or ""),
                detail={"queued": True, "mode": "fallback", "desired_reset_version": int(new_ver)},
                request=request,
            )
            return {
                "ok": True,
                "queued": True,
                "desired_reset_version": new_ver,
                "direct_error": str(exc),
                "message": "Agent 直连失败，已改为排队等待节点上报后自动执行",
            }
        except Exception as exc2:
            return JSONResponse(
                {"ok": False, "error": f"{exc}; 同时排队失败：{exc2}"},
                status_code=502,
            )


@router.get("/api/nodes/{node_id}/stats")
async def api_stats(request: Request, node_id: int, force: int = 0, user: str = Depends(require_login)):
    node = get_node(node_id)
    if not node:
        return JSONResponse({"ok": False, "error": "节点不存在"}, status_code=404)

    pool_for_scope: Optional[Dict[str, Any]] = None
    scoped_rule_view = is_rule_owner_scoped(user)
    fresh = bool(is_report_fresh(node))
    rep_cache: Optional[Dict[str, Any]] = None
    prefer_pull = bool(force) or (node_info_fetch_order() == FETCH_ORDER_PULL_FIRST)

    async def _report_stats_payload(rep_obj: Any, stale: bool) -> Optional[Dict[str, Any]]:
        nonlocal pool_for_scope
        if not (isinstance(rep_obj, dict) and isinstance(rep_obj.get("stats"), dict)):
            return None
        out = dict(rep_obj["stats"])
        out["source"] = "report"
        out["stale"] = bool(stale)
        # Use report receive time as series timestamp.
        # If we always use "now" here, repeated reads of an unchanged cached report
        # will create artificial zero/peak alternation in rate charts.
        try:
            ts_ms = int(out.get("ts_ms") or 0)
        except Exception:
            ts_ms = 0
        if ts_ms <= 0:
            try:
                seen = str(node.get("last_seen_at") or "").strip()
                dt = datetime.strptime(seen, "%Y-%m-%d %H:%M:%S")
                ts_ms = int(dt.timestamp() * 1000)
            except Exception:
                ts_ms = 0
        if ts_ms <= 0:
            try:
                ts_ms = int(time.time() * 1000)
            except Exception:
                ts_ms = 0
        if ts_ms > 0:
            out["ts_ms"] = ts_ms
        if scoped_rule_view:
            if pool_for_scope is None:
                try:
                    pool_for_scope = await load_pool_for_node(node)
                except Exception:
                    pool_for_scope = {}
            out = _filter_stats_payload_for_user(user, _normalize_pool_dict(pool_for_scope), out)
        return out

    async def _pull_stats_payload() -> Tuple[Optional[Dict[str, Any]], str]:
        nonlocal pool_for_scope
        try:
            target_base_url, target_verify_tls, _target_route = node_agent_request_target(node)
            data = await agent_get(target_base_url, node["api_key"], "/api/v1/stats", target_verify_tls)
        except Exception as exc:
            return None, str(exc)

        # Provide a stable server-side timestamp for frontend history alignment.
        try:
            if isinstance(data, dict):
                data["ts_ms"] = int(time.time() * 1000)
                data.setdefault("source", "agent")
        except Exception:
            pass

        # Fallback sampling: if push-report is not used, persist history from direct stats.
        # Best-effort: never fail the request.
        try:
            if isinstance(data, dict) and data.get("ok") is True:
                _touch_node_last_seen_safe(node_id, node)
                ingest_stats_snapshot(node_id=node_id, stats=data)
        except Exception:
            pass

        if scoped_rule_view and isinstance(data, dict):
            if pool_for_scope is None:
                try:
                    pool_for_scope = await load_pool_for_node(node)
                except Exception:
                    pool_for_scope = {}
            data = _filter_stats_payload_for_user(user, _normalize_pool_dict(pool_for_scope), data)
        return data if isinstance(data, dict) else {"ok": False, "error": "响应格式异常", "rules": []}, ""

    if (not force) and (not prefer_pull) and fresh:
        rep_cache = get_last_report(node_id)
        report_payload = await _report_stats_payload(rep_cache, stale=False)
        if isinstance(report_payload, dict):
            return report_payload

    last_direct_err = ""
    if prefer_pull:
        pulled, err = await _pull_stats_payload()
        if isinstance(pulled, dict) and bool(pulled.get("ok", True)):
            return pulled
        if isinstance(pulled, dict):
            last_direct_err = str(pulled.get("error") or err or "")
        else:
            last_direct_err = str(err or "")

    if not force:
        if rep_cache is None:
            rep_cache = get_last_report(node_id)
        report_payload = await _report_stats_payload(rep_cache, stale=(not fresh))
        if isinstance(report_payload, dict):
            return report_payload

    if not prefer_pull:
        pulled, err = await _pull_stats_payload()
        if isinstance(pulled, dict) and bool(pulled.get("ok", True)):
            return pulled
        if isinstance(pulled, dict):
            last_direct_err = str(pulled.get("error") or err or "")
        else:
            last_direct_err = str(err or "")

    # Return 200 with ok=false to keep frontend error message stable.
    return {"ok": False, "error": (last_direct_err or "暂无可用统计数据"), "rules": []}


@router.get("/api/nodes/{node_id}/stats_history")
async def api_stats_history(
    request: Request,
    node_id: int,
    key: str = "__all__",
    window_ms: int = 10 * 60 * 1000,
    limit: int = 0,
    user: str = Depends(require_login),
):
    """Return persistent traffic/connection history series for a node.

    Notes:
      - The series is stored on the panel (SQLite) and will survive browser refresh/close.
      - One extra point before the window is included (when available) so the UI can compute rate.
    """
    node = get_node(node_id)
    if not node:
        return JSONResponse({"ok": False, "error": "节点不存在"}, status_code=404)

    cfg = stats_history_config() if callable(stats_history_config) else {}
    try:
        retention_days = int((cfg or {}).get("retention_days") or 7)
    except Exception:
        retention_days = 7
    if retention_days < 1:
        retention_days = 1
    if retention_days > 90:
        retention_days = 90
    max_win_ms = retention_days * 24 * 3600 * 1000

    # Clamp window to protect DB and payload size (bounded by retention days).
    try:
        win = int(window_ms)
    except Exception:
        win = 10 * 60 * 1000
    if win < 60 * 1000:
        win = 60 * 1000
    if win > max_win_ms:
        win = max_win_ms

    # Auto-select a sensible point limit when client does not provide one.
    try:
        lim = int(limit)
    except Exception:
        lim = 0
    if lim <= 0:
        try:
            sample_interval_sec = float((cfg or {}).get("sample_interval_sec") or 10.0)
        except Exception:
            sample_interval_sec = 10.0
        if sample_interval_sec < 1.0:
            sample_interval_sec = 1.0
        # +32 to keep a small buffer and include previous-boundary sample.
        lim = int((float(win) / 1000.0) / sample_interval_sec) + 32
    if lim < 200:
        lim = 200
    if lim > 200000:
        lim = 200000

    now_ms = int(time.time() * 1000)
    from_ms = now_ms - win
    if from_ms < 0:
        from_ms = 0

    k = (key or "__all__").strip() or "__all__"
    if is_rule_owner_scoped(user):
        try:
            scoped_pool = _normalize_pool_dict(await load_pool_for_node(node))
        except Exception:
            scoped_pool = {"endpoints": []}
        allowed_keys = _visible_rule_history_keys(user, scoped_pool)
        if k == "__all__":
            # Scoped users cannot read aggregated series that may include hidden rules.
            return {
                "ok": True,
                "node_id": int(node_id),
                "key": k,
                "from_ts_ms": int(from_ms),
                "to_ts_ms": int(now_ms),
                "window_ms": int(win),
                "limit": int(lim),
                "t": [],
                "rx": [],
                "tx": [],
                "conn": [],
                "source": "db_scoped",
                "config": stats_history_config(),
            }
        if k not in allowed_keys:
            return JSONResponse({"ok": False, "error": "规则不存在或无权限"}, status_code=403)

    try:
        rows = list_rule_stats_series(
            node_id=int(node_id),
            rule_key=k,
            from_ts_ms=int(from_ms),
            to_ts_ms=int(now_ms),
            limit=int(lim),
            include_prev=True,
        )
    except Exception:
        rows = []

    t: List[int] = []
    rx: List[int] = []
    tx: List[int] = []
    conn: List[int] = []
    for r in rows:
        if not isinstance(r, dict):
            continue
        try:
            ts = int(r.get("ts_ms") or 0)
        except Exception:
            ts = 0
        if ts <= 0:
            continue
        try:
            rrx = int(r.get("rx_bytes") or 0)
        except Exception:
            rrx = 0
        try:
            rtx = int(r.get("tx_bytes") or 0)
        except Exception:
            rtx = 0
        try:
            rc = int(r.get("connections_active") or 0)
        except Exception:
            rc = 0
        t.append(ts)
        rx.append(max(0, rrx))
        tx.append(max(0, rtx))
        conn.append(max(0, rc))

    return {
        "ok": True,
        "node_id": int(node_id),
        "key": k,
        "from_ts_ms": int(from_ms),
        "to_ts_ms": int(now_ms),
        "window_ms": int(win),
        "limit": int(lim),
        "t": t,
        "rx": rx,
        "tx": tx,
        "conn": conn,
        "source": "db",
        "config": stats_history_config(),
    }


@router.post("/api/nodes/{node_id}/stats_history/clear")
async def api_stats_history_clear(
    request: Request,
    node_id: int,
    user: str = Depends(require_login),
):
    """Clear persistent history for a node."""
    node = get_node(node_id)
    if not node:
        return JSONResponse({"ok": False, "error": "节点不存在"}, status_code=404)

    try:
        deleted = clear_rule_stats_samples(int(node_id))
    except Exception as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=500)

    return {
        "ok": True,
        "node_id": int(node_id),
        "deleted": int(deleted or 0),
    }


def _sys_snapshot_cache_key(node_id: int, cached: bool) -> str:
    return f"{int(node_id)}:{1 if bool(cached) else 0}"


def _sys_snapshot_cache_ttl(payload: Any) -> float:
    if not isinstance(payload, dict):
        return float(_SYS_SNAPSHOT_ERROR_CACHE_TTL_SEC)
    if not bool(payload.get("ok")):
        return float(_SYS_SNAPSHOT_ERROR_CACHE_TTL_SEC)
    sys_data = payload.get("sys")
    if isinstance(sys_data, dict):
        if sys_data.get("ok") is False:
            return float(_SYS_SNAPSHOT_ERROR_CACHE_TTL_SEC)
        if str(sys_data.get("error") or "").strip():
            return float(_SYS_SNAPSHOT_ERROR_CACHE_TTL_SEC)
    return float(_SYS_SNAPSHOT_CACHE_TTL_SEC)


def _sys_snapshot_cache_cleanup_locked(now_ts: float) -> None:
    global _SYS_SNAPSHOT_CACHE_NEXT_CLEANUP_AT
    if now_ts < float(_SYS_SNAPSHOT_CACHE_NEXT_CLEANUP_AT) and len(_SYS_SNAPSHOT_CACHE) <= int(_SYS_SNAPSHOT_CACHE_MAX_ITEMS):
        return
    _SYS_SNAPSHOT_CACHE_NEXT_CLEANUP_AT = now_ts + float(_SYS_SNAPSHOT_CACHE_CLEANUP_INTERVAL_SEC)

    for key, row in list(_SYS_SNAPSHOT_CACHE.items()):
        if not isinstance(row, dict):
            _SYS_SNAPSHOT_CACHE.pop(key, None)
            continue
        expire_at = float(row.get("expire_at") or 0)
        if expire_at > 0 and now_ts >= expire_at:
            _SYS_SNAPSHOT_CACHE.pop(key, None)

    overflow = len(_SYS_SNAPSHOT_CACHE) - int(_SYS_SNAPSHOT_CACHE_MAX_ITEMS)
    if overflow > 0:
        ordered = sorted(
            _SYS_SNAPSHOT_CACHE.items(),
            key=lambda kv: float((kv[1] or {}).get("updated_at") or 0),
        )
        for idx in range(min(overflow, len(ordered))):
            _SYS_SNAPSHOT_CACHE.pop(str(ordered[idx][0]), None)


def _sys_snapshot_cache_get(node_id: int, cached: bool, last_seen_at: Any = "") -> Optional[Dict[str, Any]]:
    if (not _SYS_SNAPSHOT_CACHE_ENABLED) or (not bool(cached)):
        return None
    key = _sys_snapshot_cache_key(int(node_id), bool(cached))
    marker = str(last_seen_at or "").strip()
    now_ts = time.time()
    with _SYS_SNAPSHOT_CACHE_LOCK:
        _sys_snapshot_cache_cleanup_locked(now_ts)
        row = _SYS_SNAPSHOT_CACHE.get(key)
        if not isinstance(row, dict):
            return None
        if marker and str(row.get("last_seen_at") or "").strip() != marker:
            return None
        expire_at = float(row.get("expire_at") or 0)
        if expire_at > 0 and now_ts >= expire_at:
            _SYS_SNAPSHOT_CACHE.pop(key, None)
            return None
        payload = row.get("payload")
        if not isinstance(payload, dict):
            return None
        row["updated_at"] = now_ts
        _SYS_SNAPSHOT_CACHE[key] = dict(row)
        return copy.deepcopy(payload)


def _sys_snapshot_cache_put(node_id: int, cached: bool, last_seen_at: Any, payload: Dict[str, Any]) -> None:
    if (not _SYS_SNAPSHOT_CACHE_ENABLED) or (not bool(cached)) or (not isinstance(payload, dict)):
        return
    key = _sys_snapshot_cache_key(int(node_id), bool(cached))
    marker = str(last_seen_at or "").strip()
    now_ts = time.time()
    ttl = _sys_snapshot_cache_ttl(payload)
    with _SYS_SNAPSHOT_CACHE_LOCK:
        _SYS_SNAPSHOT_CACHE[key] = {
            "payload": copy.deepcopy(payload),
            "last_seen_at": marker,
            "updated_at": now_ts,
            "expire_at": now_ts + float(ttl),
        }
        _sys_snapshot_cache_cleanup_locked(now_ts)


def _parse_node_ids_csv(raw: Any, limit: int = 300) -> List[int]:
    out: List[int] = []
    seen: set[int] = set()
    text = str(raw or "").strip()
    if not text:
        return out
    for chunk in text.replace(";", ",").replace(" ", ",").split(","):
        part = str(chunk or "").strip()
        if not part:
            continue
        try:
            nid = int(part)
        except Exception:
            continue
        if nid <= 0 or nid in seen:
            continue
        seen.add(nid)
        out.append(nid)
        if len(out) >= int(limit):
            break
    return out


async def _build_api_sys_payload(
    node_id: int,
    node: Dict[str, Any],
    cached: bool,
    report_cache: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    sys_data: Optional[Dict[str, Any]] = None
    rep_cache: Optional[Dict[str, Any]] = report_cache if isinstance(report_cache, dict) else None
    auto_restart_data: Optional[Dict[str, Any]] = None
    fresh = bool(is_report_fresh(node))
    source_order = ("report", "pull") if bool(cached) else node_info_sources_order(force_pull=False)
    last_pull_err = ""

    def _ensure_auto_restart_from_report() -> None:
        nonlocal rep_cache, auto_restart_data
        if isinstance(auto_restart_data, dict):
            return
        if not isinstance(rep_cache, dict):
            rep_cache = get_last_report(node_id)
        if isinstance(rep_cache, dict) and isinstance(rep_cache.get("auto_restart"), dict):
            auto_restart_data = dict(rep_cache["auto_restart"])
            auto_restart_data["source"] = "report"
            auto_restart_data["stale"] = not fresh

    def _ensure_auto_restart_fallback() -> Dict[str, Any]:
        nonlocal auto_restart_data
        if isinstance(auto_restart_data, dict):
            return auto_restart_data
        auto_restart_data = node_auto_restart_policy_from_row(node if isinstance(node, dict) else {})
        auto_restart_data["source"] = "panel"
        auto_restart_data["stale"] = not fresh
        return auto_restart_data

    _ensure_auto_restart_from_report()

    for idx, source in enumerate(source_order):
        if source == "report":
            if not isinstance(rep_cache, dict):
                rep_cache = get_last_report(node_id)
            if not (isinstance(rep_cache, dict) and isinstance(rep_cache.get("sys"), dict)):
                continue
            allow_stale = bool(cached) or (idx > 0)
            if (not allow_stale) and (not fresh):
                continue
            sys_data = dict(rep_cache["sys"])
            sys_data["source"] = "report"
            sys_data["stale"] = not fresh
            return {"ok": True, "sys": sys_data, "auto_restart": _ensure_auto_restart_fallback()}

        try:
            target_base_url, target_verify_tls, _target_route = node_agent_request_target(node)
            data = await agent_get(target_base_url, node["api_key"], "/api/v1/sys", target_verify_tls)
        except Exception as exc:
            last_pull_err = str(exc)
            continue
        if isinstance(data, dict) and data.get("ok") is True:
            sys_data = dict(data)
            sys_data["source"] = "agent"
            _touch_node_last_seen_safe(node_id, node)
            return {"ok": True, "sys": sys_data, "auto_restart": _ensure_auto_restart_fallback()}
        if isinstance(data, dict):
            last_pull_err = str(data.get("error") or "响应格式异常")
        else:
            last_pull_err = "响应格式异常"

    auto_restart_final = _ensure_auto_restart_fallback()
    if cached:
        err = last_pull_err or "Agent 尚未上报系统信息（请升级 Agent 或稍后重试）"
        return {
            "ok": True,
            "sys": {
                "ok": False,
                "error": err,
                "source": "report",
            },
            "auto_restart": auto_restart_final,
        }
    return {"ok": False, "error": (last_pull_err or "暂无可用系统信息"), "auto_restart": auto_restart_final}


@router.get("/api/nodes/{node_id}/sys")
async def api_sys(request: Request, node_id: int, cached: int = 0, user: str = Depends(require_login)):
    """节点系统信息：CPU/内存/硬盘/交换/在线时长/流量/实时速率。"""
    _ = request
    _ = user
    # 高频接口（仪表盘会按节点轮询），避免读取 nodes 大字段（last_report_json/desired_pool_json）。
    node = get_node_runtime(node_id)
    if not node:
        return JSONResponse({"ok": False, "error": "节点不存在"}, status_code=404)

    use_cached = bool(cached)
    last_seen_marker = str((node or {}).get("last_seen_at") or "")
    if use_cached:
        hit = _sys_snapshot_cache_get(node_id, use_cached, last_seen_marker)
        if isinstance(hit, dict):
            return hit

    payload = await _build_api_sys_payload(node_id, node, use_cached)
    if use_cached and isinstance(payload, dict):
        _sys_snapshot_cache_put(node_id, use_cached, last_seen_marker, payload)
    return payload


@router.get("/api/nodes/sys_batch")
async def api_sys_batch(
    request: Request,
    ids: str = "",
    cached: int = 1,
    user: str = Depends(require_login),
):
    """Batch node system snapshots for dashboard tiles.

    Use push-report cache by default to avoid many per-node requests.
    """
    _ = request
    use_cached = bool(cached)
    rows = filter_nodes_for_user(user, list_nodes_runtime())
    node_map: Dict[int, Dict[str, Any]] = {}
    for row in rows:
        try:
            nid = int((row or {}).get("id") or 0)
        except Exception:
            nid = 0
        if nid > 0:
            node_map[nid] = row

    want_ids = _parse_node_ids_csv(ids, limit=300)
    if not want_ids:
        want_ids = list(node_map.keys())
        want_ids.sort()
        if len(want_ids) > 300:
            want_ids = want_ids[:300]

    if not want_ids:
        return {"ok": True, "items": {}, "cached": use_cached}

    out: Dict[str, Any] = {}
    miss_ids: List[int] = []
    report_map: Dict[int, Dict[str, Any]] = {}

    if use_cached:
        for nid in want_ids:
            node = node_map.get(int(nid))
            if not isinstance(node, dict):
                continue
            marker = str((node or {}).get("last_seen_at") or "")
            hit = _sys_snapshot_cache_get(int(nid), use_cached, marker)
            if isinstance(hit, dict):
                out[str(int(nid))] = hit
            else:
                miss_ids.append(int(nid))
        if miss_ids:
            try:
                report_map = get_last_reports(miss_ids)
            except Exception:
                report_map = {}

    for nid in want_ids:
        key = str(int(nid))
        if key in out:
            continue
        node = node_map.get(int(nid))
        if not isinstance(node, dict):
            out[key] = {"ok": False, "error": "节点不存在或无权限"}
            continue
        marker = str((node or {}).get("last_seen_at") or "")
        rep_cache = report_map.get(int(nid)) if use_cached else None
        payload = await _build_api_sys_payload(int(nid), node, use_cached, report_cache=rep_cache)
        out[key] = payload
        if use_cached and isinstance(payload, dict):
            _sys_snapshot_cache_put(int(nid), use_cached, marker, payload)

    return {"ok": True, "items": out, "cached": use_cached}


@router.get("/api/nodes/{node_id}/graph")
async def api_graph(request: Request, node_id: int, user: str = Depends(require_login)):
    node = get_node(node_id)
    if not node:
        return JSONResponse({"ok": False, "error": "节点不存在"}, status_code=404)
    desired_ver, desired_pool = get_desired_pool(node_id)
    pool = desired_pool if isinstance(desired_pool, dict) else None

    rep_cache: Optional[Dict[str, Any]] = None
    last_pull_err = ""
    if pool is None:
        fresh = bool(is_report_fresh(node))
        for idx, source in enumerate(node_info_sources_order(force_pull=False)):
            if source == "report":
                if rep_cache is None:
                    rep_cache = get_last_report(node_id)
                if not (isinstance(rep_cache, dict) and isinstance(rep_cache.get("pool"), dict)):
                    continue
                allow_stale = idx > 0
                if fresh or allow_stale:
                    pool = rep_cache["pool"]
                    break
                continue
            try:
                target_base_url, target_verify_tls, _target_route = node_agent_request_target(node)
                data = await agent_get(target_base_url, node["api_key"], "/api/v1/pool", target_verify_tls)
                if isinstance(data, dict) and isinstance(data.get("pool"), dict):
                    pool = data.get("pool")
                    break
                if isinstance(data, dict):
                    last_pull_err = str(data.get("error") or "响应格式异常")
                else:
                    last_pull_err = "响应格式异常"
            except Exception as exc:
                last_pull_err = str(exc)

    if pool is None and isinstance(rep_cache, dict) and isinstance(rep_cache.get("pool"), dict):
        pool = rep_cache.get("pool")

    if pool is None:
        return JSONResponse({"ok": False, "error": last_pull_err or "暂无可用规则快照"}, status_code=502)

    if not isinstance(pool, dict):
        pool = {}
    pool = _filter_pool_for_user(user, pool)
    endpoints = pool.get("endpoints", []) if isinstance(pool, dict) else []
    elements: List[Dict[str, Any]] = []

    for idx, endpoint in enumerate(endpoints):
        listen = endpoint.get("listen", f"listen-{idx}")
        listen_id = f"listen-{idx}"
        classes = ["listen"]
        if endpoint.get("disabled"):
            classes.append("disabled")
        elements.append({"data": {"id": listen_id, "label": listen}, "classes": " ".join(classes)})

        remotes = endpoint.get("remotes") or ([endpoint.get("remote")] if endpoint.get("remote") else [])
        for r_idx, remote in enumerate(remotes):
            remote_id = f"remote-{idx}-{r_idx}"
            elements.append(
                {
                    "data": {"id": remote_id, "label": remote},
                    "classes": "remote" + (" disabled" if endpoint.get("disabled") else ""),
                }
            )
            ex = endpoint.get("extra_config") or {}
            edge_label = "WSS" if ex.get("listen_transport") == "ws" or ex.get("remote_transport") == "ws" else ""
            elements.append(
                {
                    "data": {"source": listen_id, "target": remote_id, "label": edge_label},
                    "classes": "disabled" if endpoint.get("disabled") else "",
                }
            )

    return {"ok": True, "elements": elements}


@router.post("/api/traffic/reset_all")
async def api_reset_all_traffic(request: Request, user: str = Depends(require_login)):
    """Reset rule traffic counters for all nodes.

    Strategy:
    - Try direct panel -> agent call first (retry once).
    - If direct call fails, queue a signed push-report command (agent -> panel),
      so private/unreachable nodes will reset next time they report.
    """
    nodes = filter_nodes_for_user(user, list_nodes())

    if not nodes:
        return {"ok": True, "total": 0, "ok_count": 0, "queued_count": 0, "fail_count": 0, "results": []}

    sem = asyncio.Semaphore(10)

    async def _direct(n: Dict[str, Any]) -> Dict[str, Any]:
        nid = int(n.get("id") or 0)
        name = n.get("name") or f"Node-{nid}"
        base_url, verify_tls, route = node_agent_request_target(n)
        api_key = n.get("api_key", "")

        # 1) Try direct reset (retry once)
        last_err: str = ""
        async with sem:
            for attempt in range(2):
                try:
                    data = await agent_post(
                        base_url,
                        api_key,
                        "/api/v1/traffic/reset",
                        {},
                        verify_tls,
                        timeout=10.0,
                    )
                    ok = bool((data or {}).get("ok", True)) if isinstance(data, dict) else True
                    return {
                        "node_id": nid,
                        "name": name,
                        "ok": ok,
                        "queued": False,
                        "route": str(route or "base_url"),
                        "detail": data if isinstance(data, dict) else {},
                    }
                except Exception as exc:
                    last_err = str(exc)
                    if attempt == 0:
                        await asyncio.sleep(0.2)

        # direct failed (exception)
        return {"node_id": nid, "name": name, "ok": False, "queued": False, "direct_error": last_err}

    direct_results = await asyncio.gather(*[_direct(n) for n in nodes])

    # 2) Queue fallback sequentially to avoid DB-lock contention
    results: List[Dict[str, Any]] = []
    for r in direct_results:
        if r.get("ok") or not r.get("direct_error"):
            results.append(r)
            continue

        nid = int(r.get("node_id") or 0)
        name = r.get("name") or f"Node-{nid}"
        last_err = str(r.get("direct_error") or "")
        try:
            new_ver = bump_traffic_reset_version(nid)
            results.append(
                {
                    "node_id": nid,
                    "name": name,
                    "ok": True,
                    "queued": True,
                    "desired_reset_version": new_ver,
                    "direct_error": last_err,
                }
            )
        except Exception as exc2:
            results.append(
                {"node_id": nid, "name": name, "ok": False, "queued": False, "error": f"{last_err}; queue failed: {exc2}"}
            )

    ok_count = sum(1 for r in results if r.get("ok") and not r.get("queued"))
    queued_count = sum(1 for r in results if r.get("ok") and r.get("queued"))
    fail_count = sum(1 for r in results if not r.get("ok"))

    return {
        "ok": True,
        "total": len(results),
        "ok_count": ok_count,
        "queued_count": queued_count,
        "fail_count": fail_count,
        "results": results,
    }
