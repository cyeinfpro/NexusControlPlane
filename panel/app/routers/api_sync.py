from __future__ import annotations

import asyncio
import json
import logging
import os
import secrets
import threading
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse

from ..auth import can_access_rule_endpoint, check_tunnel_access, get_user_by_username, is_rule_owner_scoped, stamp_endpoint_owner
from ..clients.agent import agent_get, agent_post
from ..core.bg_tasks import spawn_background_task
from ..core.deps import require_login
from ..db import get_last_report, get_node, list_nodes, set_desired_pool, upsert_rule_owner_map
from ..services.apply import node_agent_request_target, node_verify_tls, schedule_apply_pool
try:
    from ..services.panel_config import setting_bool, setting_float
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
from ..services.pool_ops import (
    choose_receiver_port,
    find_sync_listen_port,
    load_pool_for_node,
    node_host_for_realm,
    port_used_by_other_sync,
    remove_endpoints_by_sync_id,
    upsert_endpoint_by_sync_id,
)
from ..utils.normalize import format_addr, normalize_host_input, split_host_port
from ..utils.redact import mask_url, redact_log_text
from ..utils.validate import PoolValidationError, validate_pool_inplace

router = APIRouter()
logger = logging.getLogger(__name__)


def _coerce_int(v: Any, default: int = 0) -> int:
    try:
        return int(v)
    except Exception:
        try:
            return int(float(str(v).strip()))
        except Exception:
            return int(default)


def _coerce_float(v: Any, default: float = 0.0) -> float:
    try:
        return float(v)
    except Exception:
        try:
            return float(str(v).strip())
        except Exception:
            return float(default)


def _check_sync_policy(
    user: str,
    tunnel_type: str,
    action: str,
    sender_id: int,
    receiver_id: int,
) -> Optional[JSONResponse]:
    ok, msg, detail = check_tunnel_access(
        username=str(user or ""),
        tunnel_type=str(tunnel_type or ""),
        action=str(action or ""),
        sender_node_id=int(sender_id or 0),
        receiver_node_id=int(receiver_id or 0),
    )
    if ok:
        return None
    status = 429 if str(detail.get("code") or "") == "traffic_quota_exceeded" else 403
    body: Dict[str, Any] = {"ok": False, "error": str(msg or "权限不足")}
    if isinstance(detail, dict) and detail:
        body["policy"] = detail
    return JSONResponse(body, status_code=status)


def _resolve_rule_user(user_or_name: Any) -> Any:
    if isinstance(user_or_name, str):
        try:
            u = get_user_by_username(user_or_name)
            if u is not None:
                return u
        except Exception:
            return user_or_name
    return user_or_name


def _filter_pool_for_user(user: str, pool: Any) -> Dict[str, Any]:
    user_ref = _resolve_rule_user(user)
    if not isinstance(pool, dict):
        return {"endpoints": []}
    out = dict(pool)
    eps = out.get("endpoints")
    if not isinstance(eps, list):
        out["endpoints"] = []
        return out
    if not is_rule_owner_scoped(user_ref):
        return out
    out["endpoints"] = [ep for ep in eps if isinstance(ep, dict) and can_access_rule_endpoint(user_ref, ep)]
    return out


def _find_sync_endpoint(pool: Dict[str, Any], sync_id: str) -> Optional[Dict[str, Any]]:
    sid = str(sync_id or "").strip()
    if not sid or not isinstance(pool, dict):
        return None
    for ep in (pool.get("endpoints") or []):
        if not isinstance(ep, dict):
            continue
        ex = ep.get("extra_config")
        if not isinstance(ex, dict):
            continue
        if str(ex.get("sync_id") or "").strip() == sid:
            return ep
    return None


def _deny_if_sync_not_owned(user: str, sync_id: str, *pools: Dict[str, Any]) -> Optional[JSONResponse]:
    user_ref = _resolve_rule_user(user)
    if not is_rule_owner_scoped(user_ref):
        return None
    sid = str(sync_id or "").strip()
    if not sid:
        return None
    for pool in pools:
        ep = _find_sync_endpoint(pool, sid)
        if ep is None:
            continue
        if not can_access_rule_endpoint(user_ref, ep):
            return JSONResponse({"ok": False, "error": "仅可操作自己创建的规则"}, status_code=403)
    return None


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
        v = int(str(os.getenv(name, str(default))).strip() or default)
    except Exception:
        v = int(default)
    if v < lo:
        v = lo
    if v > hi:
        v = hi
    return int(v)


_SYNC_PRECHECK_ENABLED = _env_flag("REALM_SYNC_SAVE_PRECHECK_ENABLED", True)
_SYNC_PRECHECK_HTTP_TIMEOUT = _env_float("REALM_SYNC_SAVE_PRECHECK_HTTP_TIMEOUT", 4.5, 2.0, 20.0)
_SYNC_PRECHECK_PROBE_TIMEOUT = _env_float("REALM_SYNC_SAVE_PRECHECK_PROBE_TIMEOUT", 1.2, 0.2, 6.0)
_SYNC_APPLY_TIMEOUT = _env_float("REALM_SYNC_SAVE_APPLY_TIMEOUT", 6.0, 0.5, 20.0)
_SYNC_PRECHECK_MAX_ISSUES = 24
_INTRANET_FORCE_TLS_VERIFY = _env_flag("REALM_INTRANET_FORCE_TLS_VERIFY", True)
# Fail-open by default for better cross-network availability:
# when cert cannot be fetched, keep tunnel TLS but skip cert verification
# unless user explicitly requests strict verify for this save action.
_INTRANET_TLS_VERIFY_FAIL_OPEN = _env_flag("REALM_INTRANET_TLS_VERIFY_FAIL_OPEN", True)
_INTRANET_TOKEN_GRACE_SEC = _env_int("REALM_INTRANET_TOKEN_GRACE_SEC", 900, 0, 7 * 24 * 3600)
_INTRANET_TOKEN_GRACE_MAX = _env_int("REALM_INTRANET_TOKEN_GRACE_MAX", 4, 1, 16)
_WSS_RELAY_TUNNEL_PORT = _env_int("REALM_WSS_RELAY_TUNNEL_PORT", 28443, 1, 65535)
_MPTCP_FIXED_TUNNEL_PORT_ENABLED = _env_flag("REALM_MPTCP_FIXED_TUNNEL_PORT_ENABLED", True)
_MPTCP_TUNNEL_PORT = _env_int("REALM_MPTCP_TUNNEL_PORT", 38443, 1, 65535)

# Route B (MPTCP reusable tunnel group overlay)
# - A: fixed entry port (e.g. 38443) is the reusable entry
# - C: realm aggregator forwards to a local overlay exit proxy (default 127.0.0.1:38444)
# - D/others: normal rules can set forward_tool=overlay and tunnel through A's entry
_MPTCP_OVERLAY_EXIT_HOST_RAW = str(os.getenv("REALM_MPTCP_OVERLAY_EXIT_HOST", "127.0.0.1") or "127.0.0.1").strip()
_MPTCP_OVERLAY_EXIT_HOST = normalize_host_input(_MPTCP_OVERLAY_EXIT_HOST_RAW) if _MPTCP_OVERLAY_EXIT_HOST_RAW else "127.0.0.1"
_MPTCP_OVERLAY_EXIT_PORT = _env_int("REALM_MPTCP_OVERLAY_EXIT_PORT", 38444, 1, 65535)
_SYNC_JOB_TTL_SEC = _env_int("REALM_SYNC_JOB_TTL_SEC", 1800, 120, 7 * 24 * 3600)
_SYNC_JOB_ACTIVE_MAX_SEC = _env_float(
    "REALM_SYNC_JOB_ACTIVE_MAX_SEC",
    6 * 3600.0,
    float(_SYNC_JOB_TTL_SEC),
    7 * 24 * 3600.0,
)
_SYNC_JOB_MAX_ATTEMPTS = _env_int("REALM_SYNC_JOB_MAX_ATTEMPTS", 3, 1, 10)
_SYNC_JOB_RETRY_BASE_SEC = _env_float("REALM_SYNC_JOB_RETRY_BASE_SEC", 1.2, 0.2, 30.0)
_SYNC_JOB_RETRY_MAX_SEC = _env_float("REALM_SYNC_JOB_RETRY_MAX_SEC", 8.0, 1.0, 120.0)

_SYNC_JOBS: Dict[str, Dict[str, Any]] = {}
_SYNC_JOBS_LOCK = threading.Lock()
_SYNC_EXEC_LOCK = asyncio.Lock()


def _sync_precheck_enabled() -> bool:
    return bool(setting_bool("sync_precheck_enabled", default=bool(_SYNC_PRECHECK_ENABLED)))


def _sync_precheck_http_timeout() -> float:
    return float(
        setting_float(
            "sync_precheck_http_timeout",
            default=float(_SYNC_PRECHECK_HTTP_TIMEOUT),
            lo=2.0,
            hi=20.0,
        )
    )


def _sync_precheck_probe_timeout() -> float:
    return float(
        setting_float(
            "sync_precheck_probe_timeout",
            default=float(_SYNC_PRECHECK_PROBE_TIMEOUT),
            lo=0.2,
            hi=6.0,
        )
    )


def _sync_apply_timeout() -> float:
    return float(
        setting_float(
            "sync_apply_timeout",
            default=float(_SYNC_APPLY_TIMEOUT),
            lo=0.5,
            hi=20.0,
        )
    )


def _sync_job_now() -> float:
    return float(time.time())


def _prune_sync_jobs_locked(now_ts: Optional[float] = None) -> None:
    now = float(now_ts if now_ts is not None else _sync_job_now())
    stale_ids: List[str] = []
    for jid, job in _SYNC_JOBS.items():
        st = str(job.get("status") or "")
        created = _coerce_float(job.get("created_at"), 0.0)
        updated = _coerce_float(job.get("updated_at"), 0.0)
        if st in ("queued", "running", "retrying") and created > 0 and (now - created) > float(_SYNC_JOB_ACTIVE_MAX_SEC):
            stale_ids.append(jid)
            continue
        if st in ("success", "error") and (now - updated) > float(_SYNC_JOB_TTL_SEC):
            stale_ids.append(jid)
    for jid in stale_ids:
        _SYNC_JOBS.pop(jid, None)


def _sync_job_public_view(job: Dict[str, Any], include_result: bool = True) -> Dict[str, Any]:
    meta = job.get("meta")
    out: Dict[str, Any] = {
        "job_id": str(job.get("job_id") or ""),
        "kind": str(job.get("kind") or ""),
        "status": str(job.get("status") or ""),
        "created_at": _coerce_float(job.get("created_at"), 0.0),
        "updated_at": _coerce_float(job.get("updated_at"), 0.0),
        "attempts": _coerce_int(job.get("attempts"), 0),
        "max_attempts": _coerce_int(job.get("max_attempts"), 0),
        "next_retry_at": _coerce_float(job.get("next_retry_at"), 0.0),
        "error": str(job.get("error") or ""),
        "status_code": _coerce_int(job.get("status_code"), 0),
        "meta": dict(meta) if isinstance(meta, dict) else {},
    }
    if include_result:
        res = job.get("result")
        out["result"] = dict(res) if isinstance(res, dict) else {}
    return out


def _sync_job_parse_json_response(resp: JSONResponse) -> Dict[str, Any]:
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


def _sync_job_error_text(data: Any, fallback: str = "同步失败") -> str:
    if isinstance(data, dict):
        msg = str(data.get("error") or "").strip()
        if msg:
            return msg
    txt = str(data or "").strip()
    return txt or fallback


def _sync_job_is_retriable(status_code: int, data: Dict[str, Any]) -> bool:
    if status_code <= 0:
        return True
    if status_code >= 500:
        return True
    if status_code == 409 and isinstance(data, dict):
        issues409 = data.get("issues")
        if isinstance(issues409, list):
            for it in issues409[:16]:
                if not isinstance(it, dict):
                    continue
                if str(it.get("code") or "").strip().lower() == "target_unreachable":
                    return False
    if status_code in (408, 409, 425, 429):
        return True
    # "precheck_unreachable" is often transient network jitter.
    if isinstance(data, dict):
        issues = data.get("precheck", {}).get("issues") if isinstance(data.get("precheck"), dict) else []
        if isinstance(issues, list):
            for it in issues[:8]:
                if not isinstance(it, dict):
                    continue
                if str(it.get("code") or "").strip() == "precheck_unreachable":
                    return True
    return False


def _sync_job_set(job_id: str, **kwargs: Any) -> None:
    now = _sync_job_now()
    with _SYNC_JOBS_LOCK:
        job = _SYNC_JOBS.get(job_id)
        if not isinstance(job, dict):
            return
        for k, v in kwargs.items():
            job[k] = v
        job["updated_at"] = now


def _sync_job_get(job_id: str) -> Optional[Dict[str, Any]]:
    with _SYNC_JOBS_LOCK:
        _prune_sync_jobs_locked()
        job = _SYNC_JOBS.get(job_id)
        if not isinstance(job, dict):
            return None
        return dict(job)


async def _sync_job_invoke(kind: str, payload: Dict[str, Any], user: str) -> Tuple[int, Dict[str, Any]]:
    if kind == "wss_save":
        payload2 = dict(payload) if isinstance(payload, dict) else {}
        payload2["_async_job"] = True
        ret = await api_wss_tunnel_save(payload2, user=user)
    elif kind == "mptcp_save":
        payload2 = dict(payload) if isinstance(payload, dict) else {}
        payload2["_async_job"] = True
        ret = await api_mptcp_tunnel_save(payload2, user=user)
    elif kind == "intranet_save":
        payload2 = dict(payload) if isinstance(payload, dict) else {}
        payload2["_async_job"] = True
        ret = await api_intranet_tunnel_save(payload2, user=user)
    elif kind == "wss_delete":
        payload2 = dict(payload) if isinstance(payload, dict) else {}
        payload2["_async_job"] = True
        ret = await api_wss_tunnel_delete(payload2, user=user)
    elif kind == "mptcp_delete":
        payload2 = dict(payload) if isinstance(payload, dict) else {}
        payload2["_async_job"] = True
        ret = await api_mptcp_tunnel_delete(payload2, user=user)
    elif kind == "mptcp_group_update":
        payload2 = dict(payload) if isinstance(payload, dict) else {}
        payload2["_async_job"] = True
        ret = await api_mptcp_tunnel_group_update(payload2, user=user)
    elif kind == "intranet_delete":
        payload2 = dict(payload) if isinstance(payload, dict) else {}
        payload2["_async_job"] = True
        ret = await api_intranet_tunnel_delete(payload2, user=user)
    else:
        return 400, {"ok": False, "error": f"unsupported_job_kind:{kind}"}

    if isinstance(ret, JSONResponse):
        status = int(ret.status_code or 500)
        data = _sync_job_parse_json_response(ret)
        if "ok" not in data:
            data["ok"] = status < 400
        return status, data

    if isinstance(ret, dict):
        ok = bool(ret.get("ok", True))
        return (200 if ok else 500), ret

    return 500, {"ok": False, "error": "unknown_response_type"}


async def _sync_job_runner(job_id: str) -> None:
    snap = _sync_job_get(job_id)
    if not isinstance(snap, dict):
        return
    kind = str(snap.get("kind") or "")
    payload = snap.get("_payload") if isinstance(snap.get("_payload"), dict) else {}
    user = str(snap.get("_user") or "").strip() or "system"
    max_attempts = int(snap.get("max_attempts") or _SYNC_JOB_MAX_ATTEMPTS)
    max_attempts = max(1, max_attempts)

    for attempt in range(1, max_attempts + 1):
        _sync_job_set(job_id, status="running", attempts=int(attempt), next_retry_at=0.0, error="", status_code=0)
        status_code = 0
        data: Dict[str, Any] = {}
        try:
            async with _SYNC_EXEC_LOCK:
                status_code, data = await _sync_job_invoke(kind, payload, user)
        except Exception as exc:
            status_code = 599
            data = {"ok": False, "error": f"任务执行异常：{_safe_exception_text(exc)}"}

        ok = bool(isinstance(data, dict) and data.get("ok") is True and status_code < 400)
        if ok:
            _sync_job_set(
                job_id,
                status="success",
                status_code=int(status_code),
                result=data,
                error="",
                next_retry_at=0.0,
            )
            return

        err = _sync_job_error_text(data, "同步失败")
        retriable = _sync_job_is_retriable(int(status_code), data if isinstance(data, dict) else {})
        if attempt < max_attempts and retriable:
            delay = min(float(_SYNC_JOB_RETRY_MAX_SEC), float(_SYNC_JOB_RETRY_BASE_SEC) * (2 ** (attempt - 1)))
            _sync_job_set(
                job_id,
                status="retrying",
                status_code=int(status_code),
                result=data if isinstance(data, dict) else {},
                error=err,
                next_retry_at=float(_sync_job_now() + delay),
            )
            await asyncio.sleep(max(0.2, delay))
            continue

        _sync_job_set(
            job_id,
            status="error",
            status_code=int(status_code),
            result=data if isinstance(data, dict) else {},
            error=err,
            next_retry_at=0.0,
        )
        return


def _sync_job_enqueue(kind: str, payload: Dict[str, Any], user: str) -> Dict[str, Any]:
    payload_d = payload if isinstance(payload, dict) else {}

    def _as_int(v: Any, default: int = 0) -> int:
        try:
            return int(v)
        except Exception:
            return int(default)

    now = _sync_job_now()
    job_id = uuid.uuid4().hex
    receiver_id = _as_int(payload_d.get("receiver_node_id"), 0)
    if receiver_id <= 0:
        receiver_id = _as_int(payload_d.get("aggregator_node_id"), 0)
    member_ids_raw = payload_d.get("member_node_ids")
    member_count = 0
    if isinstance(member_ids_raw, list):
        member_count = len(
            [1 for x in member_ids_raw if _as_int(x, 0) > 0]
        )
    meta = {
        "sender_node_id": _as_int(payload_d.get("sender_node_id"), 0),
        "receiver_node_id": int(receiver_id),
        "sync_id": str(payload_d.get("sync_id") or "").strip(),
        "listen": str(payload_d.get("listen") or "").strip(),
        "member_count": int(member_count),
    }
    job = {
        "job_id": job_id,
        "kind": str(kind),
        "status": "queued",
        "created_at": now,
        "updated_at": now,
        "attempts": 0,
        "max_attempts": int(_SYNC_JOB_MAX_ATTEMPTS),
        "next_retry_at": 0.0,
        "status_code": 0,
        "error": "",
        "result": {},
        "meta": meta,
        "_payload": dict(payload_d),
        "_user": str(user or "system"),
    }
    with _SYNC_JOBS_LOCK:
        _prune_sync_jobs_locked(now)
        _SYNC_JOBS[job_id] = job
    try:
        spawn_background_task(_sync_job_runner(job_id), label="sync-job")
    except Exception as exc:
        _sync_job_set(
            job_id,
            status="error",
            status_code=500,
            error=f"任务调度失败：{exc}",
            next_retry_at=0.0,
        )
    return _sync_job_public_view(job, include_result=False)


def random_wss_params() -> Tuple[str, str, str]:
    """Generate a reasonable random WSS {host, path, sni}."""
    hosts = [
        "cdn.jsdelivr.net",
        "assets.cloudflare.com",
        "edge.microsoft.com",
        "static.cloudflareinsights.com",
        "ajax.googleapis.com",
        "fonts.gstatic.com",
        "images.unsplash.com",
        "cdn.discordapp.com",
    ]
    path_templates = [
        "/ws",
        "/ws/{token}",
        "/socket",
        "/socket/{token}",
        "/connect",
        "/gateway",
        "/api/ws",
        "/v1/ws/{token}",
        "/edge/{token}",
    ]

    host = secrets.choice(hosts)
    token = secrets.token_hex(5)
    tpl = secrets.choice(path_templates)
    path = str(tpl or "/ws").replace("{token}", token)
    if path and not path.startswith("/"):
        path = "/" + path
    sni = host
    return host, path, sni


def _qos_has_value(v: Any) -> bool:
    return v is not None and str(v).strip() != ""


def _coerce_nonneg_int(v: Any) -> Optional[int]:
    if v is None:
        return None
    if isinstance(v, bool):
        return None
    if isinstance(v, int):
        return int(v) if int(v) >= 0 else None
    if isinstance(v, float):
        if not float(v).is_integer():
            return None
        iv = int(v)
        return iv if iv >= 0 else None
    s = str(v).strip()
    if not s or not s.isdigit():
        return None
    try:
        iv = int(s)
    except Exception:
        return None
    return iv if iv >= 0 else None


def _pick_qos_raw(sources: List[Dict[str, Any]], keys: Tuple[str, ...]) -> Any:
    for src in sources:
        if not isinstance(src, dict):
            continue
        for k in keys:
            if k in src:
                return src.get(k)
    return None


def _normalize_qos_from_sources(sources: List[Dict[str, Any]], strict: bool) -> Tuple[Dict[str, int], Optional[str]]:
    bw_kbps_raw = _pick_qos_raw(sources, ("bandwidth_kbps", "bandwidth_kbit", "bandwidth_limit_kbps", "qos_bandwidth_kbps"))
    bw_mbps_raw = _pick_qos_raw(sources, ("bandwidth_mbps", "bandwidth_mb", "bandwidth_limit_mbps", "qos_bandwidth_mbps"))
    max_conns_raw = _pick_qos_raw(sources, ("max_conns", "max_conn", "max_connections", "qos_max_conns"))
    conn_rate_raw = _pick_qos_raw(
        sources, ("conn_rate", "conn_per_sec", "new_conn_per_sec", "new_connections_per_sec", "qos_conn_rate")
    )
    traffic_bytes_raw = _pick_qos_raw(
        sources, ("traffic_total_bytes", "traffic_bytes", "traffic_limit_bytes", "qos_traffic_total_bytes")
    )
    traffic_gb_raw = _pick_qos_raw(
        sources, ("traffic_total_gb", "traffic_gb", "traffic_limit_gb", "qos_traffic_total_gb")
    )

    bw_kbps = _coerce_nonneg_int(bw_kbps_raw)
    bw_mbps = _coerce_nonneg_int(bw_mbps_raw)
    max_conns = _coerce_nonneg_int(max_conns_raw)
    conn_rate = _coerce_nonneg_int(conn_rate_raw)
    traffic_bytes = _coerce_nonneg_int(traffic_bytes_raw)
    traffic_gb = _coerce_nonneg_int(traffic_gb_raw)

    if strict:
        if bw_kbps is None and _qos_has_value(bw_kbps_raw):
            return {}, "qos.bandwidth_kbps 必须是非负整数"
        if bw_mbps is None and _qos_has_value(bw_mbps_raw):
            return {}, "qos.bandwidth_mbps 必须是非负整数"
        if max_conns is None and _qos_has_value(max_conns_raw):
            return {}, "qos.max_conns 必须是非负整数"
        if conn_rate is None and _qos_has_value(conn_rate_raw):
            return {}, "qos.conn_rate 必须是非负整数"
        if traffic_bytes is None and _qos_has_value(traffic_bytes_raw):
            return {}, "qos.traffic_total_bytes 必须是非负整数"
        if traffic_gb is None and _qos_has_value(traffic_gb_raw):
            return {}, "qos.traffic_total_gb 必须是非负整数"

    if bw_kbps is None and bw_mbps is not None:
        bw_kbps = int(bw_mbps) * 1024
    if traffic_bytes is None and traffic_gb is not None:
        traffic_bytes = int(traffic_gb) * 1024 * 1024 * 1024

    qos: Dict[str, int] = {}
    if bw_kbps is not None and bw_kbps > 0:
        qos["bandwidth_kbps"] = int(bw_kbps)
    if max_conns is not None and max_conns > 0:
        qos["max_conns"] = int(max_conns)
    if conn_rate is not None and conn_rate > 0:
        qos["conn_rate"] = int(conn_rate)
    if traffic_bytes is not None and traffic_bytes > 0:
        qos["traffic_total_bytes"] = int(traffic_bytes)
    return qos, None


def _normalize_qos_payload(raw: Any) -> Tuple[Dict[str, int], Optional[str]]:
    if raw is None:
        return {}, None
    if not isinstance(raw, dict):
        return {}, "qos 参数格式无效，应为对象"
    return _normalize_qos_from_sources([raw], strict=True)


def _extract_qos_from_endpoint(ep: Dict[str, Any]) -> Dict[str, int]:
    if not isinstance(ep, dict):
        return {}
    ex = ep.get("extra_config")
    if not isinstance(ex, dict):
        ex = {}
    net = ep.get("network")
    if not isinstance(net, dict):
        net = {}
    ex_qos = ex.get("qos")
    if not isinstance(ex_qos, dict):
        ex_qos = {}
    net_qos = net.get("qos")
    if not isinstance(net_qos, dict):
        net_qos = {}
    qos, _ = _normalize_qos_from_sources([ex_qos, net_qos, ex, net, ep], strict=False)
    return qos


def _find_sync_qos(pool: Dict[str, Any], sync_id: str) -> Dict[str, int]:
    sid = str(sync_id or "").strip()
    if not sid:
        return {}
    try:
        for ep in (pool or {}).get("endpoints") or []:
            if not isinstance(ep, dict):
                continue
            ex0 = ep.get("extra_config") or {}
            if not isinstance(ex0, dict):
                continue
            if str(ex0.get("sync_id") or "") != sid:
                continue
            qos = _extract_qos_from_endpoint(ep)
            if qos:
                return qos
    except Exception:
        return {}
    return {}


def _split_to_list(raw: Any, max_items: int = 128, item_max_len: int = 128) -> List[str]:
    rows: List[Any]
    if isinstance(raw, list):
        rows = raw
    elif isinstance(raw, str):
        rows = [x for x in str(raw).replace(",", "\n").splitlines()]
    else:
        rows = []
    out: List[str] = []
    seen: set[str] = set()
    for row in rows:
        s = str(row or "").strip()
        if not s:
            continue
        if len(s) > item_max_len:
            s = s[:item_max_len]
        if s in seen:
            continue
        seen.add(s)
        out.append(s)
        if len(out) >= max_items:
            break
    return out


def _normalize_acl_hours(raw: Any) -> Tuple[List[str], Optional[str]]:
    rows = _split_to_list(raw, max_items=16, item_max_len=16)
    out: List[str] = []
    for row in rows:
        txt = str(row or "").strip()
        if "-" not in txt:
            return [], f"ACL 时间窗格式无效：{txt}"
        left, right = txt.split("-", 1)
        left = left.strip()
        right = right.strip()
        if ":" not in left or ":" not in right:
            return [], f"ACL 时间窗格式无效：{txt}"
        lh, lm = left.split(":", 1)
        rh, rm = right.split(":", 1)
        if (not lh.isdigit()) or (not lm.isdigit()) or (not rh.isdigit()) or (not rm.isdigit()):
            return [], f"ACL 时间窗格式无效：{txt}"
        ih, im, jh, jm = int(lh), int(lm), int(rh), int(rm)
        if ih < 0 or ih > 23 or im < 0 or im > 59 or jh < 0 or jh > 23 or jm < 0 or jm > 59:
            return [], f"ACL 时间窗超出范围：{txt}"
        out.append(f"{ih:02d}:{im:02d}-{jh:02d}:{jm:02d}")
    return out, None


def _normalize_intranet_acl_payload(raw: Any) -> Tuple[Dict[str, Any], Optional[str]]:
    if raw is None:
        return {}, None
    if not isinstance(raw, dict):
        return {}, "ACL 参数格式无效，应为对象"
    allow_sources = _split_to_list(raw.get("allow_sources"), max_items=128, item_max_len=64)
    deny_sources = _split_to_list(raw.get("deny_sources"), max_items=128, item_max_len=64)
    allow_tokens = _split_to_list(raw.get("allow_tokens"), max_items=64, item_max_len=96)
    allow_hours, hour_err = _normalize_acl_hours(raw.get("allow_hours"))
    if hour_err:
        return {}, hour_err
    acl: Dict[str, Any] = {}
    if allow_sources:
        acl["allow_sources"] = allow_sources
    if deny_sources:
        acl["deny_sources"] = deny_sources
    if allow_hours:
        acl["allow_hours"] = allow_hours
    if allow_tokens:
        acl["allow_tokens"] = allow_tokens
    return acl, None


def _find_sync_intranet_acl(pool: Dict[str, Any], sync_id: str) -> Dict[str, Any]:
    sid = str(sync_id or "").strip()
    if not sid:
        return {}
    try:
        for ep in (pool or {}).get("endpoints") or []:
            if not isinstance(ep, dict):
                continue
            ex0 = ep.get("extra_config") or {}
            if not isinstance(ex0, dict):
                continue
            if str(ex0.get("sync_id") or "") != sid:
                continue
            acl0 = ex0.get("intranet_acl")
            if isinstance(acl0, dict):
                acl, _ = _normalize_intranet_acl_payload(acl0)
                if acl:
                    return acl
    except Exception:
        return {}
    return {}


def _normalize_intranet_token_grace(raw: Any, now_ts: int) -> List[Dict[str, int]]:
    rows = raw if isinstance(raw, list) else []
    latest: Dict[str, int] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        tok = str(row.get("token") or "").strip()
        if not tok:
            continue
        try:
            exp = int(row.get("expires_at") or 0)
        except Exception:
            exp = 0
        if exp <= now_ts:
            continue
        old = int(latest.get(tok) or 0)
        if exp > old:
            latest[tok] = int(exp)

    ordered = sorted(latest.items(), key=lambda it: int(it[1]), reverse=True)
    out: List[Dict[str, int]] = []
    for tok, exp in ordered[: _INTRANET_TOKEN_GRACE_MAX]:
        out.append({"token": tok, "expires_at": int(exp)})
    return out


def _extract_intranet_token_meta(pool: Dict[str, Any], sync_id: str, now_ts: int) -> Tuple[str, List[Dict[str, int]]]:
    sid = str(sync_id or "").strip()
    if not sid:
        return "", []

    candidate_ex: List[Dict[str, Any]] = []
    try:
        for ep in (pool or {}).get("endpoints") or []:
            if not isinstance(ep, dict):
                continue
            ex0 = ep.get("extra_config") or {}
            if not isinstance(ex0, dict):
                continue
            if str(ex0.get("sync_id") or "") != sid:
                continue
            candidate_ex.append(ex0)
    except Exception:
        return "", []

    # Prefer server side metadata when available.
    candidate_ex.sort(key=lambda ex: 0 if str(ex.get("intranet_role") or "") == "server" else 1)
    for ex in candidate_ex:
        primary = str(ex.get("intranet_token") or "").strip()
        grace = _normalize_intranet_token_grace(ex.get("intranet_token_grace"), now_ts)
        if primary or grace:
            return primary, grace
    return "", []


def _build_intranet_tokens(
    primary_token: str,
    previous_primary: str,
    previous_grace: List[Dict[str, int]],
    now_ts: int,
) -> Tuple[List[str], List[Dict[str, int]]]:
    grace = _normalize_intranet_token_grace(previous_grace, now_ts)
    prev = str(previous_primary or "").strip()
    cur = str(primary_token or "").strip()
    if prev and cur and prev != cur and _INTRANET_TOKEN_GRACE_SEC > 0:
        grace.append({"token": prev, "expires_at": int(now_ts + _INTRANET_TOKEN_GRACE_SEC)})
        grace = _normalize_intranet_token_grace(grace, now_ts)

    tokens: List[str] = []
    seen: set[str] = set()
    for tok in [cur] + [str(it.get("token") or "").strip() for it in grace]:
        if not tok or tok in seen:
            continue
        seen.add(tok)
        tokens.append(tok)
    return tokens, grace


def _issue_key(issue: Dict[str, Any]) -> str:
    return (
        f"{issue.get('path') or ''}|{issue.get('code') or ''}|"
        f"{issue.get('severity') or ''}|{issue.get('message') or ''}"
    )


async def _apply_pool_best_effort(node: Dict[str, Any], pool: Dict[str, Any]) -> None:
    apply_timeout = _sync_apply_timeout()
    target_base_url, target_verify_tls, _target_route = node_agent_request_target(node)
    try:
        data = await agent_post(
            target_base_url,
            node.get("api_key", ""),
            "/api/v1/pool",
            {"pool": pool},
            target_verify_tls,
            timeout=apply_timeout,
        )
        if isinstance(data, dict) and data.get("ok", True):
            await agent_post(
                target_base_url,
                node.get("api_key", ""),
                "/api/v1/apply",
                {},
                target_verify_tls,
                timeout=apply_timeout,
            )
    except Exception:
        pass


async def _apply_pools_best_effort(items: List[Tuple[Dict[str, Any], Dict[str, Any]]]) -> None:
    tasks = []
    for node, pool in items:
        if isinstance(node, dict) and isinstance(pool, dict):
            tasks.append(_apply_pool_best_effort(node, pool))
    if not tasks:
        return
    await asyncio.gather(*tasks, return_exceptions=True)


def _append_issue(
    issues: List[Dict[str, Any]],
    seen: set[str],
    issue: Dict[str, Any],
    limit: int = _SYNC_PRECHECK_MAX_ISSUES,
) -> None:
    k = _issue_key(issue)
    if k in seen:
        return
    if len(issues) >= limit:
        return
    seen.add(k)
    issues.append(issue)


def _safe_error_text(data: Any, default: str = "unknown") -> str:
    if isinstance(data, dict):
        msg = str(data.get("error") or "").strip()
        return msg or default
    msg = str(data or "").strip()
    return msg or default


def _safe_exception_text(exc: Any, default: str = "unknown_error") -> str:
    if exc is None:
        return default
    msg = str(exc or "").strip()
    cls_name = str(getattr(getattr(exc, "__class__", None), "__name__", "") or "").strip()
    if msg and cls_name and msg.lower() != cls_name.lower():
        return f"{cls_name}: {msg}"
    if msg:
        return msg
    if cls_name:
        return cls_name
    return default


def _agent_request_error_hint(text: str) -> str:
    low = str(text or "").lower()
    if not low:
        return ""
    if ("readtimeout" in low) or ("connecttimeout" in low) or ("timeout" in low) or ("timed out" in low):
        return "请求超时（节点可能离线或网络延迟过高）"
    if (
        ("connecterror" in low)
        or ("connection refused" in low)
        or ("name or service not known" in low)
        or ("nodename nor servname provided" in low)
        or ("network is unreachable" in low)
    ):
        return "连接失败（请检查节点 base_url、端口和防火墙）"
    if ("ssl" in low) or ("tls" in low) or ("certificate" in low):
        return "TLS 校验失败（证书不受信或 verify_tls 配置不匹配）"
    return ""


def _format_agent_request_failure(
    node: Dict[str, Any],
    path: str,
    exc: Any,
    timeout_sec: Optional[float],
    target_base_url: Optional[str] = None,
    target_verify_tls: Optional[bool] = None,
    target_route: Optional[str] = None,
) -> str:
    err_txt = _safe_exception_text(exc)
    hint = _agent_request_error_hint(err_txt)
    extras: List[str] = []
    if hint:
        extras.append(hint)
    if timeout_sec is not None and float(timeout_sec) > 0:
        extras.append(f"timeout={float(timeout_sec):.1f}s")
    base_url_raw = str(target_base_url or "").strip() or str(node.get("base_url") or "").strip()
    base_url = mask_url(base_url_raw)
    if base_url:
        extras.append(f"base_url={base_url}")
    verify = node_verify_tls(node) if target_verify_tls is None else bool(target_verify_tls)
    extras.append(f"verify_tls={'on' if verify else 'off'}")
    route = str(target_route or "").strip().lower()
    if route:
        extras.append(f"route={route}")
    if extras:
        err_txt = f"{err_txt}（{'；'.join(extras)}）"
    return f"{path} 请求失败：{err_txt}"


async def _apply_pool_strict(node: Dict[str, Any], pool: Dict[str, Any]) -> Tuple[bool, str]:
    apply_timeout = _sync_apply_timeout()
    target_base_url, target_verify_tls, target_route = node_agent_request_target(node)
    api_key = str(node.get("api_key") or "").strip()
    try:
        data = await agent_post(
            target_base_url,
            api_key,
            "/api/v1/pool",
            {"pool": pool},
            target_verify_tls,
            timeout=apply_timeout,
        )
    except Exception as exc:
        return False, _format_agent_request_failure(
            node,
            "/api/v1/pool",
            exc,
            apply_timeout,
            target_base_url=target_base_url,
            target_verify_tls=target_verify_tls,
            target_route=target_route,
        )
    if not (isinstance(data, dict) and bool(data.get("ok", False))):
        return False, f"/api/v1/pool 返回失败：{_safe_error_text(data)}"

    try:
        data2 = await agent_post(
            target_base_url,
            api_key,
            "/api/v1/apply",
            {},
            target_verify_tls,
            timeout=apply_timeout,
        )
    except Exception as exc:
        return False, _format_agent_request_failure(
            node,
            "/api/v1/apply",
            exc,
            apply_timeout,
            target_base_url=target_base_url,
            target_verify_tls=target_verify_tls,
            target_route=target_route,
        )
    if not (isinstance(data2, dict) and bool(data2.get("ok", False))):
        return False, f"/api/v1/apply 返回失败：{_safe_error_text(data2)}"
    return True, ""


async def _apply_pools_strict(items: List[Tuple[Dict[str, Any], Dict[str, Any]]]) -> List[Dict[str, Any]]:
    run_items: List[Tuple[Dict[str, Any], Dict[str, Any]]] = []
    for node, pool in items:
        if isinstance(node, dict) and isinstance(pool, dict):
            run_items.append((node, pool))
    if not run_items:
        return []

    tasks = [_apply_pool_strict(node, pool) for node, pool in run_items]
    results = await asyncio.gather(*tasks, return_exceptions=False)

    errors: List[Dict[str, Any]] = []
    for i, res in enumerate(results):
        ok, err = res
        if ok:
            continue
        node = run_items[i][0]
        node_id = _coerce_int(node.get("id"), 0)
        node_name = str(node.get("name") or "").strip()
        errors.append(
            {
                "node_id": int(node_id),
                "node_name": node_name,
                "error": str(err or "apply_failed"),
            }
        )
    return errors


def _is_apply_transport_failure(err: Any) -> bool:
    txt = str(err or "").strip().lower()
    if not txt:
        return False
    if "请求失败" not in txt:
        return False
    return ("/api/v1/pool" in txt) or ("/api/v1/apply" in txt)


def _queue_apply_via_report(node_id: int, pool: Dict[str, Any]) -> Tuple[bool, int, str]:
    try:
        ver, _ = set_desired_pool(int(node_id), pool)
        return True, int(ver), ""
    except Exception as exc:
        return False, 0, _safe_exception_text(exc)


def _intranet_cert_fetch_hint(detail: str) -> str:
    d = str(detail or "").strip()
    if not d:
        return "cert_empty"
    low = d.lower()
    if d == "cert_fetch_failed":
        return "面板请求 A 节点证书接口失败（请检查 panel 日志）"
    if d == "report_cache_missing":
        return "A 节点近期未上报，证书缓存不存在"
    if d == "report_cache_intranet_missing":
        return "A 节点上报中缺少内网证书信息（可能 Agent 版本过旧）"
    if d == "report_cache_cert_missing":
        return "A 节点上报中未包含可用证书（请稍后重试）"
    if d == "tls_cert_missing":
        return "A 节点未生成内网穿透 TLS 证书（通常是 openssl 缺失）"
    if d == "tls_context_unavailable":
        return "A 节点 TLS 证书或私钥不可用（可重启 Agent 后重试）"
    if ("certificate verify failed" in low) or ("certificat" in low and "verify" in low):
        return "A 节点启用了 HTTPS 且开启证书校验，但证书不受信任（可改用有效证书或关闭该节点 TLS 校验）"
    if ("invalid api key" in low) or ("api key 无效" in low) or ("401" in low) or ("403" in low):
        return "A 节点 API Key 校验失败，请重新接入节点或更新 API Key"
    if "命中了站点 nginx 页面而不是 agent api" in low:
        return "A 节点 base_url 命中了站点端口，请改为 Agent 地址/端口（默认 :18700）"
    if ("connection refused" in low) or ("timed out" in low) or ("timeout" in low) or ("connect" in low):
        return "面板无法访问 A 节点 Agent API，请检查 base_url、端口和防火墙"
    if len(d) > 200:
        return d[:200] + "…"
    return d


def _sender_cert_from_report_cache(node_id: int) -> Tuple[str, str]:
    try:
        report = get_last_report(int(node_id))
    except Exception:
        report = None
    if not isinstance(report, dict):
        return "", "report_cache_missing"
    intr = report.get("intranet")
    if not isinstance(intr, dict):
        return "", "report_cache_intranet_missing"
    pem = str(intr.get("cert_pem") or "").strip()
    ready = bool(intr.get("tls_ready", False))
    if pem and ready:
        return pem, ""
    err = str(intr.get("cert_error") or "").strip()
    if err:
        return "", err
    if pem and (not ready):
        return "", "tls_context_unavailable"
    return "", "report_cache_cert_missing"


def _intranet_cert_from_existing_receiver_pool(pool: Dict[str, Any], sync_id: str) -> str:
    sid = str(sync_id or "").strip()
    if not sid:
        return ""
    try:
        for ep in (pool or {}).get("endpoints") or []:
            if not isinstance(ep, dict):
                continue
            ex = ep.get("extra_config") or {}
            if not isinstance(ex, dict):
                continue
            if str(ex.get("sync_id") or "").strip() != sid:
                continue
            role = str(ex.get("intranet_role") or "").strip().lower()
            if role != "client":
                continue
            pem = str(ex.get("intranet_server_cert_pem") or "").strip()
            if pem:
                return pem
    except Exception:
        return ""
    return ""


def _pool_rules_for_probe(pool: Dict[str, Any], only_sync_id: str = "") -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    sid = str(only_sync_id or "").strip()
    eps = pool.get("endpoints") if isinstance(pool.get("endpoints"), list) else []
    if not isinstance(eps, list):
        return out
    for ep in eps[:160]:
        if not isinstance(ep, dict):
            continue
        ex0 = ep.get("extra_config")
        if sid:
            exd = ex0 if isinstance(ex0, dict) else {}
            ep_sid = str(exd.get("sync_id") or "").strip()
            if ep_sid != sid:
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
        if isinstance(ex0, dict):
            item["extra_config"] = ex0
        out.append(item)
    return out


async def _probe_node_rules_precheck(
    node: Dict[str, Any],
    pool: Dict[str, Any],
    node_label: str,
    force: bool = False,
    only_sync_id: str = "",
) -> List[Dict[str, Any]]:
    precheck_enabled = _sync_precheck_enabled()
    if (not precheck_enabled) and (not bool(force)):
        return []

    rules_payload = _pool_rules_for_probe(pool, only_sync_id=only_sync_id)
    if not rules_payload:
        return []

    issues: List[Dict[str, Any]] = []
    seen: set[str] = set()
    body = {"mode": "rules", "rules": rules_payload, "timeout": _sync_precheck_probe_timeout()}
    target_base_url, target_verify_tls, target_route = node_agent_request_target(node)

    try:
        data = await agent_post(
            target_base_url,
            node.get("api_key", ""),
            "/api/v1/netprobe",
            body,
            target_verify_tls,
            timeout=_sync_precheck_http_timeout(),
        )
    except Exception as exc:
        req_err = _format_agent_request_failure(
            node,
            "/api/v1/netprobe",
            exc,
            _sync_precheck_http_timeout(),
            target_base_url=target_base_url,
            target_verify_tls=target_verify_tls,
            target_route=target_route,
        )
        _append_issue(
            issues,
            seen,
            {
                "path": "endpoints",
                "message": f"{node_label}预检失败：{req_err}",
                "severity": "warning",
                "code": "precheck_unreachable",
            },
        )
        return issues

    if not isinstance(data, dict) or data.get("ok") is not True:
        _append_issue(
            issues,
            seen,
            {
                "path": "endpoints",
                "message": f"{node_label}预检失败：Agent rules 探测返回异常（{_safe_error_text(data)}）",
                "severity": "warning",
                "code": "precheck_failed",
            },
        )
        return issues

    deps = data.get("deps") if isinstance(data.get("deps"), dict) else {}
    if isinstance(deps, dict):
        if deps.get("sysctl") is False:
            _append_issue(
                issues,
                seen,
                {
                    "path": "endpoints",
                    "message": f"{node_label}依赖提示：节点缺少 sysctl 命令，性能优化提示可能不完整",
                    "severity": "warning",
                    "code": "dependency_missing",
                },
            )
        if deps.get("ss") is False:
            _append_issue(
                issues,
                seen,
                {
                    "path": "endpoints",
                    "message": f"{node_label}依赖提示：节点缺少 ss 命令，端口占用检查可能不完整",
                    "severity": "warning",
                    "code": "dependency_missing",
                },
            )

    perf_hints = data.get("perf_hints") if isinstance(data.get("perf_hints"), list) else []
    for hint in perf_hints[:8]:
        msg = str(hint or "").strip()
        if not msg:
            continue
        _append_issue(
            issues,
            seen,
            {
                "path": "endpoints",
                "message": f"{node_label}性能风险提示：{msg}",
                "severity": "warning",
                "code": "sysctl_tuning_recommended",
            },
        )

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
                _append_issue(
                    issues,
                    seen,
                    {
                        "path": path,
                        "message": f"{node_label}第 {nth} 条规则目标不可达：{show}" if nth > 0 else f"{node_label}规则目标不可达：{show}",
                        "severity": "warning",
                        "code": "target_unreachable",
                    },
                )

        warns = r.get("warnings") if isinstance(r.get("warnings"), list) else []
        for w in warns[:6]:
            msg = str(w or "").strip()
            if not msg:
                continue
            _append_issue(
                issues,
                seen,
                {
                    "path": path,
                    "message": f"{node_label}第 {nth} 条规则预检提示：{msg}" if nth > 0 else f"{node_label}规则预检提示：{msg}",
                    "severity": "warning",
                    "code": "runtime_warning",
                },
            )

    return issues


def _mptcp_parse_node_ids(raw: Any) -> List[int]:
    seq = raw if isinstance(raw, list) else []
    out: List[int] = []
    seen: set[int] = set()
    for item in seq:
        try:
            nid = int(item)
        except Exception:
            continue
        if nid <= 0 or nid in seen:
            continue
        seen.add(nid)
        out.append(nid)
    return out


def _mptcp_to_bool(raw: Any, default: bool = False) -> bool:
    if isinstance(raw, bool):
        return raw
    if raw is None:
        return bool(default)
    s = str(raw).strip().lower()
    if s in ("1", "true", "yes", "y", "on"):
        return True
    if s in ("0", "false", "no", "n", "off"):
        return False
    return bool(default)


def _mptcp_sender_group_from_endpoint(sender: Dict[str, Any], ep: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    if not isinstance(ep, dict):
        return None
    ex = ep.get("extra_config") if isinstance(ep.get("extra_config"), dict) else {}
    if not isinstance(ex, dict):
        return None
    sync_id = str(ex.get("sync_id") or "").strip()
    if not sync_id:
        return None
    role = str(ex.get("mptcp_role") or ex.get("sync_role") or "").strip().lower()
    mode = str(ex.get("forward_mode") or "").strip().lower()
    sync_type = str(ex.get("sync_tunnel_mode") or ex.get("sync_tunnel_type") or "").strip().lower()
    if role in ("member", "aggregator"):
        return None
    if role == "sender":
        pass
    elif not (mode == "mptcp" and sync_type in ("", "mptcp") and _coerce_int(ex.get("sync_from_node_id"), 0) <= 0):
        return None

    listen = str(ep.get("listen") or ex.get("sync_sender_listen") or "").strip()
    if not listen:
        return None
    remotes_raw = ex.get("sync_original_remotes")
    remotes: List[str] = []
    if isinstance(remotes_raw, list):
        remotes = [str(x).strip() for x in remotes_raw if str(x).strip()]
    elif isinstance(ep.get("remotes"), list):
        remotes = [str(x).strip() for x in (ep.get("remotes") or []) if str(x).strip()]

    member_ids = _mptcp_parse_node_ids(ex.get("mptcp_member_node_ids"))
    aggregator_id = _coerce_int(ex.get("mptcp_aggregator_node_id") or ex.get("sync_peer_node_id"), 0)
    if len(member_ids) < 1 and aggregator_id <= 0:
        return None

    member_ports_raw = ex.get("mptcp_member_ports") if isinstance(ex.get("mptcp_member_ports"), dict) else {}
    member_ports: Dict[str, int] = {}
    if isinstance(member_ports_raw, dict):
        for k, v in member_ports_raw.items():
            try:
                nid = int(k)
                p = int(v)
            except Exception:
                continue
            if nid <= 0 or not (1 <= p <= 65535):
                continue
            member_ports[str(nid)] = int(p)

    scheduler = str(ex.get("mptcp_scheduler") or "aggregate").strip().lower()
    if scheduler not in ("aggregate", "backup", "hybrid"):
        scheduler = "aggregate"

    _, listen_port = split_host_port(listen)
    listen_port_i = _coerce_int(listen_port, 0)
    aggregator_port = _coerce_int(ex.get("mptcp_aggregator_port"), 0)
    channel_port = _coerce_int(ex.get("mptcp_channel_port"), 0)
    if not (1 <= channel_port <= 65535):
        channel_port = int(aggregator_port or listen_port_i or _MPTCP_TUNNEL_PORT)
    if not (1 <= aggregator_port <= 65535):
        aggregator_port = int(channel_port)

    agg_host_raw = str(ex.get("mptcp_aggregator_host") or "").strip()
    aggregator_host = normalize_host_input(agg_host_raw) if agg_host_raw else ""

    qos_raw = ex.get("qos") if isinstance(ex.get("qos"), dict) else {}
    if not qos_raw:
        net_qos = (ep.get("network") or {}).get("qos") if isinstance(ep.get("network"), dict) else {}
        if isinstance(net_qos, dict):
            qos_raw = dict(net_qos)
    qos = dict(qos_raw) if isinstance(qos_raw, dict) else {}

    overlay_enabled = bool(
        _mptcp_to_bool(
            ex.get("mptcp_overlay_enabled")
            if ("mptcp_overlay_enabled" in ex)
            else ex.get("overlay_enabled"),
            False,
        )
    )
    overlay_token = str(ex.get("mptcp_overlay_token") or ex.get("overlay_token") or "").strip()
    overlay_exit_port = _coerce_int(ex.get("mptcp_overlay_exit_port") or ex.get("overlay_exit_port"), 0)
    if not (1 <= overlay_exit_port <= 65535):
        overlay_exit_port = int(_MPTCP_OVERLAY_EXIT_PORT)

    return {
        "sync_id": sync_id,
        "sender_node_id": _coerce_int(sender.get("id"), 0),
        "sender_node_name": str(sender.get("name") or ""),
        "sender_host": node_host_for_realm(sender),
        "listen": listen,
        "listen_port": int(listen_port_i),
        "channel_port": int(channel_port),
        "tunnel_port_mode": ("fixed_group" if bool(_MPTCP_FIXED_TUNNEL_PORT_ENABLED) else "custom"),
        "reusable": bool(ex.get("mptcp_channel_reusable")) if ("mptcp_channel_reusable" in ex) else bool(_MPTCP_FIXED_TUNNEL_PORT_ENABLED),
        "member_node_ids": list(member_ids),
        "member_ports": dict(member_ports),
        "aggregator_node_id": int(aggregator_id),
        "aggregator_host": aggregator_host,
        "aggregator_port": int(aggregator_port),
        "scheduler": scheduler,
        "remotes": list(remotes),
        "disabled": bool(ep.get("disabled")),
        "balance": str(ep.get("balance") or "roundrobin").strip() or "roundrobin",
        "protocol": str(ep.get("protocol") or "tcp").strip() or "tcp",
        "remark": str(ep.get("remark") or "").strip(),
        "favorite": _mptcp_to_bool(ep.get("favorite"), False),
        "qos": qos,
        "failover_rtt_ms": _coerce_int(ex.get("mptcp_failover_rtt_ms"), 0) if ex.get("mptcp_failover_rtt_ms") is not None else None,
        "failover_jitter_ms": _coerce_int(ex.get("mptcp_failover_jitter_ms"), 0) if ex.get("mptcp_failover_jitter_ms") is not None else None,
        "failover_loss_pct": (_coerce_float(ex.get("mptcp_failover_loss_pct"), 0.0) if ex.get("mptcp_failover_loss_pct") is not None else None),
        "overlay_enabled": bool(overlay_enabled),
        "overlay_exit_host": str(_MPTCP_OVERLAY_EXIT_HOST or "127.0.0.1"),
        "overlay_exit_port": int(overlay_exit_port),
        "overlay_token": overlay_token,
        "updated_at": str(ex.get("mptcp_updated_at") or ex.get("sync_updated_at") or ""),
    }


def _mptcp_sender_groups_from_pool(sender: Dict[str, Any], pool: Dict[str, Any], only_sync_id: str = "") -> List[Dict[str, Any]]:
    sid = str(only_sync_id or "").strip()
    out: List[Dict[str, Any]] = []
    seen_sync: set[str] = set()
    for ep in (pool.get("endpoints") or []):
        if not isinstance(ep, dict):
            continue
        g = _mptcp_sender_group_from_endpoint(sender, ep)
        if not isinstance(g, dict):
            continue
        sync_id = str(g.get("sync_id") or "").strip()
        if not sync_id:
            continue
        if sid and sync_id != sid:
            continue
        if sync_id in seen_sync:
            continue
        seen_sync.add(sync_id)
        out.append(g)
    out.sort(key=lambda x: str(x.get("updated_at") or ""), reverse=True)
    return out


def _mptcp_node_view(node: Optional[Dict[str, Any]], node_id: int = 0) -> Dict[str, Any]:
    n = node if isinstance(node, dict) else {}
    nid = _coerce_int((n.get("id") if isinstance(n, dict) else 0) or node_id, 0)
    return {
        "id": int(nid),
        "name": str(n.get("name") or (f"节点-{nid}" if nid > 0 else "")),
        "host": node_host_for_realm(n) if isinstance(n, dict) else "",
        "online": bool(n.get("online")) if isinstance(n, dict) else False,
        "is_private": bool(n.get("is_private")) if isinstance(n, dict) else False,
        "exists": bool(isinstance(node, dict)),
    }


def _mptcp_attach_group_nodes(group: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(group) if isinstance(group, dict) else {}
    sender_id = _coerce_int(out.get("sender_node_id"), 0)
    sender_node = get_node(int(sender_id)) if sender_id > 0 else None
    sender_view = _mptcp_node_view(sender_node, sender_id)
    if not str(out.get("sender_node_name") or "").strip():
        out["sender_node_name"] = str(sender_view.get("name") or "")
    if not str(out.get("sender_host") or "").strip():
        out["sender_host"] = str(sender_view.get("host") or "")

    channel_port = _coerce_int(out.get("channel_port"), 0)
    if not (1 <= channel_port <= 65535):
        channel_port = int(_MPTCP_TUNNEL_PORT)
    out["channel_port"] = int(channel_port)

    member_ids = _mptcp_parse_node_ids(out.get("member_node_ids"))
    member_ports_raw = out.get("member_ports") if isinstance(out.get("member_ports"), dict) else {}
    member_nodes: List[Dict[str, Any]] = []
    for mid in member_ids:
        mnode = get_node(int(mid))
        mview = _mptcp_node_view(mnode, int(mid))
        p0 = _coerce_int(member_ports_raw.get(str(mid)), 0)
        if not (1 <= p0 <= 65535):
            p0 = int(channel_port)
        mview["listen_port"] = int(p0)
        mhost = str(mview.get("host") or "").strip()
        mview["target"] = format_addr(mhost, int(p0)) if mhost else ""
        member_nodes.append(mview)
    out["member_node_ids"] = [int(x.get("id") or 0) for x in member_nodes if _coerce_int(x.get("id"), 0) > 0]
    out["member_nodes"] = member_nodes

    agg_id = _coerce_int(out.get("aggregator_node_id"), 0)
    agg_node = get_node(int(agg_id)) if agg_id > 0 else None
    agg_view = _mptcp_node_view(agg_node, agg_id)
    agg_port = _coerce_int(out.get("aggregator_port"), 0)
    if not (1 <= agg_port <= 65535):
        agg_port = int(channel_port)
    agg_host = str(out.get("aggregator_host") or "").strip()
    if not agg_host:
        agg_host = str(agg_view.get("host") or "").strip()
    out["aggregator_host"] = agg_host
    out["aggregator_port"] = int(agg_port)
    agg_view["listen_port"] = int(agg_port)
    agg_view["target"] = format_addr(agg_host, int(agg_port)) if agg_host else ""
    out["aggregator_node"] = agg_view
    if not str(out.get("aggregator_node_name") or "").strip():
        out["aggregator_node_name"] = str(agg_view.get("name") or "")

    out["sender_node"] = sender_view
    out["member_count"] = len(member_nodes)
    return out


def _mptcp_group_to_save_payload(group: Dict[str, Any], sender_node_id: int = 0, sync_id: str = "") -> Dict[str, Any]:
    g = dict(group) if isinstance(group, dict) else {}
    sid = str(sync_id or g.get("sync_id") or "").strip()
    sender_id = _coerce_int(sender_node_id or g.get("sender_node_id"), 0)
    members = _mptcp_parse_node_ids(g.get("member_node_ids"))
    aggregator_id = _coerce_int(g.get("aggregator_node_id"), 0)
    listen = str(g.get("listen") or "").strip()
    remotes = g.get("remotes") if isinstance(g.get("remotes"), list) else []
    remotes_out = [str(x).strip() for x in remotes if str(x).strip()]
    payload: Dict[str, Any] = {
        "sender_node_id": int(sender_id),
        "member_node_ids": list(members),
        "aggregator_node_id": int(aggregator_id),
        "listen": listen,
        "remotes": remotes_out,
        "disabled": bool(g.get("disabled")),
        "balance": str(g.get("balance") or "roundrobin").strip() or "roundrobin",
        "protocol": "tcp",
        "scheduler": str(g.get("scheduler") or "aggregate").strip().lower() or "aggregate",
        "sync_id": sid,
        "remark": str(g.get("remark") or "").strip(),
        "favorite": _mptcp_to_bool(g.get("favorite"), False),
    }
    agg_host = str(g.get("aggregator_host") or "").strip()
    if agg_host:
        payload["aggregator_host"] = agg_host
    agg_port = _coerce_int(g.get("aggregator_port"), 0)
    if 1 <= agg_port <= 65535:
        payload["aggregator_port"] = int(agg_port)

    if g.get("failover_rtt_ms") is not None:
        payload["failover_rtt_ms"] = _coerce_int(g.get("failover_rtt_ms"), 0)
    if g.get("failover_jitter_ms") is not None:
        payload["failover_jitter_ms"] = _coerce_int(g.get("failover_jitter_ms"), 0)
    if g.get("failover_loss_pct") is not None:
        payload["failover_loss_pct"] = _coerce_float(g.get("failover_loss_pct"), 0.0)

    qos = g.get("qos") if isinstance(g.get("qos"), dict) else {}
    if qos:
        payload["qos"] = dict(qos)

    # Route B overlay settings (optional)
    if "overlay_enabled" in g or "mptcp_overlay_enabled" in g:
        payload["overlay_enabled"] = _mptcp_to_bool(g.get("overlay_enabled") if "overlay_enabled" in g else g.get("mptcp_overlay_enabled"), False)
    if "overlay_exit_port" in g or "mptcp_overlay_exit_port" in g:
        p0 = _coerce_int(g.get("overlay_exit_port") if "overlay_exit_port" in g else g.get("mptcp_overlay_exit_port"), 0)
        if 1 <= p0 <= 65535:
            payload["overlay_exit_port"] = int(p0)
    if "overlay_token" in g or "mptcp_overlay_token" in g:
        payload["overlay_token"] = str(g.get("overlay_token") if "overlay_token" in g else g.get("mptcp_overlay_token") or "").strip()
    return payload


def _mptcp_probe_result_entry(target: str, result: Dict[str, Any], **extra: Any) -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "target": str(target or "").strip(),
        "ok": False,
        "latency_ms": None,
        "error": "",
    }
    if isinstance(result, dict):
        out["ok"] = bool(result.get("ok") is True)
        lat = result.get("latency_ms")
        if lat is not None:
            try:
                out["latency_ms"] = float(round(float(lat), 3))
            except Exception:
                out["latency_ms"] = None
        out["error"] = str(result.get("error") or "").strip()
    for k, v in extra.items():
        out[k] = v
    return out


def _mptcp_probe_stage_summary(details: List[Dict[str, Any]]) -> Dict[str, Any]:
    total = len(details)
    ok_count = 0
    latencies: List[float] = []
    for item in details:
        if bool(item.get("ok") is True):
            ok_count += 1
        lv = item.get("latency_ms")
        try:
            if lv is not None:
                latencies.append(float(lv))
        except Exception:
            continue
    fail_count = max(0, total - ok_count)
    avg_rtt = (sum(latencies) / len(latencies)) if latencies else None
    return {
        "total": int(total),
        "ok": int(ok_count),
        "failed": int(fail_count),
        "availability_pct": (float(round((ok_count * 100.0 / total), 2)) if total > 0 else None),
        "avg_rtt_ms": (float(round(avg_rtt, 3)) if avg_rtt is not None else None),
        "best_rtt_ms": (float(round(min(latencies), 3)) if latencies else None),
        "worst_rtt_ms": (float(round(max(latencies), 3)) if latencies else None),
        "status": ("ok" if total > 0 and fail_count == 0 else ("warn" if ok_count > 0 else ("fail" if total > 0 else "skip"))),
    }


async def _mptcp_probe_targets_from_node(node: Dict[str, Any], targets: List[str], timeout_sec: float = 1.4) -> Dict[str, Any]:
    cleaned: List[str] = []
    seen: set[str] = set()
    for raw in (targets or []):
        t = str(raw or "").strip()
        if not t or t in seen:
            continue
        seen.add(t)
        cleaned.append(t)
    if not cleaned:
        return {"ok": True, "results": {}}

    target_base_url, target_verify_tls, target_route = node_agent_request_target(node)
    probe_timeout = max(0.2, min(8.0, float(timeout_sec)))
    req_timeout = max(float(_sync_precheck_http_timeout()), probe_timeout + 1.8)
    body = {"mode": "tcping", "targets": cleaned[:50], "timeout": probe_timeout}
    try:
        data = await agent_post(
            target_base_url,
            str(node.get("api_key") or ""),
            "/api/v1/netprobe",
            body,
            target_verify_tls,
            timeout=req_timeout,
        )
    except Exception as exc:
        return {
            "ok": False,
            "results": {},
            "error": _format_agent_request_failure(
                node,
                "/api/v1/netprobe",
                exc,
                req_timeout,
                target_base_url=target_base_url,
                target_verify_tls=target_verify_tls,
                target_route=target_route,
            ),
        }
    if not isinstance(data, dict) or data.get("ok") is not True:
        return {
            "ok": False,
            "results": {},
            "error": f"/api/v1/netprobe 返回失败：{_safe_error_text(data)}",
        }
    results = data.get("results") if isinstance(data.get("results"), dict) else {}
    return {"ok": True, "results": results, "raw": data}


@router.get("/api/mptcp_tunnel/groups")
async def api_mptcp_tunnel_groups(sender_node_id: int, user: str = Depends(require_login)):
    sid = _coerce_int(sender_node_id, 0)
    if sid <= 0:
        return JSONResponse({"ok": False, "error": "sender_node_id 无效"}, status_code=400)
    sender = get_node(int(sid))
    if not sender:
        return JSONResponse({"ok": False, "error": "入口节点不存在"}, status_code=404)

    sender_pool = await load_pool_for_node(sender)
    sender_pool_view = _filter_pool_for_user(user, sender_pool)
    groups_raw = _mptcp_sender_groups_from_pool(sender, sender_pool_view)
    groups = [_mptcp_attach_group_nodes(g) for g in groups_raw]

    return {
        "ok": True,
        "sender_node": _mptcp_node_view(sender, int(sid)),
        "groups": groups,
        "defaults": {
            "fixed_tunnel_port_enabled": bool(_MPTCP_FIXED_TUNNEL_PORT_ENABLED),
            "tunnel_port": int(_MPTCP_TUNNEL_PORT),
            "overlay_exit_port": int(_MPTCP_OVERLAY_EXIT_PORT),
            "overlay_exit_host": str(_MPTCP_OVERLAY_EXIT_HOST or "127.0.0.1"),
        },
    }


@router.get("/api/mptcp_tunnel/groups_all")
async def api_mptcp_tunnel_groups_all(
    overlay_only: int = 1,
    user: str = Depends(require_login),
):
    """List reusable MPTCP tunnel groups across all sender nodes.

    Used by Overlay rule editor dropdown to avoid manual copy/paste.
    """
    only = True
    try:
        only = bool(int(overlay_only) != 0)
    except Exception:
        only = True

    groups_out: List[Dict[str, Any]] = []
    seen: set[str] = set()

    # NOTE: This endpoint is UI-helper; keep it lightweight.
    nodes = list_nodes()
    for sender in nodes[:200]:
        sid = _coerce_int(sender.get("id"), 0)
        if sid <= 0:
            continue
        try:
            sender_pool = await load_pool_for_node(sender)
        except Exception:
            continue
        sender_pool_view = _filter_pool_for_user(user, sender_pool)
        groups_raw = _mptcp_sender_groups_from_pool(sender, sender_pool_view)
        for g in groups_raw:
            if not isinstance(g, dict):
                continue
            if only and not bool(g.get("overlay_enabled") is True):
                continue
            gid = str(g.get("sync_id") or "").strip()
            if not gid or gid in seen:
                continue
            seen.add(gid)
            try:
                groups_out.append(_mptcp_attach_group_nodes(g))
            except Exception:
                groups_out.append(dict(g))
        if len(groups_out) >= 500:
            break

    # Sort by updated_at desc (best-effort)
    try:
        groups_out.sort(key=lambda x: str(x.get("updated_at") or ""), reverse=True)
    except Exception:
        pass

    return {
        "ok": True,
        "groups": groups_out,
        "defaults": {
            "fixed_tunnel_port_enabled": bool(_MPTCP_FIXED_TUNNEL_PORT_ENABLED),
            "tunnel_port": int(_MPTCP_TUNNEL_PORT),
            "overlay_exit_port": int(_MPTCP_OVERLAY_EXIT_PORT),
            "overlay_exit_host": str(_MPTCP_OVERLAY_EXIT_HOST or "127.0.0.1"),
        },
    }


@router.post("/api/mptcp_tunnel/group_probe")
async def api_mptcp_tunnel_group_probe(payload: Dict[str, Any], user: str = Depends(require_login)):
    if not isinstance(payload, dict):
        return JSONResponse({"ok": False, "error": "payload 无效"}, status_code=400)
    sync_id = str(payload.get("sync_id") or "").strip()
    if not sync_id:
        return JSONResponse({"ok": False, "error": "sync_id 不能为空"}, status_code=400)

    source_sender_id = _coerce_int(payload.get("old_sender_node_id") or payload.get("source_sender_node_id") or payload.get("sender_node_id"), 0)
    if source_sender_id <= 0:
        return JSONResponse({"ok": False, "error": "sender_node_id 无效"}, status_code=400)
    source_sender = get_node(int(source_sender_id))
    if not source_sender:
        return JSONResponse({"ok": False, "error": "入口节点不存在"}, status_code=404)

    source_pool = await load_pool_for_node(source_sender)
    source_pool_view = _filter_pool_for_user(user, source_pool)
    groups_raw = _mptcp_sender_groups_from_pool(source_sender, source_pool_view, only_sync_id=sync_id)
    if not groups_raw:
        return JSONResponse({"ok": False, "error": "隧道组不存在或无权限访问"}, status_code=404)
    base_group = _mptcp_attach_group_nodes(groups_raw[0])

    probe_sender_id = _coerce_int(payload.get("sender_node_id"), 0) or int(base_group.get("sender_node_id") or 0)
    sender = get_node(int(probe_sender_id))
    if not sender:
        return JSONResponse({"ok": False, "error": "探测入口节点不存在"}, status_code=404)

    override_members = _mptcp_parse_node_ids(payload.get("member_node_ids"))
    if not override_members:
        override_members = _mptcp_parse_node_ids(payload.get("mptcp_member_node_ids"))
    member_ids = override_members if len(override_members) >= 1 else _mptcp_parse_node_ids(base_group.get("member_node_ids"))
    if len(member_ids) < 1:
        return JSONResponse({"ok": False, "error": "成员链路节点为空，无法探测"}, status_code=400)

    aggregator_id = _coerce_int(payload.get("aggregator_node_id") or payload.get("mptcp_aggregator_node_id"), 0)
    if aggregator_id <= 0:
        aggregator_id = _coerce_int(base_group.get("aggregator_node_id"), 0)
    if aggregator_id <= 0:
        return JSONResponse({"ok": False, "error": "汇聚节点为空，无法探测"}, status_code=400)

    for nid in member_ids + [aggregator_id]:
        if nid <= 0 or nid == probe_sender_id:
            continue
        denied = _check_sync_policy(user, "mptcp", "save", probe_sender_id, int(nid))
        if isinstance(denied, JSONResponse):
            return denied

    channel_port = _coerce_int(payload.get("channel_port"), 0)
    if not (1 <= channel_port <= 65535):
        channel_port = _coerce_int(base_group.get("channel_port"), 0)
    if not (1 <= channel_port <= 65535):
        channel_port = int(_MPTCP_TUNNEL_PORT)

    agg_port = _coerce_int(payload.get("aggregator_port"), 0)
    if not (1 <= agg_port <= 65535):
        agg_port = _coerce_int(base_group.get("aggregator_port"), 0)
    if not (1 <= agg_port <= 65535):
        agg_port = int(channel_port)

    agg_host_raw = ""
    if payload.get("aggregator_host") is not None:
        agg_host_raw = str(payload.get("aggregator_host") or "").strip()
    if not agg_host_raw:
        agg_host_raw = str(base_group.get("aggregator_host") or "").strip()
    agg_host = normalize_host_input(agg_host_raw) if agg_host_raw else ""
    agg_node = get_node(int(aggregator_id))
    if not agg_host and isinstance(agg_node, dict):
        agg_host = node_host_for_realm(agg_node)
    if not agg_host:
        return JSONResponse({"ok": False, "error": "汇聚节点地址为空，无法探测"}, status_code=400)
    agg_target = format_addr(agg_host, int(agg_port))

    remotes_raw = payload.get("remotes")
    if isinstance(remotes_raw, str):
        remotes = [x.strip() for x in remotes_raw.splitlines() if x.strip()]
    elif isinstance(remotes_raw, list):
        remotes = [str(x).strip() for x in remotes_raw if str(x).strip()]
    else:
        remotes = [str(x).strip() for x in (base_group.get("remotes") or []) if str(x).strip()]
    remotes = remotes[:20]

    overlay_enabled = None
    if ("overlay_enabled" in payload) or ("mptcp_overlay_enabled" in payload):
        overlay_enabled = _mptcp_to_bool(payload.get("overlay_enabled") if "overlay_enabled" in payload else payload.get("mptcp_overlay_enabled"), False)
    else:
        overlay_enabled = _mptcp_to_bool(base_group.get("overlay_enabled"), False)

    overlay_exit_port = _coerce_int(
        payload.get("overlay_exit_port")
        if ("overlay_exit_port" in payload)
        else payload.get("mptcp_overlay_exit_port")
        if ("mptcp_overlay_exit_port" in payload)
        else base_group.get("overlay_exit_port"),
        0,
    )
    if not (1 <= overlay_exit_port <= 65535):
        overlay_exit_port = int(_MPTCP_OVERLAY_EXIT_PORT)

    warnings: List[str] = []
    stage_ab_details: List[Dict[str, Any]] = []
    stage_bc_details: List[Dict[str, Any]] = []
    stage_cr_details: List[Dict[str, Any]] = []
    stage_ce_details: List[Dict[str, Any]] = []

    member_nodes: List[Dict[str, Any]] = []
    for mid in member_ids:
        node_obj = get_node(int(mid))
        view = _mptcp_node_view(node_obj, int(mid))
        listen_port = _coerce_int(((base_group.get("member_ports") or {}).get(str(mid)) if isinstance(base_group.get("member_ports"), dict) else 0), 0)
        if not (1 <= listen_port <= 65535):
            listen_port = int(channel_port)
        view["listen_port"] = int(listen_port)
        mhost = str(view.get("host") or "").strip()
        view["target"] = format_addr(mhost, int(listen_port)) if mhost else ""
        member_nodes.append(view)

    ab_targets = [str(it.get("target") or "").strip() for it in member_nodes if str(it.get("target") or "").strip()]
    ab_probe = await _mptcp_probe_targets_from_node(sender, ab_targets, timeout_sec=1.4)
    if not bool(ab_probe.get("ok")) and str(ab_probe.get("error") or "").strip():
        warnings.append(str(ab_probe.get("error") or "").strip())
    for item in member_nodes:
        target = str(item.get("target") or "").strip()
        if not target:
            stage_ab_details.append(
                _mptcp_probe_result_entry(
                    "",
                    {"ok": False, "error": "成员节点地址为空"},
                    node_id=_coerce_int(item.get("id"), 0),
                    node_name=str(item.get("name") or ""),
                )
            )
            continue
        r0 = ab_probe.get("results", {}).get(target) if isinstance(ab_probe.get("results"), dict) else {}
        if not isinstance(r0, dict):
            r0 = {"ok": False, "error": str(ab_probe.get("error") or "no_probe_result")}
        stage_ab_details.append(
            _mptcp_probe_result_entry(
                target,
                r0,
                node_id=_coerce_int(item.get("id"), 0),
                node_name=str(item.get("name") or ""),
            )
        )

    async def _probe_member_to_c(member: Dict[str, Any]) -> Dict[str, Any]:
        mid = _coerce_int(member.get("id"), 0)
        name = str(member.get("name") or "")
        node_obj = get_node(int(mid))
        if not isinstance(node_obj, dict):
            return _mptcp_probe_result_entry(
                agg_target,
                {"ok": False, "error": "成员节点不存在"},
                source_node_id=int(mid),
                source_node_name=name,
                target_node_id=int(aggregator_id),
                target_node_name=str((agg_node or {}).get("name") or f"节点-{aggregator_id}"),
            )
        probe = await _mptcp_probe_targets_from_node(node_obj, [agg_target], timeout_sec=1.4)
        r0 = probe.get("results", {}).get(agg_target) if isinstance(probe.get("results"), dict) else {}
        if not isinstance(r0, dict):
            r0 = {"ok": False, "error": str(probe.get("error") or "no_probe_result")}
        if (not bool(probe.get("ok"))) and str(probe.get("error") or "").strip():
            warnings.append(str(probe.get("error") or "").strip())
        return _mptcp_probe_result_entry(
            agg_target,
            r0,
            source_node_id=int(mid),
            source_node_name=name,
            target_node_id=int(aggregator_id),
            target_node_name=str((agg_node or {}).get("name") or f"节点-{aggregator_id}"),
        )

    if member_nodes:
        bc_results = await asyncio.gather(*[_probe_member_to_c(item) for item in member_nodes], return_exceptions=False)
        for one in bc_results:
            if isinstance(one, dict):
                stage_bc_details.append(one)

    if not isinstance(agg_node, dict):
        stage_cr_details.append(
            _mptcp_probe_result_entry(
                "",
                {"ok": False, "error": "汇聚节点不存在"},
                source_node_id=int(aggregator_id),
                source_node_name=f"节点-{aggregator_id}",
            )
        )
    else:
        if overlay_enabled:
            # Overlay mode: verify local exit proxy health first (C -> 127.0.0.1:overlay_exit_port)
            exit_target = format_addr(str(_MPTCP_OVERLAY_EXIT_HOST or "127.0.0.1"), int(overlay_exit_port))
            ce_probe = await _mptcp_probe_targets_from_node(agg_node, [exit_target], timeout_sec=1.4)
            if not bool(ce_probe.get("ok")) and str(ce_probe.get("error") or "").strip():
                warnings.append(str(ce_probe.get("error") or "").strip())
            r0 = ce_probe.get("results", {}).get(exit_target) if isinstance(ce_probe.get("results"), dict) else {}
            if not isinstance(r0, dict):
                r0 = {"ok": False, "error": str(ce_probe.get("error") or "no_probe_result")}
            stage_ce_details.append(
                _mptcp_probe_result_entry(
                    exit_target,
                    r0,
                    source_node_id=int(aggregator_id),
                    source_node_name=str(agg_node.get("name") or f"节点-{aggregator_id}"),
                )
            )

            # Optional allowlist targets probe (C -> allowlist)
            if remotes:
                c_probe = await _mptcp_probe_targets_from_node(agg_node, remotes, timeout_sec=1.8)
                if not bool(c_probe.get("ok")) and str(c_probe.get("error") or "").strip():
                    warnings.append(str(c_probe.get("error") or "").strip())
                for t in remotes:
                    r0 = c_probe.get("results", {}).get(t) if isinstance(c_probe.get("results"), dict) else {}
                    if not isinstance(r0, dict):
                        r0 = {"ok": False, "error": str(c_probe.get("error") or "no_probe_result")}
                    stage_cr_details.append(
                        _mptcp_probe_result_entry(
                            t,
                            r0,
                            source_node_id=int(aggregator_id),
                            source_node_name=str(agg_node.get("name") or f"节点-{aggregator_id}"),
                        )
                    )
        else:
            if remotes:
                c_probe = await _mptcp_probe_targets_from_node(agg_node, remotes, timeout_sec=1.8)
                if not bool(c_probe.get("ok")) and str(c_probe.get("error") or "").strip():
                    warnings.append(str(c_probe.get("error") or "").strip())
                for t in remotes:
                    r0 = c_probe.get("results", {}).get(t) if isinstance(c_probe.get("results"), dict) else {}
                    if not isinstance(r0, dict):
                        r0 = {"ok": False, "error": str(c_probe.get("error") or "no_probe_result")}
                    stage_cr_details.append(
                        _mptcp_probe_result_entry(
                            t,
                            r0,
                            source_node_id=int(aggregator_id),
                            source_node_name=str(agg_node.get("name") or f"节点-{aggregator_id}"),
                        )
                    )

    stage_ab_summary = _mptcp_probe_stage_summary(stage_ab_details)
    stage_bc_summary = _mptcp_probe_stage_summary(stage_bc_details)
    stage_ce_summary = _mptcp_probe_stage_summary(stage_ce_details)
    stage_cr_summary = _mptcp_probe_stage_summary(stage_cr_details)
    all_details = stage_ab_details + stage_bc_details + stage_ce_details + stage_cr_details
    all_summary = _mptcp_probe_stage_summary(all_details)

    seen_warn: set[str] = set()
    warn_out: List[str] = []
    for w in warnings:
        ww = str(w or "").strip()
        if not ww or ww in seen_warn:
            continue
        seen_warn.add(ww)
        warn_out.append(ww)

    group_out = dict(base_group)
    group_out["sender_node_id"] = int(probe_sender_id)
    group_out["member_node_ids"] = list(member_ids)
    group_out["aggregator_node_id"] = int(aggregator_id)
    group_out["aggregator_host"] = agg_host
    group_out["aggregator_port"] = int(agg_port)
    group_out["channel_port"] = int(channel_port)
    group_out = _mptcp_attach_group_nodes(group_out)

    stages_out: List[Dict[str, Any]] = [
        {
            "stage": "a_to_b",
            "label": "A 入口 -> B 通道",
            "from_node": _mptcp_node_view(sender, int(probe_sender_id)),
            "details": stage_ab_details,
            "summary": stage_ab_summary,
        },
        {
            "stage": "b_to_c",
            "label": "B 通道 -> C 汇聚",
            "from_nodes": member_nodes,
            "to_node": _mptcp_node_view(agg_node, int(aggregator_id)),
            "target": agg_target,
            "details": stage_bc_details,
            "summary": stage_bc_summary,
        },
    ]
    if overlay_enabled:
        stages_out.append(
            {
                "stage": "c_to_exit",
                "label": "C 汇聚 -> Overlay 出口代理",
                "from_node": _mptcp_node_view(agg_node, int(aggregator_id)),
                "details": stage_ce_details,
                "summary": stage_ce_summary,
            }
        )
        stages_out.append(
            {
                "stage": "c_to_allowlist",
                "label": "C 汇聚 -> 允许目标（可选）",
                "from_node": _mptcp_node_view(agg_node, int(aggregator_id)),
                "details": stage_cr_details,
                "summary": stage_cr_summary,
            }
        )
    else:
        stages_out.append(
            {
                "stage": "c_to_remote",
                "label": "C 汇聚 -> 最终目标",
                "from_node": _mptcp_node_view(agg_node, int(aggregator_id)),
                "details": stage_cr_details,
                "summary": stage_cr_summary,
            }
        )

    return {
        "ok": True,
        "sync_id": sync_id,
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "group": group_out,
        "summary": all_summary,
        "stages": stages_out,
        "warnings": warn_out,
    }


@router.get("/api/sync_jobs/{job_id}")
async def api_sync_job_get(job_id: str, user: str = Depends(require_login)):
    jid = str(job_id or "").strip()
    if not jid:
        return JSONResponse({"ok": False, "error": "job_id 不能为空"}, status_code=400)
    with _SYNC_JOBS_LOCK:
        _prune_sync_jobs_locked()
        job = _SYNC_JOBS.get(jid)
        if not isinstance(job, dict):
            return JSONResponse({"ok": False, "error": "任务不存在或已过期"}, status_code=404)
        owner = str(job.get("_user") or "").strip()
        if owner and owner != str(user or "").strip():
            return JSONResponse({"ok": False, "error": "任务不存在或已过期"}, status_code=404)
        return {"ok": True, "job": _sync_job_public_view(job, include_result=True)}


@router.post("/api/sync_jobs/{job_id}/retry")
async def api_sync_job_retry(job_id: str, user: str = Depends(require_login)):
    jid = str(job_id or "").strip()
    if not jid:
        return JSONResponse({"ok": False, "error": "job_id 不能为空"}, status_code=400)

    kind = ""
    payload: Dict[str, Any] = {}
    with _SYNC_JOBS_LOCK:
        _prune_sync_jobs_locked()
        job = _SYNC_JOBS.get(jid)
        if not isinstance(job, dict):
            return JSONResponse({"ok": False, "error": "任务不存在或已过期"}, status_code=404)
        owner = str(job.get("_user") or "").strip()
        if owner and owner != str(user or "").strip():
            return JSONResponse({"ok": False, "error": "任务不存在或已过期"}, status_code=404)
        st = str(job.get("status") or "")
        if st not in ("error", "success"):
            return JSONResponse({"ok": False, "error": "任务仍在执行中，请稍后再试"}, status_code=409)
        kind = str(job.get("kind") or "")
        payload0 = job.get("_payload")
        if not isinstance(payload0, dict):
            return JSONResponse({"ok": False, "error": "原任务缺少可重试参数"}, status_code=400)
        payload = dict(payload0)
    if payload is None:
        return JSONResponse({"ok": False, "error": "原任务缺少可重试参数"}, status_code=400)
    if kind not in (
        "wss_save",
        "mptcp_save",
        "mptcp_group_update",
        "intranet_save",
        "wss_delete",
        "mptcp_delete",
        "intranet_delete",
    ):
        return JSONResponse({"ok": False, "error": "不支持该任务类型重试"}, status_code=400)
    nj = _sync_job_enqueue(kind=kind, payload=payload, user=user)
    return {"ok": True, "job": nj}


@router.post("/api/wss_tunnel/save_async")
async def api_wss_tunnel_save_async(payload: Dict[str, Any], user: str = Depends(require_login)):
    if not isinstance(payload, dict):
        return JSONResponse({"ok": False, "error": "payload 无效"}, status_code=400)
    try:
        sender_id = int(payload.get("sender_node_id") or 0)
        receiver_id = int(payload.get("receiver_node_id") or 0)
    except Exception:
        sender_id = 0
        receiver_id = 0
    if sender_id > 0 and receiver_id > 0 and sender_id != receiver_id:
        denied = _check_sync_policy(user, "wss", "save", sender_id, receiver_id)
        if isinstance(denied, JSONResponse):
            return denied
    job = _sync_job_enqueue(kind="wss_save", payload=payload, user=user)
    return {"ok": True, "job": job}


@router.post("/api/mptcp_tunnel/save_async")
async def api_mptcp_tunnel_save_async(payload: Dict[str, Any], user: str = Depends(require_login)):
    if not isinstance(payload, dict):
        return JSONResponse({"ok": False, "error": "payload 无效"}, status_code=400)
    try:
        sender_id = int(payload.get("sender_node_id") or 0)
    except Exception:
        sender_id = 0
    member_ids_raw = payload.get("member_node_ids")
    if not isinstance(member_ids_raw, list):
        member_ids_raw = payload.get("mptcp_member_node_ids")
    member_ids: List[int] = []
    seen: set[int] = set()
    if isinstance(member_ids_raw, list):
        for item in member_ids_raw:
            try:
                nid = int(item)
            except Exception:
                continue
            if nid <= 0 or nid in seen:
                continue
            seen.add(nid)
            member_ids.append(nid)
    try:
        agg_id = int(
            payload.get("aggregator_node_id")
            or payload.get("mptcp_aggregator_node_id")
            or payload.get("receiver_node_id")
            or 0
        )
    except Exception:
        agg_id = 0
    if sender_id > 0:
        for rid in member_ids + ([agg_id] if agg_id > 0 else []):
            if rid <= 0 or rid == sender_id:
                continue
            denied = _check_sync_policy(user, "mptcp", "save", sender_id, rid)
            if isinstance(denied, JSONResponse):
                return denied
    job = _sync_job_enqueue(kind="mptcp_save", payload=payload, user=user)
    return {"ok": True, "job": job}


@router.post("/api/intranet_tunnel/save_async")
async def api_intranet_tunnel_save_async(payload: Dict[str, Any], user: str = Depends(require_login)):
    if not isinstance(payload, dict):
        return JSONResponse({"ok": False, "error": "payload 无效"}, status_code=400)
    try:
        sender_id = int(payload.get("sender_node_id") or 0)
        receiver_id = int(payload.get("receiver_node_id") or 0)
    except Exception:
        sender_id = 0
        receiver_id = 0
    if sender_id > 0 and receiver_id > 0 and sender_id != receiver_id:
        denied = _check_sync_policy(user, "intranet", "save", sender_id, receiver_id)
        if isinstance(denied, JSONResponse):
            return denied
    job = _sync_job_enqueue(kind="intranet_save", payload=payload, user=user)
    return {"ok": True, "job": job}


@router.post("/api/wss_tunnel/delete_async")
async def api_wss_tunnel_delete_async(payload: Dict[str, Any], user: str = Depends(require_login)):
    if not isinstance(payload, dict):
        return JSONResponse({"ok": False, "error": "payload 无效"}, status_code=400)
    try:
        sender_id = int(payload.get("sender_node_id") or 0)
        receiver_id = int(payload.get("receiver_node_id") or 0)
    except Exception:
        sender_id = 0
        receiver_id = 0
    if sender_id > 0 and receiver_id > 0 and sender_id != receiver_id:
        receiver = get_node(int(receiver_id))
        # Peer node may have been removed already: allow sender-side cleanup path.
        policy_receiver_id = int(receiver_id) if receiver else int(sender_id)
        denied = _check_sync_policy(user, "wss", "delete", sender_id, policy_receiver_id)
        if isinstance(denied, JSONResponse):
            return denied
    job = _sync_job_enqueue(kind="wss_delete", payload=payload, user=user)
    return {"ok": True, "job": job}


@router.post("/api/mptcp_tunnel/delete_async")
async def api_mptcp_tunnel_delete_async(payload: Dict[str, Any], user: str = Depends(require_login)):
    if not isinstance(payload, dict):
        return JSONResponse({"ok": False, "error": "payload 无效"}, status_code=400)
    try:
        sender_id = int(payload.get("sender_node_id") or 0)
    except Exception:
        sender_id = 0
    member_ids_raw = payload.get("member_node_ids")
    if not isinstance(member_ids_raw, list):
        member_ids_raw = payload.get("mptcp_member_node_ids")
    member_ids: List[int] = []
    seen: set[int] = set()
    if isinstance(member_ids_raw, list):
        for item in member_ids_raw:
            try:
                nid = int(item)
            except Exception:
                continue
            if nid <= 0 or nid in seen:
                continue
            seen.add(nid)
            member_ids.append(nid)
    try:
        agg_id = int(
            payload.get("aggregator_node_id")
            or payload.get("mptcp_aggregator_node_id")
            or payload.get("receiver_node_id")
            or 0
        )
    except Exception:
        agg_id = 0
    if sender_id > 0:
        for rid in member_ids + ([agg_id] if agg_id > 0 else []):
            if rid <= 0 or rid == sender_id:
                continue
            receiver = get_node(int(rid))
            policy_receiver_id = int(rid) if receiver else int(sender_id)
            denied = _check_sync_policy(user, "mptcp", "delete", sender_id, policy_receiver_id)
            if isinstance(denied, JSONResponse):
                return denied
    job = _sync_job_enqueue(kind="mptcp_delete", payload=payload, user=user)
    return {"ok": True, "job": job}


@router.post("/api/mptcp_tunnel/group_update_async")
async def api_mptcp_tunnel_group_update_async(payload: Dict[str, Any], user: str = Depends(require_login)):
    if not isinstance(payload, dict):
        return JSONResponse({"ok": False, "error": "payload 无效"}, status_code=400)
    sync_id = str(payload.get("sync_id") or "").strip()
    if not sync_id:
        return JSONResponse({"ok": False, "error": "sync_id 不能为空"}, status_code=400)
    job = _sync_job_enqueue(kind="mptcp_group_update", payload=payload, user=user)
    return {"ok": True, "job": job}


@router.post("/api/mptcp_tunnel/group_update")
async def api_mptcp_tunnel_group_update(payload: Dict[str, Any], user: str = Depends(require_login)):
    if not isinstance(payload, dict):
        return JSONResponse({"ok": False, "error": "payload 无效"}, status_code=400)
    sync_id = str(payload.get("sync_id") or "").strip()
    if not sync_id:
        return JSONResponse({"ok": False, "error": "sync_id 不能为空"}, status_code=400)
    is_async_job = bool(payload.get("_async_job") is True)

    old_sender_id = _coerce_int(payload.get("old_sender_node_id") or payload.get("source_sender_node_id") or payload.get("sender_node_id"), 0)
    if old_sender_id <= 0:
        return JSONResponse({"ok": False, "error": "old_sender_node_id 无效"}, status_code=400)
    old_sender = get_node(int(old_sender_id))
    if not old_sender:
        return JSONResponse({"ok": False, "error": "原入口节点不存在"}, status_code=404)

    old_sender_pool = await load_pool_for_node(old_sender)
    old_sender_pool_view = _filter_pool_for_user(user, old_sender_pool)
    old_groups = _mptcp_sender_groups_from_pool(old_sender, old_sender_pool_view, only_sync_id=sync_id)
    if not old_groups:
        return JSONResponse({"ok": False, "error": "原隧道组不存在或无权限访问"}, status_code=404)
    old_group = _mptcp_attach_group_nodes(old_groups[0])

    new_group = dict(old_group)
    new_sender_id = _coerce_int(payload.get("sender_node_id"), 0)
    if new_sender_id <= 0:
        new_sender_id = int(old_sender_id)
    new_group["sender_node_id"] = int(new_sender_id)

    member_ids = _mptcp_parse_node_ids(payload.get("member_node_ids"))
    if not member_ids:
        member_ids = _mptcp_parse_node_ids(payload.get("mptcp_member_node_ids"))
    if member_ids:
        new_group["member_node_ids"] = list(member_ids)

    agg_id = _coerce_int(payload.get("aggregator_node_id") or payload.get("mptcp_aggregator_node_id"), 0)
    if agg_id > 0:
        new_group["aggregator_node_id"] = int(agg_id)

    if "listen" in payload:
        new_group["listen"] = str(payload.get("listen") or "").strip()
    if "remotes" in payload:
        remotes_raw = payload.get("remotes")
        if isinstance(remotes_raw, str):
            remotes = [x.strip() for x in remotes_raw.splitlines() if x.strip()]
        elif isinstance(remotes_raw, list):
            remotes = [str(x).strip() for x in remotes_raw if str(x).strip()]
        else:
            remotes = []
        new_group["remotes"] = remotes

    if "disabled" in payload:
        new_group["disabled"] = _mptcp_to_bool(payload.get("disabled"), bool(old_group.get("disabled")))
    if "balance" in payload:
        new_group["balance"] = str(payload.get("balance") or old_group.get("balance") or "roundrobin").strip() or "roundrobin"
    if "remark" in payload:
        new_group["remark"] = str(payload.get("remark") or "").strip()
    if "favorite" in payload:
        new_group["favorite"] = _mptcp_to_bool(payload.get("favorite"), bool(old_group.get("favorite")))

    if "scheduler" in payload:
        scheduler = str(payload.get("scheduler") or "").strip().lower()
        if scheduler not in ("aggregate", "backup", "hybrid"):
            scheduler = "aggregate"
        new_group["scheduler"] = scheduler

    if "aggregator_host" in payload or "mptcp_aggregator_host" in payload:
        raw_host = str(payload.get("aggregator_host") or payload.get("mptcp_aggregator_host") or "").strip()
        new_group["aggregator_host"] = normalize_host_input(raw_host) if raw_host else ""
    if "aggregator_port" in payload or "mptcp_aggregator_port" in payload:
        p0 = _coerce_int(payload.get("aggregator_port") or payload.get("mptcp_aggregator_port"), 0)
        if 1 <= p0 <= 65535:
            new_group["aggregator_port"] = int(p0)

    if "failover_rtt_ms" in payload or "mptcp_failover_rtt_ms" in payload:
        rv = payload.get("failover_rtt_ms") if "failover_rtt_ms" in payload else payload.get("mptcp_failover_rtt_ms")
        if rv is None or str(rv).strip() == "":
            new_group["failover_rtt_ms"] = None
        else:
            new_group["failover_rtt_ms"] = _coerce_int(rv, 0)
    if "failover_jitter_ms" in payload or "mptcp_failover_jitter_ms" in payload:
        rv = payload.get("failover_jitter_ms") if "failover_jitter_ms" in payload else payload.get("mptcp_failover_jitter_ms")
        if rv is None or str(rv).strip() == "":
            new_group["failover_jitter_ms"] = None
        else:
            new_group["failover_jitter_ms"] = _coerce_int(rv, 0)
    if "failover_loss_pct" in payload or "mptcp_failover_loss_pct" in payload:
        rv = payload.get("failover_loss_pct") if "failover_loss_pct" in payload else payload.get("mptcp_failover_loss_pct")
        if rv is None or str(rv).strip() == "":
            new_group["failover_loss_pct"] = None
        else:
            new_group["failover_loss_pct"] = float(round(_coerce_float(rv, 0.0), 2))

    if "qos" in payload:
        if isinstance(payload.get("qos"), dict):
            new_group["qos"] = dict(payload.get("qos") or {})
        else:
            new_group["qos"] = {}

    if len(_mptcp_parse_node_ids(new_group.get("member_node_ids"))) < 2:
        return JSONResponse({"ok": False, "error": "member_node_ids 至少需要 2 个节点"}, status_code=400)
    if _coerce_int(new_group.get("aggregator_node_id"), 0) <= 0:
        return JSONResponse({"ok": False, "error": "aggregator_node_id 无效"}, status_code=400)

    async def _invoke_sync_call(func: Any, req_payload: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
        ret = await func(req_payload, user=user)
        if isinstance(ret, JSONResponse):
            status0 = int(ret.status_code or 500)
            data0 = _sync_job_parse_json_response(ret)
            if "ok" not in data0:
                data0["ok"] = status0 < 400
            return status0, data0
        if isinstance(ret, dict):
            return (200 if bool(ret.get("ok", True)) else 500), ret
        return 500, {"ok": False, "error": "unknown_response_type"}

    save_payload = _mptcp_group_to_save_payload(new_group, sender_node_id=int(new_sender_id), sync_id=sync_id)
    if is_async_job:
        save_payload["_async_job"] = True

    migrated_sender = int(new_sender_id) != int(old_sender_id)
    cleanup_payload = _mptcp_group_to_save_payload(old_group, sender_node_id=int(old_sender_id), sync_id=sync_id)
    cleanup_payload = {
        "sender_node_id": int(old_sender_id),
        "sync_id": sync_id,
        "member_node_ids": _mptcp_parse_node_ids(cleanup_payload.get("member_node_ids")),
        "aggregator_node_id": _coerce_int(cleanup_payload.get("aggregator_node_id"), 0),
    }
    if is_async_job:
        cleanup_payload["_async_job"] = True

    cleanup_data: Dict[str, Any] = {}
    if migrated_sender:
        cleanup_status, cleanup_data = await _invoke_sync_call(api_mptcp_tunnel_delete, cleanup_payload)
        if not (cleanup_status < 400 and bool(cleanup_data.get("ok") is True)):
            err_txt = _sync_job_error_text(cleanup_data, "old_sender_cleanup_failed")
            return JSONResponse(
                {
                    "ok": False,
                    "error": f"隧道组更新失败：清理旧入口失败（{err_txt}）",
                    "stage": "cleanup_old_sender",
                    "sync_id": sync_id,
                    "old_sender_node_id": int(old_sender_id),
                    "sender_node_id": int(new_sender_id),
                    "cleanup": cleanup_data,
                },
                status_code=(cleanup_status if cleanup_status >= 400 else 500),
            )

    save_status, save_data = await _invoke_sync_call(api_mptcp_tunnel_save, save_payload)
    if not (save_status < 400 and bool(save_data.get("ok") is True)):
        rollback_data: Dict[str, Any] = {}
        rollback_ok = False
        if migrated_sender:
            rollback_payload = _mptcp_group_to_save_payload(old_group, sender_node_id=int(old_sender_id), sync_id=sync_id)
            if is_async_job:
                rollback_payload["_async_job"] = True
            rb_status, rb_data = await _invoke_sync_call(api_mptcp_tunnel_save, rollback_payload)
            rollback_data = rb_data
            rollback_ok = bool(rb_status < 400 and isinstance(rb_data, dict) and rb_data.get("ok") is True)
        err_txt = _sync_job_error_text(save_data, "save_failed")
        return JSONResponse(
            {
                "ok": False,
                "error": f"隧道组更新失败：{err_txt}",
                "stage": "save_new_sender",
                "sync_id": sync_id,
                "old_sender_node_id": int(old_sender_id),
                "sender_node_id": int(new_sender_id),
                "cleanup": cleanup_data,
                "rollback": {"ok": bool(rollback_ok), "result": rollback_data},
                "save": save_data,
            },
            status_code=(save_status if save_status >= 400 else 500),
        )

    out = dict(save_data) if isinstance(save_data, dict) else {"ok": True}
    out["sender_node_id"] = int(new_sender_id)
    out["old_sender_node_id"] = int(old_sender_id)
    out["group_update"] = {
        "sync_id": sync_id,
        "migrated_sender": bool(migrated_sender),
        "old_sender_node_id": int(old_sender_id),
        "sender_node_id": int(new_sender_id),
    }
    if migrated_sender:
        out["migrated_cleanup"] = {"ok": True, "result": cleanup_data}
    return out


@router.post("/api/intranet_tunnel/delete_async")
async def api_intranet_tunnel_delete_async(payload: Dict[str, Any], user: str = Depends(require_login)):
    if not isinstance(payload, dict):
        return JSONResponse({"ok": False, "error": "payload 无效"}, status_code=400)
    try:
        sender_id = int(payload.get("sender_node_id") or 0)
        receiver_id = int(payload.get("receiver_node_id") or 0)
    except Exception:
        sender_id = 0
        receiver_id = 0
    if sender_id > 0 and receiver_id > 0 and sender_id != receiver_id:
        receiver = get_node(int(receiver_id))
        # Peer node may have been removed already: allow sender-side cleanup path.
        policy_receiver_id = int(receiver_id) if receiver else int(sender_id)
        denied = _check_sync_policy(user, "intranet", "delete", sender_id, policy_receiver_id)
        if isinstance(denied, JSONResponse):
            return denied
    job = _sync_job_enqueue(kind="intranet_delete", payload=payload, user=user)
    return {"ok": True, "job": job}


@router.post("/api/wss_tunnel/save")
async def api_wss_tunnel_save(payload: Dict[str, Any], user: str = Depends(require_login)):
    rule_user_ref = _resolve_rule_user(user)
    try:
        sender_id = int(payload.get("sender_node_id") or 0)
        receiver_id = int(payload.get("receiver_node_id") or 0)
    except Exception:
        sender_id = 0
        receiver_id = 0

    if sender_id <= 0 or receiver_id <= 0 or sender_id == receiver_id:
        return JSONResponse({"ok": False, "error": "sender_node_id / receiver_node_id 无效"}, status_code=400)
    is_async_job = bool(isinstance(payload, dict) and payload.get("_async_job") is True)
    denied = _check_sync_policy(user, "wss", "save", sender_id, receiver_id)
    if isinstance(denied, JSONResponse):
        return denied

    sender = get_node(sender_id)
    receiver = get_node(receiver_id)
    if not sender or not receiver:
        return JSONResponse({"ok": False, "error": "节点不存在"}, status_code=404)

    listen = str(payload.get("listen") or "").strip()
    remotes = payload.get("remotes") or []
    if isinstance(remotes, str):
        remotes = [x.strip() for x in remotes.splitlines() if x.strip()]
    if not isinstance(remotes, list):
        remotes = []
    remotes = [str(x).strip() for x in remotes if str(x).strip()]

    disabled = bool(payload.get("disabled", False))
    balance = str(payload.get("balance") or "roundrobin").strip() or "roundrobin"
    raw_protocol = str(payload.get("protocol") or "tcp+udp").strip().lower()
    if raw_protocol not in ("tcp", "udp", "tcp+udp"):
        raw_protocol = "tcp+udp"
    protocol = raw_protocol

    if not listen:
        return JSONResponse({"ok": False, "error": "listen 不能为空"}, status_code=400)
    if not remotes:
        return JSONResponse({"ok": False, "error": "目标地址不能为空"}, status_code=400)

    _lh, sender_listen_port = split_host_port(listen)
    if sender_listen_port is None:
        return JSONResponse({"ok": False, "error": "listen 格式不正确，请使用 0.0.0.0:端口"}, status_code=400)

    sync_id = str(payload.get("sync_id") or "").strip() or uuid.uuid4().hex

    # If editing an existing synced rule and switching receiver node, remove old receiver-side rule.
    sender_pool = await load_pool_for_node(sender)
    denied_owner = _deny_if_sync_not_owned(user, sync_id, sender_pool)
    if isinstance(denied_owner, JSONResponse):
        return denied_owner
    old_receiver_id: int = 0
    try:
        for ep in sender_pool.get("endpoints") or []:
            if not isinstance(ep, dict):
                continue
            ex0 = ep.get("extra_config") or {}
            if not isinstance(ex0, dict):
                continue
            if str(ex0.get("sync_id") or "") != str(sync_id):
                continue
            if str(ex0.get("sync_role") or "") != "sender":
                continue
            old_receiver_id = int(ex0.get("sync_peer_node_id") or 0)
            break
    except Exception:
        old_receiver_id = 0

    old_receiver: Optional[Dict[str, Any]] = None
    old_receiver_pool: Optional[Dict[str, Any]] = None
    if old_receiver_id > 0 and old_receiver_id != receiver_id:
        old_receiver = get_node(old_receiver_id)
        if old_receiver:
            try:
                old_receiver_pool = await load_pool_for_node(old_receiver)
                denied_owner = _deny_if_sync_not_owned(user, sync_id, old_receiver_pool)
                if isinstance(denied_owner, JSONResponse):
                    return denied_owner
                remove_endpoints_by_sync_id(old_receiver_pool, sync_id)
                set_desired_pool(old_receiver_id, old_receiver_pool)
            except Exception:
                old_receiver = None
                old_receiver_pool = None

    receiver_pool = await load_pool_for_node(receiver)
    denied_owner = _deny_if_sync_not_owned(user, sync_id, receiver_pool)
    if isinstance(denied_owner, JSONResponse):
        return denied_owner

    # WSS now uses single fixed relay tunnel port (default 28443).
    server_port = int(_WSS_RELAY_TUNNEL_PORT)
    raw_tunnel_port = payload.get("tunnel_port")
    if raw_tunnel_port is None or raw_tunnel_port == "":
        raw_tunnel_port = payload.get("server_port")
    if raw_tunnel_port is not None and raw_tunnel_port != "":
        try:
            server_port = int(raw_tunnel_port)
        except Exception:
            return JSONResponse({"ok": False, "error": "tunnel_port 必须是数字"}, status_code=400)
    if server_port <= 0 or server_port > 65535:
        return JSONResponse({"ok": False, "error": "tunnel_port 端口范围必须是 1-65535"}, status_code=400)

    override_host = normalize_host_input(str(payload.get("server_host") or ""))
    receiver_host = override_host or node_host_for_realm(receiver)
    if not receiver_host:
        return JSONResponse(
            {"ok": False, "error": "出口节点地址为空。请检查 receiver 节点 base_url 或填写 server_host。"},
            status_code=400,
        )

    now_ts = int(datetime.now(timezone.utc).timestamp())
    existing_token, existing_token_grace = _extract_intranet_token_meta(sender_pool, sync_id, now_ts)
    req_token = str(payload.get("token") or "").strip()
    token = req_token or existing_token or uuid.uuid4().hex

    now_iso = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    # Panel-only meta (remark / favorite)
    has_remark = "remark" in payload
    has_favorite = "favorite" in payload

    def _coerce_bool(v: Any) -> bool:
        if isinstance(v, bool):
            return v
        s = str(v or "").strip().lower()
        return s in ("1", "true", "yes", "y", "on")

    tunnel_tls_verify = False
    if "tunnel_tls_verify" in payload:
        tunnel_tls_verify = _coerce_bool(payload.get("tunnel_tls_verify"))

    server_cert_pem = ""
    cert_fetch_err = ""
    if tunnel_tls_verify:
        # Reversed tunnel mode: sender side is client, receiver side is server.
        # Prefer cert already cached on sender-side synced endpoint.
        server_cert_pem = _intranet_cert_from_existing_receiver_pool(sender_pool, sync_id)
        if not server_cert_pem:
            cached_cert, cached_err = _sender_cert_from_report_cache(receiver_id)
            if cached_cert:
                server_cert_pem = cached_cert
            else:
                cert_fetch_err = cached_err or ""
                try:
                    receiver_target_base, receiver_target_verify, _receiver_target_route = node_agent_request_target(receiver)
                    cert = await agent_get(
                        receiver_target_base,
                        receiver.get("api_key", ""),
                        "/api/v1/intranet/cert",
                        receiver_target_verify,
                        timeout=_sync_precheck_http_timeout(),
                    )
                    if isinstance(cert, dict) and cert.get("ok") is True:
                        server_cert_pem = str(cert.get("cert_pem") or "").strip()
                    else:
                        cert_fetch_err = _safe_error_text(cert, cert_fetch_err or "cert_unavailable")
                except Exception as exc:
                    msg = str(exc or "").strip()
                    cert_fetch_err = msg or exc.__class__.__name__ or cert_fetch_err or "cert_fetch_failed"
        if not server_cert_pem:
            hint = _intranet_cert_fetch_hint(cert_fetch_err or "cert_empty")
            return JSONResponse(
                {
                    "ok": False,
                    "error": f"隧道证书校验已开启，但无法获取入口证书：{hint}。",
                    "detail": cert_fetch_err or "cert_empty",
                },
                status_code=400,
            )

    def _find_meta(pool: Dict[str, Any]) -> Tuple[str, Optional[bool]]:
        try:
            for ep in (pool or {}).get("endpoints") or []:
                if not isinstance(ep, dict):
                    continue
                ex0 = ep.get("extra_config") or {}
                if not isinstance(ex0, dict):
                    continue
                if str(ex0.get("sync_id") or "") != str(sync_id):
                    continue
                r = str(ep.get("remark") or "").strip()
                f_raw = ep.get("favorite")
                f_val: Optional[bool] = None
                if f_raw is not None:
                    try:
                        f_val = bool(f_raw)
                    except Exception:
                        f_val = None
                return r, f_val
        except Exception:
            pass
        return "", None

    existing_remark = ""
    existing_fav: Optional[bool] = None
    if (not has_remark) or (not has_favorite):
        r1, f1 = _find_meta(sender_pool)
        r2, f2 = _find_meta(receiver_pool)
        existing_remark = r1 or r2 or ""
        existing_fav = f1 if f1 is not None else f2

    remark = str(payload.get("remark") or "").strip() if has_remark else str(existing_remark or "").strip()
    if len(remark) > 200:
        remark = remark[:200]
    favorite = _coerce_bool(payload.get("favorite")) if has_favorite else bool(existing_fav or False)

    has_qos = "qos" in payload
    if has_qos:
        qos, qos_err = _normalize_qos_payload(payload.get("qos"))
        if qos_err:
            return JSONResponse({"ok": False, "error": qos_err}, status_code=400)
    else:
        qos_sender = _find_sync_qos(sender_pool, sync_id)
        qos_receiver = _find_sync_qos(receiver_pool, sync_id)
        qos = qos_sender or qos_receiver

    token_candidates, token_grace = _build_intranet_tokens(
        primary_token=token,
        previous_primary=existing_token,
        previous_grace=existing_token_grace,
        now_ts=now_ts,
    )

    sender_extra: Dict[str, Any] = {
        "intranet_role": "client",
        "intranet_peer_node_id": receiver_id,
        "intranet_peer_node_name": receiver.get("name"),
        "intranet_peer_host": receiver_host,
        "intranet_server_port": server_port,
        "intranet_token": token,
        "intranet_tokens": token_candidates,
        "intranet_original_remotes": remotes,
        "intranet_server_cert_pem": server_cert_pem,
        "intranet_tls_verify": bool(tunnel_tls_verify and bool(server_cert_pem)),
        "intranet_sender_listen": listen,
        "intranet_updated_at": now_iso,
        "sync_tunnel_mode": "relay",
        "sync_tunnel_type": "wss_relay",
        # sync meta
        "sync_id": sync_id,
        "sync_role": "sender",
        "sync_peer_node_id": receiver_id,
        "sync_peer_node_name": receiver.get("name"),
        "sync_receiver_port": server_port,
        "sync_sender_listen": listen,
        "sync_original_remotes": remotes,
        "sync_updated_at": now_iso,
    }
    if token_grace:
        sender_extra["intranet_token_grace"] = token_grace
    if qos:
        sender_extra["qos"] = dict(qos)

    sender_ep = {
        "listen": listen,
        "disabled": disabled,
        "balance": balance,
        "protocol": protocol,
        "remotes": remotes,
        "extra_config": sender_extra,
    }
    if qos:
        sender_ep["network"] = {"qos": dict(qos)}

    if remark:
        sender_ep["remark"] = remark
    if favorite:
        sender_ep["favorite"] = True
    stamp_endpoint_owner(sender_ep, rule_user_ref)

    receiver_extra: Dict[str, Any] = {
        "intranet_role": "server",
        "intranet_peer_node_id": sender_id,
        "intranet_peer_node_name": sender.get("name"),
        "intranet_public_host": receiver_host,
        "intranet_server_port": server_port,
        "intranet_token": token,
        "intranet_tokens": token_candidates,
        "intranet_original_remotes": remotes,
        "intranet_updated_at": now_iso,
        "sync_tunnel_mode": "relay",
        "sync_tunnel_type": "wss_relay",
        # sync meta
        "sync_id": sync_id,
        "sync_role": "receiver",
        "sync_lock": True,
        "sync_from_node_id": sender_id,
        "sync_from_node_name": sender.get("name"),
        "sync_sender_listen": listen,
        "sync_original_remotes": remotes,
        "sync_updated_at": now_iso,
    }
    if token_grace:
        receiver_extra["intranet_token_grace"] = token_grace
    if qos:
        receiver_extra["qos"] = dict(qos)

    receiver_ep = {
        "listen": format_addr("0.0.0.0", 0),
        "disabled": disabled,
        "balance": balance,
        "protocol": protocol,
        "remotes": remotes,
        "extra_config": receiver_extra,
    }
    if qos:
        receiver_ep["network"] = {"qos": dict(qos)}

    if remark:
        receiver_ep["remark"] = remark
    if favorite:
        receiver_ep["favorite"] = True
    stamp_endpoint_owner(receiver_ep, rule_user_ref)

    upsert_endpoint_by_sync_id(sender_pool, sync_id, sender_ep)
    upsert_endpoint_by_sync_id(receiver_pool, sync_id, receiver_ep)

    # Save-time validation (sender+receiver): blocking errors + warning hints
    sender_warnings: List[Dict[str, Any]] = []
    receiver_warnings: List[Dict[str, Any]] = []
    try:
        sender_warnings = [i.__dict__ for i in validate_pool_inplace(sender_pool)]
        receiver_warnings = [i.__dict__ for i in validate_pool_inplace(receiver_pool)]
    except PoolValidationError as exc:
        return JSONResponse({"ok": False, "error": str(exc), "issues": [i.__dict__ for i in exc.issues]}, status_code=400)
    except Exception as exc:
        return JSONResponse({"ok": False, "error": f"隧道转发保存失败：规则校验异常（{exc}）"}, status_code=500)

    runtime_issues: List[Dict[str, Any]] = []
    # Async jobs should return quickly; runtime netprobe is kept for sync path only.
    skip_runtime_precheck = bool(is_async_job)
    sync_precheck_enabled = _sync_precheck_enabled()
    if sync_precheck_enabled and (not skip_runtime_precheck):
        i1, i2 = await asyncio.gather(
            _probe_node_rules_precheck(sender, sender_pool, "发送机"),
            _probe_node_rules_precheck(receiver, receiver_pool, "接收机"),
        )
        runtime_issues += list(i1 or [])
        runtime_issues += list(i2 or [])

    precheck_issues: List[Dict[str, Any]] = []
    precheck_seen: set[str] = set()
    for it in sender_warnings + receiver_warnings + runtime_issues:
        if isinstance(it, dict):
            _append_issue(precheck_issues, precheck_seen, it)

    precheck_summary = {
        "enabled": bool(sync_precheck_enabled and (not skip_runtime_precheck)),
        "source": (
            "static_validate+agent_netprobe_rules"
            if (sync_precheck_enabled and (not skip_runtime_precheck))
            else ("static_validate+runtime_skipped_async" if skip_runtime_precheck else "static_validate")
        ),
        "runtime_skipped_async": bool(skip_runtime_precheck),
        "issues": len(precheck_issues),
    }

    try:
        upsert_rule_owner_map(node_id=sender_id, pool=sender_pool)
        upsert_rule_owner_map(node_id=receiver_id, pool=receiver_pool)
    except Exception:
        pass

    s_ver, _ = set_desired_pool(sender_id, sender_pool)
    r_ver, _ = set_desired_pool(receiver_id, receiver_pool)

    apply_items: List[Tuple[Dict[str, Any], Dict[str, Any]]] = [(sender, sender_pool), (receiver, receiver_pool)]
    if old_receiver and isinstance(old_receiver_pool, dict):
        apply_items.append((old_receiver, old_receiver_pool))
    apply_errors = await _apply_pools_strict(apply_items)
    if apply_errors:
        first = apply_errors[0]
        node_txt = str(first.get("node_name") or f"节点#{_coerce_int(first.get('node_id'), 0)}")
        err_txt = str(first.get("error") or "apply_failed")
        return JSONResponse(
            {
                "ok": False,
                "error": f"隧道转发下发失败：{node_txt}（{err_txt}）",
                "apply_errors": apply_errors,
                "sync_id": sync_id,
            },
            status_code=502,
        )

    return {
        "ok": True,
        "sync_id": sync_id,
        "receiver_port": server_port,
        "tunnel_port": server_port,
        "mode": "relay",
        "sender_pool": sender_pool,
        "receiver_pool": receiver_pool,
        "sender_desired_version": s_ver,
        "receiver_desired_version": r_ver,
        "precheck": {
            "issues": precheck_issues,
            "summary": precheck_summary,
        },
    }


@router.post("/api/wss_tunnel/delete")
async def api_wss_tunnel_delete(payload: Dict[str, Any], user: str = Depends(require_login)):
    sync_id = str(payload.get("sync_id") or "").strip()
    if not sync_id:
        return JSONResponse({"ok": False, "error": "sync_id 不能为空"}, status_code=400)
    is_async_job = bool(isinstance(payload, dict) and payload.get("_async_job") is True)

    try:
        sender_id = int(payload.get("sender_node_id") or 0)
        receiver_id = int(payload.get("receiver_node_id") or 0)
    except Exception:
        sender_id = 0
        receiver_id = 0

    if sender_id <= 0 or receiver_id <= 0 or sender_id == receiver_id:
        return JSONResponse({"ok": False, "error": "sender_node_id / receiver_node_id 无效"}, status_code=400)
    sender = get_node(sender_id)
    receiver = get_node(receiver_id)
    if not sender:
        return JSONResponse({"ok": False, "error": "发送节点不存在"}, status_code=404)
    # Receiver may be removed already; treat as sender-only stale-sync cleanup.
    receiver_missing = receiver is None
    policy_receiver_id = int(receiver_id) if not receiver_missing else int(sender_id)
    denied = _check_sync_policy(user, "wss", "delete", sender_id, policy_receiver_id)
    if isinstance(denied, JSONResponse):
        return denied

    sender_pool = await load_pool_for_node(sender)
    receiver_pool = await load_pool_for_node(receiver) if receiver else {"endpoints": []}
    denied_owner = _deny_if_sync_not_owned(user, sync_id, sender_pool, receiver_pool if receiver else {})
    if isinstance(denied_owner, JSONResponse):
        return denied_owner

    remove_endpoints_by_sync_id(sender_pool, sync_id)
    if receiver:
        remove_endpoints_by_sync_id(receiver_pool, sync_id)

    s_ver, _ = set_desired_pool(sender_id, sender_pool)
    r_ver = 0
    if receiver:
        r_ver, _ = set_desired_pool(receiver_id, receiver_pool)

    apply_items: List[Tuple[Dict[str, Any], Dict[str, Any]]] = [(sender, sender_pool)]
    if receiver:
        apply_items.append((receiver, receiver_pool))
    apply_errors = await _apply_pools_strict(apply_items)
    if apply_errors:
        first = apply_errors[0]
        node_txt = str(first.get("node_name") or f"节点#{_coerce_int(first.get('node_id'), 0)}")
        err_txt = str(first.get("error") or "apply_failed")
        return JSONResponse(
            {
                "ok": False,
                "error": f"隧道转发删除后下发失败：{node_txt}（{err_txt}）",
                "apply_errors": apply_errors,
                "sync_id": sync_id,
            },
            status_code=502,
        )

    return {
        "ok": True,
        "sync_id": sync_id,
        "sender_pool": _filter_pool_for_user(user, sender_pool),
        "receiver_pool": (_filter_pool_for_user(user, receiver_pool) if receiver else {"endpoints": []}),
        "sender_desired_version": s_ver,
        "receiver_desired_version": r_ver,
        "receiver_missing": bool(receiver_missing),
    }


@router.post("/api/mptcp_tunnel/save")
async def api_mptcp_tunnel_save(payload: Dict[str, Any], user: str = Depends(require_login)):
    if not isinstance(payload, dict):
        return JSONResponse({"ok": False, "error": "payload 无效"}, status_code=400)
    rule_user_ref = _resolve_rule_user(user)
    is_async_job = bool(payload.get("_async_job") is True)

    def _coerce_bool(v: Any) -> bool:
        if isinstance(v, bool):
            return v
        s = str(v or "").strip().lower()
        return s in ("1", "true", "yes", "y", "on")

    def _parse_member_ids(raw: Any) -> List[int]:
        seq = raw if isinstance(raw, list) else []
        out: List[int] = []
        seen: set[int] = set()
        for item in seq:
            try:
                nid = int(item)
            except Exception:
                continue
            if nid <= 0 or nid in seen:
                continue
            seen.add(nid)
            out.append(nid)
        return out

    def _port_from_payload(primary: str, secondary: str = "") -> Tuple[int, bool, Optional[str]]:
        raw = payload.get(primary)
        if (raw is None or raw == "") and secondary:
            raw = payload.get(secondary)
        explicit = not (raw is None or raw == "")
        if not explicit:
            return 0, False, None
        try:
            p = int(raw)
        except Exception:
            return 0, True, f"{primary} 必须是 1-65535 的整数"
        if p < 1 or p > 65535:
            return 0, True, f"{primary} 端口范围必须是 1-65535"
        return p, True, None

    def _fmt_node(node: Dict[str, Any]) -> str:
        nid = _coerce_int(node.get("id"), 0)
        name = str(node.get("name") or "").strip()
        return f"{name}(#{nid})" if name else f"节点#{nid}"

    try:
        sender_id = int(payload.get("sender_node_id") or 0)
    except Exception:
        sender_id = 0
    if sender_id <= 0:
        return JSONResponse({"ok": False, "error": "sender_node_id 无效"}, status_code=400)

    member_ids = _parse_member_ids(payload.get("member_node_ids"))
    if not member_ids:
        member_ids = _parse_member_ids(payload.get("mptcp_member_node_ids"))
    if len(member_ids) < 1:
        return JSONResponse({"ok": False, "error": "member_node_ids 至少需要 1 个节点"}, status_code=400)
    if sender_id in member_ids:
        return JSONResponse({"ok": False, "error": "成员链路节点（B）不能包含当前入口节点（A）"}, status_code=400)

    try:
        aggregator_id = int(
            payload.get("aggregator_node_id")
            or payload.get("mptcp_aggregator_node_id")
            or payload.get("receiver_node_id")
            or 0
        )
    except Exception:
        aggregator_id = 0
    if aggregator_id <= 0:
        return JSONResponse({"ok": False, "error": "aggregator_node_id 无效"}, status_code=400)
    if aggregator_id == sender_id:
        return JSONResponse({"ok": False, "error": "汇聚节点（C）不能是当前入口节点（A）"}, status_code=400)
    if aggregator_id in member_ids:
        return JSONResponse({"ok": False, "error": "汇聚节点（C）不能同时作为成员链路节点（B）"}, status_code=400)

    sender = get_node(sender_id)
    if not sender:
        return JSONResponse({"ok": False, "error": "入口节点不存在"}, status_code=404)
    aggregator_node = get_node(aggregator_id)
    if not aggregator_node:
        return JSONResponse({"ok": False, "error": "汇聚节点不存在"}, status_code=404)

    member_nodes: Dict[int, Dict[str, Any]] = {}
    missing_members: List[int] = []
    for mid in member_ids:
        n = get_node(mid)
        if not n:
            missing_members.append(mid)
            continue
        member_nodes[mid] = n
    if missing_members:
        return JSONResponse(
            {"ok": False, "error": f"成员链路节点不存在：{','.join([str(x) for x in missing_members])}"},
            status_code=404,
        )

    for nid in member_ids + [aggregator_id]:
        denied = _check_sync_policy(user, "mptcp", "save", sender_id, int(nid))
        if isinstance(denied, JSONResponse):
            return denied

    listen = str(payload.get("listen") or "").strip()
    if not listen:
        return JSONResponse({"ok": False, "error": "listen 不能为空"}, status_code=400)
    _lh, sender_listen_port = split_host_port(listen)
    if sender_listen_port is None:
        return JSONResponse({"ok": False, "error": "listen 格式不正确，请使用 0.0.0.0:端口"}, status_code=400)
    sender_listen_port = int(sender_listen_port)
    if sender_listen_port <= 0 or sender_listen_port > 65535:
        return JSONResponse({"ok": False, "error": "listen 端口范围必须是 1-65535"}, status_code=400)
    sender_listen_host = str(_lh or "0.0.0.0").strip() or "0.0.0.0"

    remotes = payload.get("remotes") or []
    if isinstance(remotes, str):
        remotes = [x.strip() for x in remotes.splitlines() if x.strip()]
    if not isinstance(remotes, list):
        remotes = []
    remotes = [str(x).strip() for x in remotes if str(x).strip()]
    # NOTE: Route B overlay mode may allow empty allowlist.

    disabled = bool(payload.get("disabled", False))
    balance = str(payload.get("balance") or "roundrobin").strip() or "roundrobin"
    protocol = "tcp"
    sync_id = str(payload.get("sync_id") or "").strip() or uuid.uuid4().hex

    sender_pool = await load_pool_for_node(sender)
    denied_owner = _deny_if_sync_not_owned(user, sync_id, sender_pool)
    if isinstance(denied_owner, JSONResponse):
        return denied_owner

    old_sender_ex: Dict[str, Any] = {}
    try:
        for ep in sender_pool.get("endpoints") or []:
            if not isinstance(ep, dict):
                continue
            ex0 = ep.get("extra_config") or {}
            if not isinstance(ex0, dict):
                continue
            if str(ex0.get("sync_id") or "").strip() != sync_id:
                continue
            role = str(ex0.get("mptcp_role") or ex0.get("sync_role") or "").strip().lower()
            mode = str(ex0.get("forward_mode") or "").strip().lower()
            if role == "sender" or mode == "mptcp":
                old_sender_ex = ex0
                break
    except Exception:
        old_sender_ex = {}

    old_member_ids = _parse_member_ids(old_sender_ex.get("mptcp_member_node_ids"))
    old_agg_id = _coerce_int(old_sender_ex.get("mptcp_aggregator_node_id") or old_sender_ex.get("sync_peer_node_id"), 0)
    old_agg_port = _coerce_int(old_sender_ex.get("mptcp_aggregator_port"), 0)
    old_channel_port = _coerce_int(old_sender_ex.get("mptcp_channel_port"), 0)
    fixed_tunnel_port = int(_MPTCP_TUNNEL_PORT)
    use_fixed_tunnel_port = bool(_MPTCP_FIXED_TUNNEL_PORT_ENABLED)
    if use_fixed_tunnel_port:
        sender_listen_port = int(fixed_tunnel_port)
        listen = format_addr(sender_listen_host, int(sender_listen_port))

    channel_port, explicit_channel_port, channel_port_err = _port_from_payload("channel_port", "mptcp_channel_port")
    if channel_port_err:
        return JSONResponse({"ok": False, "error": channel_port_err}, status_code=400)
    if use_fixed_tunnel_port:
        channel_port = int(fixed_tunnel_port)
        explicit_channel_port = False
    elif not explicit_channel_port:
        if 1 <= old_channel_port <= 65535:
            channel_port = int(old_channel_port)
        else:
            channel_port = int(sender_listen_port)

    aggregator_port, explicit_agg_port, agg_port_err = _port_from_payload("aggregator_port", "mptcp_aggregator_port")
    if agg_port_err:
        return JSONResponse({"ok": False, "error": agg_port_err}, status_code=400)
    if use_fixed_tunnel_port:
        aggregator_port = int(fixed_tunnel_port)
        explicit_agg_port = False
    elif not explicit_agg_port:
        if old_agg_port >= 1 and old_agg_port <= 65535:
            aggregator_port = int(old_agg_port)
        else:
            aggregator_port = int(channel_port)

    # ---------------- Route B: overlay (reusable tunnel group) ----------------
    # overlay_enabled controls whether C forwards to a local exit proxy (dynamic destination).
    overlay_enabled: bool
    if ("overlay_enabled" in payload) or ("mptcp_overlay_enabled" in payload):
        overlay_enabled = _coerce_bool(payload.get("overlay_enabled") if "overlay_enabled" in payload else payload.get("mptcp_overlay_enabled"))
    else:
        overlay_enabled = _coerce_bool(old_sender_ex.get("mptcp_overlay_enabled")) if ("mptcp_overlay_enabled" in old_sender_ex) else False

    overlay_exit_port, overlay_exit_port_explicit, overlay_exit_port_err = _port_from_payload(
        "overlay_exit_port", "mptcp_overlay_exit_port"
    )
    if overlay_exit_port_err:
        return JSONResponse({"ok": False, "error": overlay_exit_port_err}, status_code=400)
    if not overlay_exit_port_explicit:
        old_overlay_exit_port = _coerce_int(old_sender_ex.get("mptcp_overlay_exit_port"), 0)
        if 1 <= old_overlay_exit_port <= 65535:
            overlay_exit_port = int(old_overlay_exit_port)
        else:
            overlay_exit_port = int(_MPTCP_OVERLAY_EXIT_PORT)

    overlay_token_raw = str(payload.get("overlay_token") or payload.get("mptcp_overlay_token") or "").strip()
    old_overlay_token = str(old_sender_ex.get("mptcp_overlay_token") or "").strip()
    overlay_token = overlay_token_raw or old_overlay_token
    if overlay_enabled and not overlay_token:
        overlay_token = uuid.uuid4().hex

    # In non-overlay mode, final remotes are required.
    if (not overlay_enabled) and (not remotes):
        return JSONResponse({"ok": False, "error": "目标地址不能为空"}, status_code=400)

    scheduler_raw = str(
        payload.get("scheduler")
        or payload.get("mptcp_scheduler")
        or old_sender_ex.get("mptcp_scheduler")
        or "aggregate"
    ).strip().lower()
    if scheduler_raw not in ("aggregate", "backup", "hybrid"):
        scheduler_raw = "aggregate"

    def _read_nonneg_int(new_key: str, old_key: str, label: str) -> Tuple[Optional[int], Optional[str]]:
        rv = payload.get(new_key)
        if rv is None:
            rv = payload.get(old_key)
        if rv is None or str(rv).strip() == "":
            old_v = old_sender_ex.get(old_key)
            iv = _coerce_nonneg_int(old_v)
            return iv, None
        iv = _coerce_nonneg_int(rv)
        if iv is None:
            return None, f"{label} 必须是非负整数"
        return iv, None

    failover_rtt, err_rtt = _read_nonneg_int("failover_rtt_ms", "mptcp_failover_rtt_ms", "RTT 阈值")
    if err_rtt:
        return JSONResponse({"ok": False, "error": err_rtt}, status_code=400)
    failover_jitter, err_jitter = _read_nonneg_int("failover_jitter_ms", "mptcp_failover_jitter_ms", "抖动阈值")
    if err_jitter:
        return JSONResponse({"ok": False, "error": err_jitter}, status_code=400)

    loss_raw = payload.get("failover_loss_pct")
    if loss_raw is None:
        loss_raw = payload.get("mptcp_failover_loss_pct")
    if loss_raw is None or str(loss_raw).strip() == "":
        old_loss = old_sender_ex.get("mptcp_failover_loss_pct")
        failover_loss_pct = None
        if old_loss is not None and str(old_loss).strip() != "":
            try:
                n0 = float(old_loss)
                if 0.0 <= n0 <= 100.0:
                    failover_loss_pct = float(round(n0, 2))
            except Exception:
                failover_loss_pct = None
    else:
        try:
            n = float(str(loss_raw).strip())
        except Exception:
            return JSONResponse({"ok": False, "error": "丢包阈值必须是 0-100 的数字"}, status_code=400)
        if n < 0.0 or n > 100.0:
            return JSONResponse({"ok": False, "error": "丢包阈值必须是 0-100 的数字"}, status_code=400)
        failover_loss_pct = float(round(n, 2))

    agg_host_raw: Any = None
    if "aggregator_host" in payload:
        agg_host_raw = payload.get("aggregator_host")
    elif "mptcp_aggregator_host" in payload:
        agg_host_raw = payload.get("mptcp_aggregator_host")
    override_agg_host = normalize_host_input(str(agg_host_raw or "")) if agg_host_raw is not None else ""
    aggregator_host = override_agg_host or node_host_for_realm(aggregator_node)
    if not aggregator_host:
        return JSONResponse({"ok": False, "error": "汇聚节点地址为空，请检查 C 节点 base_url"}, status_code=400)
    sender_channel_host = node_host_for_realm(sender)
    sender_channel_entry = format_addr(sender_channel_host, int(sender_listen_port)) if sender_channel_host else ""

    current_target_ids = set(member_ids + [aggregator_id])
    old_target_ids: set[int] = set(old_member_ids)
    if old_agg_id > 0:
        old_target_ids.add(old_agg_id)
    stale_target_ids = sorted([nid for nid in old_target_ids if nid > 0 and nid not in current_target_ids])

    stale_nodes: Dict[int, Dict[str, Any]] = {}
    stale_pools: Dict[int, Dict[str, Any]] = {}
    for nid in stale_target_ids:
        node = get_node(int(nid))
        if not node:
            continue
        pool = await load_pool_for_node(node)
        denied_owner = _deny_if_sync_not_owned(user, sync_id, pool)
        if isinstance(denied_owner, JSONResponse):
            return denied_owner
        remove_endpoints_by_sync_id(pool, sync_id)
        stale_nodes[int(nid)] = node
        stale_pools[int(nid)] = pool

    aggregator_pool = await load_pool_for_node(aggregator_node)
    denied_owner = _deny_if_sync_not_owned(user, sync_id, aggregator_pool)
    if isinstance(denied_owner, JSONResponse):
        return denied_owner

    member_pools: Dict[int, Dict[str, Any]] = {}
    for mid in member_ids:
        mnode = member_nodes.get(mid)
        if not isinstance(mnode, dict):
            return JSONResponse({"ok": False, "error": f"成员链路节点不存在：{mid}"}, status_code=404)
        mpool = await load_pool_for_node(mnode)
        denied_owner = _deny_if_sync_not_owned(user, sync_id, mpool)
        if isinstance(denied_owner, JSONResponse):
            return denied_owner
        member_pools[mid] = mpool

    if port_used_by_other_sync(aggregator_pool, int(aggregator_port), sync_id):
        if explicit_agg_port or use_fixed_tunnel_port:
            return JSONResponse(
                {"ok": False, "error": f"汇聚节点端口 {int(aggregator_port)} 已被其他规则占用"},
                status_code=409,
            )
        aggregator_port = choose_receiver_port(aggregator_pool, preferred=int(aggregator_port), ignore_sync_id=sync_id)

    # Overlay exit proxy port must not conflict with any existing listener on C,
    # and must not equal the aggregator listen port.
    if overlay_enabled:
        # prefer stable configuration; auto-choose only when not explicit
        if int(overlay_exit_port) == int(aggregator_port):
            if overlay_exit_port_explicit:
                return JSONResponse(
                    {"ok": False, "error": f"overlay_exit_port 不能与汇聚端口相同（{int(aggregator_port)}）"},
                    status_code=409,
                )
            overlay_exit_port = int(_MPTCP_OVERLAY_EXIT_PORT)

        def _port_used_any(pool_obj: Dict[str, Any], p0: int) -> bool:
            for ep0 in (pool_obj.get("endpoints") or []):
                if not isinstance(ep0, dict):
                    continue
                _hh, _pp = split_host_port(str(ep0.get("listen") or ""))
                if _pp is None:
                    continue
                try:
                    if int(_pp) == int(p0):
                        return True
                except Exception:
                    continue
            return False

        if _port_used_any(aggregator_pool, int(overlay_exit_port)):
            if overlay_exit_port_explicit:
                return JSONResponse(
                    {"ok": False, "error": f"汇聚节点 overlay_exit_port {int(overlay_exit_port)} 已被其他规则占用"},
                    status_code=409,
                )
            overlay_exit_port = choose_receiver_port(aggregator_pool, preferred=int(overlay_exit_port), ignore_sync_id=None)
            if int(overlay_exit_port) == int(aggregator_port):
                overlay_exit_port = choose_receiver_port(aggregator_pool, preferred=int(_MPTCP_OVERLAY_EXIT_PORT), ignore_sync_id=None)

    existing_member_ports: Dict[int, int] = {}
    old_port_map = old_sender_ex.get("mptcp_member_ports")
    if isinstance(old_port_map, dict):
        for k, v in old_port_map.items():
            try:
                nid = int(k)
                p = int(v)
            except Exception:
                continue
            if nid > 0 and 1 <= p <= 65535:
                existing_member_ports[nid] = p

    member_ports: Dict[int, int] = {}
    member_hosts: Dict[int, str] = {}
    for mid in member_ids:
        mnode = member_nodes[mid]
        mpool = member_pools[mid]
        mhost = node_host_for_realm(mnode)
        if not mhost:
            return JSONResponse({"ok": False, "error": f"成员节点地址为空：{_fmt_node(mnode)}"}, status_code=400)
        member_hosts[mid] = mhost

        if use_fixed_tunnel_port:
            p0 = int(fixed_tunnel_port)
        else:
            p0 = existing_member_ports.get(mid, 0)
            if not (1 <= p0 <= 65535):
                p1 = find_sync_listen_port(mpool, sync_id, role=None)
                p0 = int(p1 or 0)
            if not (1 <= p0 <= 65535):
                p0 = int(channel_port)
        if port_used_by_other_sync(mpool, p0, sync_id):
            if use_fixed_tunnel_port:
                return JSONResponse(
                    {
                        "ok": False,
                        "error": f"成员链路节点 {_fmt_node(mnode)} 的固定端口 {int(p0)} 已被其他规则占用",
                    },
                    status_code=409,
                )
            p0 = choose_receiver_port(mpool, preferred=int(sender_listen_port), ignore_sync_id=sync_id)
        member_ports[mid] = int(p0)

    now_iso = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    # Panel-only meta (remark / favorite)
    has_remark = "remark" in payload
    has_favorite = "favorite" in payload

    def _find_meta(pools: List[Dict[str, Any]]) -> Tuple[str, Optional[bool]]:
        try:
            for pool in pools:
                for ep in (pool or {}).get("endpoints") or []:
                    if not isinstance(ep, dict):
                        continue
                    ex0 = ep.get("extra_config") or {}
                    if not isinstance(ex0, dict):
                        continue
                    if str(ex0.get("sync_id") or "") != str(sync_id):
                        continue
                    r = str(ep.get("remark") or "").strip()
                    f_raw = ep.get("favorite")
                    f_val: Optional[bool] = None
                    if f_raw is not None:
                        try:
                            f_val = bool(f_raw)
                        except Exception:
                            f_val = None
                    return r, f_val
        except Exception:
            pass
        return "", None

    existing_remark = ""
    existing_fav: Optional[bool] = None
    if (not has_remark) or (not has_favorite):
        scan_pools = [sender_pool, aggregator_pool] + [member_pools[mid] for mid in member_ids]
        existing_remark, existing_fav = _find_meta(scan_pools)

    remark = str(payload.get("remark") or "").strip() if has_remark else str(existing_remark or "").strip()
    if len(remark) > 200:
        remark = remark[:200]
    favorite = _coerce_bool(payload.get("favorite")) if has_favorite else bool(existing_fav or False)

    has_qos = "qos" in payload
    if has_qos:
        qos, qos_err = _normalize_qos_payload(payload.get("qos"))
        if qos_err:
            return JSONResponse({"ok": False, "error": qos_err}, status_code=400)
    else:
        qos = _find_sync_qos(sender_pool, sync_id) or _find_sync_qos(aggregator_pool, sync_id)
        if not qos:
            for mid in member_ids:
                qos = _find_sync_qos(member_pools[mid], sync_id)
                if qos:
                    break

    member_names: List[str] = []
    for mid in member_ids:
        mnode = member_nodes[mid]
        member_names.append(str(mnode.get("name") or f"节点-{mid}"))
    aggregator_name = str(aggregator_node.get("name") or f"节点-{aggregator_id}")

    sender_member_targets: List[str] = []
    member_ports_payload: Dict[str, int] = {}
    for mid in member_ids:
        sender_member_targets.append(format_addr(member_hosts[mid], member_ports[mid]))
        member_ports_payload[str(mid)] = int(member_ports[mid])

    sender_extra: Dict[str, Any] = {
        "forward_mode": "mptcp",
        "mptcp_role": "sender",
        "mptcp_member_node_ids": list(member_ids),
        "mptcp_member_node_names": list(member_names),
        "mptcp_member_ports": dict(member_ports_payload),
        "mptcp_member_targets": list(sender_member_targets),
        "mptcp_aggregator_node_id": int(aggregator_id),
        "mptcp_aggregator_node_name": aggregator_name,
        "mptcp_aggregator_host": aggregator_host,
        "mptcp_aggregator_port": int(aggregator_port),
        "mptcp_scheduler": scheduler_raw,
        "mptcp_updated_at": now_iso,
        "sync_tunnel_mode": "mptcp",
        "sync_tunnel_type": "mptcp",
        "sync_id": sync_id,
        "sync_role": "sender",
        "sync_peer_node_id": int(aggregator_id),
        "sync_peer_node_name": aggregator_name,
        "sync_sender_listen": listen,
        "sync_original_remotes": list(remotes),
        "mptcp_channel_port": int(channel_port),
        "mptcp_channel_entry_host": str(sender_channel_host or ""),
        "mptcp_channel_entry": str(sender_channel_entry or ""),
        "mptcp_channel_reusable": bool(use_fixed_tunnel_port),
        "sync_updated_at": now_iso,
    }

    # Route B overlay: keep config on all three roles for easier UI reconstruction.
    sender_extra["mptcp_overlay_enabled"] = bool(overlay_enabled)
    if overlay_token:
        sender_extra["mptcp_overlay_token"] = str(overlay_token)
    sender_extra["mptcp_overlay_exit_host"] = str(_MPTCP_OVERLAY_EXIT_HOST or "127.0.0.1")
    sender_extra["mptcp_overlay_exit_port"] = int(overlay_exit_port)
    sender_extra["mptcp_overlay_allowlist"] = list(remotes)
    if failover_rtt is not None:
        sender_extra["mptcp_failover_rtt_ms"] = int(failover_rtt)
    if failover_jitter is not None:
        sender_extra["mptcp_failover_jitter_ms"] = int(failover_jitter)
    if failover_loss_pct is not None:
        sender_extra["mptcp_failover_loss_pct"] = float(failover_loss_pct)
    if qos:
        sender_extra["qos"] = dict(qos)

    sender_ep: Dict[str, Any] = {
        "listen": listen,
        "disabled": bool(disabled),
        "balance": balance,
        "protocol": protocol,
        "remotes": list(sender_member_targets),
        "send_mptcp": True,
        "extra_config": sender_extra,
    }
    if qos:
        sender_ep["network"] = {"qos": dict(qos)}
    if remark:
        sender_ep["remark"] = remark
    if favorite:
        sender_ep["favorite"] = True
    stamp_endpoint_owner(sender_ep, rule_user_ref)
    upsert_endpoint_by_sync_id(sender_pool, sync_id, sender_ep)

    member_target = format_addr(aggregator_host, int(aggregator_port))
    for idx, mid in enumerate(member_ids):
        mnode = member_nodes[mid]
        mpool = member_pools[mid]
        mname = str(mnode.get("name") or f"节点-{mid}")
        mport = int(member_ports[mid])
        member_extra: Dict[str, Any] = {
            "forward_mode": "mptcp",
            "mptcp_role": "member",
            "mptcp_member_index": int(idx + 1),
            "mptcp_member_node_id": int(mid),
            "mptcp_member_node_name": mname,
            "mptcp_member_port": int(mport),
            "mptcp_member_node_ids": list(member_ids),
            "mptcp_member_node_names": list(member_names),
            "mptcp_aggregator_node_id": int(aggregator_id),
            "mptcp_aggregator_node_name": aggregator_name,
            "mptcp_aggregator_host": aggregator_host,
            "mptcp_aggregator_port": int(aggregator_port),
            "mptcp_scheduler": scheduler_raw,
            "mptcp_updated_at": now_iso,
            "sync_tunnel_mode": "mptcp",
            "sync_tunnel_type": "mptcp",
            "sync_id": sync_id,
            "sync_role": "member",
            "sync_lock": True,
            "sync_from_node_id": int(sender_id),
            "sync_from_node_name": str(sender.get("name") or ""),
            "sync_sender_listen": listen,
            "sync_original_remotes": list(remotes),
            "mptcp_channel_port": int(channel_port),
            "mptcp_channel_entry_host": str(sender_channel_host or ""),
            "mptcp_channel_entry": str(sender_channel_entry or ""),
            "mptcp_channel_reusable": bool(use_fixed_tunnel_port),
            "sync_updated_at": now_iso,
        }

        member_extra["mptcp_overlay_enabled"] = bool(overlay_enabled)
        if overlay_token:
            member_extra["mptcp_overlay_token"] = str(overlay_token)
        member_extra["mptcp_overlay_exit_host"] = str(_MPTCP_OVERLAY_EXIT_HOST or "127.0.0.1")
        member_extra["mptcp_overlay_exit_port"] = int(overlay_exit_port)
        member_extra["mptcp_overlay_allowlist"] = list(remotes)
        if failover_rtt is not None:
            member_extra["mptcp_failover_rtt_ms"] = int(failover_rtt)
        if failover_jitter is not None:
            member_extra["mptcp_failover_jitter_ms"] = int(failover_jitter)
        if failover_loss_pct is not None:
            member_extra["mptcp_failover_loss_pct"] = float(failover_loss_pct)
        if qos:
            member_extra["qos"] = dict(qos)

        member_ep: Dict[str, Any] = {
            "listen": format_addr("0.0.0.0", int(mport)),
            "disabled": bool(disabled),
            "balance": balance,
            "protocol": "tcp",
            "remotes": [member_target],
            "accept_mptcp": True,
            "extra_config": member_extra,
        }
        if qos:
            member_ep["network"] = {"qos": dict(qos)}
        if remark:
            member_ep["remark"] = remark
        if favorite:
            member_ep["favorite"] = True
        stamp_endpoint_owner(member_ep, rule_user_ref)
        upsert_endpoint_by_sync_id(mpool, sync_id, member_ep)

    aggregator_extra: Dict[str, Any] = {
        "forward_mode": "mptcp",
        "mptcp_role": "aggregator",
        "mptcp_member_node_ids": list(member_ids),
        "mptcp_member_node_names": list(member_names),
        "mptcp_member_ports": dict(member_ports_payload),
        "mptcp_aggregator_node_id": int(aggregator_id),
        "mptcp_aggregator_node_name": aggregator_name,
        "mptcp_aggregator_port": int(aggregator_port),
        "mptcp_scheduler": scheduler_raw,
        "mptcp_updated_at": now_iso,
        "sync_tunnel_mode": "mptcp",
        "sync_tunnel_type": "mptcp",
        "sync_id": sync_id,
        "sync_role": "aggregator",
        "sync_lock": True,
        "sync_from_node_id": int(sender_id),
        "sync_from_node_name": str(sender.get("name") or ""),
        "sync_sender_listen": listen,
        "sync_original_remotes": list(remotes),
        "mptcp_channel_port": int(channel_port),
        "mptcp_channel_entry_host": str(sender_channel_host or ""),
        "mptcp_channel_entry": str(sender_channel_entry or ""),
        "mptcp_channel_reusable": bool(use_fixed_tunnel_port),
        "sync_updated_at": now_iso,
    }

    aggregator_extra["mptcp_overlay_enabled"] = bool(overlay_enabled)
    if overlay_token:
        aggregator_extra["mptcp_overlay_token"] = str(overlay_token)
    aggregator_extra["mptcp_overlay_exit_host"] = str(_MPTCP_OVERLAY_EXIT_HOST or "127.0.0.1")
    aggregator_extra["mptcp_overlay_exit_port"] = int(overlay_exit_port)
    aggregator_extra["mptcp_overlay_allowlist"] = list(remotes)
    if failover_rtt is not None:
        aggregator_extra["mptcp_failover_rtt_ms"] = int(failover_rtt)
    if failover_jitter is not None:
        aggregator_extra["mptcp_failover_jitter_ms"] = int(failover_jitter)
    if failover_loss_pct is not None:
        aggregator_extra["mptcp_failover_loss_pct"] = float(failover_loss_pct)
    if qos:
        aggregator_extra["qos"] = dict(qos)

    aggregator_ep: Dict[str, Any] = {
        "listen": format_addr("0.0.0.0", int(aggregator_port)),
        "disabled": bool(disabled),
        "balance": balance,
        "protocol": "tcp",
        "remotes": (
            [format_addr(str(_MPTCP_OVERLAY_EXIT_HOST or "127.0.0.1"), int(overlay_exit_port))]
            if overlay_enabled
            else list(remotes)
        ),
        "accept_mptcp": True,
        "extra_config": aggregator_extra,
    }
    if qos:
        aggregator_ep["network"] = {"qos": dict(qos)}
    if remark:
        aggregator_ep["remark"] = remark
    if favorite:
        aggregator_ep["favorite"] = True
    stamp_endpoint_owner(aggregator_ep, rule_user_ref)
    upsert_endpoint_by_sync_id(aggregator_pool, sync_id, aggregator_ep)

    # Save-time validation (all touched nodes): blocking errors + warning hints
    def _label_issue(node_name: str, issues: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for it in issues:
            if not isinstance(it, dict):
                continue
            d = dict(it)
            msg = str(d.get("message") or "").strip()
            if msg:
                d["message"] = f"{node_name}：{msg}"
            out.append(d)
        return out

    validate_warnings: List[Dict[str, Any]] = []
    touched_for_validate: List[Tuple[Dict[str, Any], Dict[str, Any]]] = [(sender, sender_pool)]
    touched_for_validate += [(member_nodes[mid], member_pools[mid]) for mid in member_ids]
    touched_for_validate.append((aggregator_node, aggregator_pool))
    touched_for_validate += [(stale_nodes[nid], stale_pools[nid]) for nid in stale_target_ids if nid in stale_nodes and nid in stale_pools]

    for node_obj, pool_obj in touched_for_validate:
        node_label = _fmt_node(node_obj)
        try:
            warns = [i.__dict__ for i in validate_pool_inplace(pool_obj)]
        except PoolValidationError as exc:
            return JSONResponse(
                {
                    "ok": False,
                    "error": f"多链路聚合保存失败：{node_label} 规则校验失败（{exc}）",
                    "issues": _label_issue(node_label, [i.__dict__ for i in exc.issues]),
                    "sync_id": sync_id,
                },
                status_code=400,
            )
        except Exception as exc:
            return JSONResponse(
                {"ok": False, "error": f"多链路聚合保存失败：{node_label} 规则校验异常（{exc}）", "sync_id": sync_id},
                status_code=500,
            )
        validate_warnings += _label_issue(node_label, warns)

    runtime_issues: List[Dict[str, Any]] = []
    sync_precheck_enabled = _sync_precheck_enabled()
    # For async save path, deploy first then rely on runtime health/status.
    force_runtime_precheck = False
    runtime_precheck_enabled = bool((sync_precheck_enabled and (not bool(is_async_job))) or force_runtime_precheck)
    skip_runtime_precheck = bool((not runtime_precheck_enabled) and is_async_job)
    if runtime_precheck_enabled:
        precheck_jobs = [
            _probe_node_rules_precheck(
                node_obj,
                pool_obj,
                _fmt_node(node_obj),
                force=force_runtime_precheck,
                only_sync_id=sync_id,
            )
            for node_obj, pool_obj in touched_for_validate
        ]
        try:
            precheck_results = await asyncio.gather(*precheck_jobs, return_exceptions=False)
            for sub in precheck_results:
                runtime_issues += list(sub or [])
        except Exception:
            # Runtime precheck should not block save path unexpectedly.
            pass

    precheck_issues: List[Dict[str, Any]] = []
    precheck_seen: set[str] = set()
    for it in validate_warnings + runtime_issues:
        if isinstance(it, dict):
            _append_issue(precheck_issues, precheck_seen, it)

    precheck_summary = {
        "enabled": bool(runtime_precheck_enabled),
        "source": (
            "static_validate+agent_netprobe_rules"
            if runtime_precheck_enabled
            else ("static_validate+runtime_skipped_async" if skip_runtime_precheck else "static_validate")
        ),
        "runtime_skipped_async": bool(skip_runtime_precheck),
        "forced_target_probe": bool(force_runtime_precheck),
        "issues": len(precheck_issues),
    }

    desired_versions: Dict[int, int] = {}
    # Persist desired pools for all touched nodes.
    touched_for_set: List[Tuple[Dict[str, Any], Dict[str, Any]]] = []
    touched_for_set += [(member_nodes[mid], member_pools[mid]) for mid in member_ids]
    touched_for_set.append((aggregator_node, aggregator_pool))
    touched_for_set.append((sender, sender_pool))
    touched_for_set += [(stale_nodes[nid], stale_pools[nid]) for nid in stale_target_ids if nid in stale_nodes and nid in stale_pools]
    try:
        for node_obj, pool_obj in touched_for_set:
            nid = _coerce_int(node_obj.get("id"), 0)
            if nid <= 0:
                continue
            try:
                upsert_rule_owner_map(node_id=nid, pool=pool_obj)
            except Exception:
                pass
            ver, _ = set_desired_pool(nid, pool_obj)
            desired_versions[int(nid)] = int(ver)
    except Exception as exc:
        return JSONResponse({"ok": False, "error": f"多链路聚合保存失败：写入目标配置失败（{exc}）"}, status_code=500)

    apply_map: Dict[int, Tuple[Dict[str, Any], Dict[str, Any]]] = {}
    for node_obj, pool_obj in touched_for_set:
        nid = _coerce_int(node_obj.get("id"), 0)
        if nid <= 0:
            continue
        apply_map[int(nid)] = (node_obj, pool_obj)
    fallback_queued_nodes: List[Dict[str, Any]] = []
    apply_errors: List[Dict[str, Any]] = []

    async def _apply_stage_node_ids(node_ids: List[int]) -> List[Dict[str, Any]]:
        stage_items: List[Tuple[Dict[str, Any], Dict[str, Any]]] = []
        seen_ids: set[int] = set()
        for raw_nid in node_ids:
            nid0 = _coerce_int(raw_nid, 0)
            if nid0 <= 0 or nid0 in seen_ids:
                continue
            seen_ids.add(nid0)
            pair0 = apply_map.get(int(nid0))
            if not pair0:
                continue
            stage_items.append(pair0)
        if not stage_items:
            return []
        stage_errors = await _apply_pools_strict(stage_items)
        if not stage_errors:
            return []
        fatal_errors: List[Dict[str, Any]] = []
        for item in stage_errors:
            cur = dict(item) if isinstance(item, dict) else {}
            nid = _coerce_int(cur.get("node_id"), 0)
            err_txt0 = str(cur.get("error") or "").strip()
            pair = apply_map.get(int(nid))
            can_fallback = (
                nid > 0
                and isinstance(pair, tuple)
                and len(pair) == 2
                and isinstance(pair[0], dict)
                and isinstance(pair[1], dict)
                and _is_apply_transport_failure(err_txt0)
            )
            if not can_fallback:
                fatal_errors.append(cur)
                continue
            node_obj, pool_obj = pair
            ok_q, new_ver, q_err = _queue_apply_via_report(int(nid), pool_obj)
            if not ok_q:
                cur["error"] = f"{err_txt0 or 'apply_failed'}；上报兜底排队失败：{q_err or 'queue_failed'}"
                fatal_errors.append(cur)
                continue
            desired_versions[int(nid)] = int(new_ver)
            fallback_queued_nodes.append(
                {
                    "node_id": int(nid),
                    "node_name": str(node_obj.get("name") or cur.get("node_name") or f"节点#{nid}"),
                    "desired_version": int(new_ver),
                    "reason": err_txt0 or "direct_apply_failed",
                }
            )
        return fatal_errors

    # Staged rollout for fixed channel:
    # 1) Bring up B/C tunnel path first
    # 2) Then switch A sender entry
    # 3) Finally cleanup stale peers
    stage_plan: List[List[int]] = [
        list(member_ids) + [int(aggregator_id)],
        [int(sender_id)],
        [int(nid) for nid in stale_target_ids],
    ]
    for idx, stage in enumerate(stage_plan):
        stage_errs = await _apply_stage_node_ids(stage)
        if stage_errs:
            apply_errors = stage_errs
            break
        # Give peer listeners a short time window before flipping sender entry.
        if idx == 0:
            try:
                await asyncio.sleep(0.35)
            except Exception:
                pass
    if apply_errors:
        first = apply_errors[0]
        node_txt = str(first.get("node_name") or f"节点#{_coerce_int(first.get('node_id'), 0)}")
        err_txt = str(first.get("error") or "apply_failed")
        return JSONResponse(
            {
                "ok": False,
                "error": f"多链路聚合下发失败：{node_txt}（{err_txt}）",
                "apply_errors": apply_errors,
                "queued_nodes": fallback_queued_nodes,
                "sync_id": sync_id,
            },
            status_code=502,
        )

    postcheck: Dict[str, Any] = {
        "enabled": bool(use_fixed_tunnel_port),
        "aggregator_self": {},
        # A -> B reachability (TCPing each member tunnel entry)
        "sender_to_member": [],
        # B -> C reachability (TCPing each member -> aggregator entry)
        "member_to_aggregator": [],
        # Intersection of members that are OK on both stages (A->B and B->C)
        "working_members": [],
        "overlay_exit_proxy": {},
    }
    if use_fixed_tunnel_port:
        # Ensure C is actually listening on fixed tunnel port before reporting success.
        agg_loop_target = format_addr("127.0.0.1", int(aggregator_port))
        agg_self_probe = await _mptcp_probe_targets_from_node(aggregator_node, [agg_loop_target], timeout_sec=1.2)
        agg_self_raw = agg_self_probe.get("results", {}).get(agg_loop_target) if isinstance(agg_self_probe.get("results"), dict) else {}
        if not isinstance(agg_self_raw, dict):
            agg_self_raw = {"ok": False, "error": str(agg_self_probe.get("error") or "probe_result_missing")}
        agg_self_entry = _mptcp_probe_result_entry(
            agg_loop_target,
            agg_self_raw,
            node_id=int(aggregator_id),
            node_name=str(aggregator_name),
        )
        postcheck["aggregator_self"] = agg_self_entry
        if not bool(agg_self_entry.get("ok") is True):
            return JSONResponse(
                {
                    "ok": False,
                    "error": f"多链路聚合下发后校验失败：C 汇聚节点 {aggregator_name} 未监听端口 {int(aggregator_port)}",
                    "stage": "postcheck_aggregator_listener",
                    "sync_id": sync_id,
                    "target": agg_loop_target,
                    "detail": str(agg_self_entry.get("error") or "listener_not_ready"),
                    "postcheck": postcheck,
                },
                status_code=502,
            )

        # Verify there is at least one workable path:
        #   A -> B(member) -> C
        # We accept partial failures as long as >=1 member is healthy.
        sender_to_member_ok: set[int] = set()
        member_to_agg_ok: set[int] = set()

        # A -> B
        try:
            s_probe = await _mptcp_probe_targets_from_node(sender, sender_member_targets, timeout_sec=1.3)
            results = s_probe.get("results") if isinstance(s_probe.get("results"), dict) else {}
            for mid in member_ids:
                t = format_addr(member_hosts[mid], member_ports[mid])
                raw = results.get(t) if isinstance(results, dict) else {}
                if not isinstance(raw, dict):
                    raw = {"ok": False, "error": str(s_probe.get("error") or "probe_result_missing")}
                ent = _mptcp_probe_result_entry(
                    t,
                    raw,
                    source_node_id=int(sender_id),
                    source_node_name=str(sender.get("name") or ""),
                    target_node_id=int(mid),
                    target_node_name=str(member_nodes[mid].get("name") or f"节点-{mid}"),
                )
                postcheck["sender_to_member"].append(ent)
                if bool(ent.get("ok") is True):
                    sender_to_member_ok.add(int(mid))
        except Exception:
            pass

        # B -> C
        async def _probe_b_to_c(mid: int) -> Dict[str, Any]:
            node_obj = member_nodes.get(int(mid))
            if not isinstance(node_obj, dict):
                return _mptcp_probe_result_entry(
                    member_target,
                    {"ok": False, "error": "member_missing"},
                    source_node_id=int(mid),
                    source_node_name=f"节点-{mid}",
                    target_node_id=int(aggregator_id),
                    target_node_name=str(aggregator_name),
                )
            probe = await _mptcp_probe_targets_from_node(node_obj, [member_target], timeout_sec=1.3)
            raw = probe.get("results", {}).get(member_target) if isinstance(probe.get("results"), dict) else {}
            if not isinstance(raw, dict):
                raw = {"ok": False, "error": str(probe.get("error") or "probe_result_missing")}
            return _mptcp_probe_result_entry(
                member_target,
                raw,
                source_node_id=int(mid),
                source_node_name=str(node_obj.get("name") or f"节点-{mid}"),
                target_node_id=int(aggregator_id),
                target_node_name=str(aggregator_name),
            )

        try:
            bc_entries = await asyncio.gather(*[_probe_b_to_c(int(mid)) for mid in member_ids], return_exceptions=False)
            for ent in bc_entries:
                if isinstance(ent, dict):
                    postcheck["member_to_aggregator"].append(ent)
                    if bool(ent.get("ok") is True):
                        try:
                            member_to_agg_ok.add(int(ent.get("source_node_id") or 0))
                        except Exception:
                            pass
        except Exception:
            pass

        working = sorted([mid for mid in member_ids if int(mid) in sender_to_member_ok and int(mid) in member_to_agg_ok])
        postcheck["working_members"] = working
        if not working:
            return JSONResponse(
                {
                    "ok": False,
                    "error": f"多链路聚合下发后校验失败：A->B 或 B->C 不通（至少需要 1 条可用通道）",
                    "stage": "postcheck_path",
                    "sync_id": sync_id,
                    "detail": "no_working_member",
                    "postcheck": postcheck,
                },
                status_code=502,
            )

    if overlay_enabled:
        # Ensure overlay exit proxy is listening on C (agent-managed, not realm).
        # Use configured overlay exit host (default 127.0.0.1) to avoid false negatives.
        exit_loop_target = format_addr(str(_MPTCP_OVERLAY_EXIT_HOST or "127.0.0.1"), int(overlay_exit_port))
        exit_entry: Dict[str, Any] = {}
        max_attempts = 6
        for attempt in range(max_attempts):
            exit_probe = await _mptcp_probe_targets_from_node(aggregator_node, [exit_loop_target], timeout_sec=1.4)
            exit_raw = exit_probe.get("results", {}).get(exit_loop_target) if isinstance(exit_probe.get("results"), dict) else {}
            if not isinstance(exit_raw, dict):
                exit_raw = {"ok": False, "error": str(exit_probe.get("error") or "probe_result_missing")}
            exit_entry = _mptcp_probe_result_entry(
                exit_loop_target,
                exit_raw,
                node_id=int(aggregator_id),
                node_name=str(aggregator_name),
            )
            if bool(exit_entry.get("ok") is True):
                break
            if attempt < (max_attempts - 1):
                try:
                    await asyncio.sleep(0.35)
                except Exception:
                    pass
        postcheck["overlay_exit_proxy"] = exit_entry
        if not bool(exit_entry.get("ok") is True):
            return JSONResponse(
                {
                    "ok": False,
                    "error": f"多链路聚合下发后校验失败：C 汇聚节点 {aggregator_name} 未监听 overlay_exit_port {int(overlay_exit_port)}",
                    "stage": "postcheck_overlay_exit_proxy",
                    "sync_id": sync_id,
                    "target": exit_loop_target,
                    "detail": str(exit_entry.get("error") or "overlay_exit_not_ready"),
                    "postcheck": postcheck,
                },
                status_code=502,
            )

    return {
        "ok": True,
        "mode": "mptcp",
        "sync_id": sync_id,
        "tunnel_port_mode": ("fixed_group" if use_fixed_tunnel_port else ("manual" if explicit_agg_port else "auto")),
        "tunnel_port": int(fixed_tunnel_port if use_fixed_tunnel_port else aggregator_port),
        "channel_port": int(channel_port),
        "reuse_entry": {
            "host": str(sender_channel_host or ""),
            "port": int(sender_listen_port),
            "target": str(sender_channel_entry or ""),
            "reusable": bool(use_fixed_tunnel_port),
        },
        "overlay": {
            "enabled": bool(overlay_enabled),
            "exit_host": str(_MPTCP_OVERLAY_EXIT_HOST or "127.0.0.1"),
            "exit_port": int(overlay_exit_port),
            "token": str(overlay_token or ""),
            "allowlist": list(remotes),
        },
        "sender_pool": _filter_pool_for_user(user, sender_pool),
        "sender_member_targets": sender_member_targets,
        "member_nodes": [
            {
                "node_id": int(mid),
                "node_name": str(member_nodes[mid].get("name") or ""),
                "listen_port": int(member_ports[mid]),
                "target": format_addr(member_hosts[mid], member_ports[mid]),
            }
            for mid in member_ids
        ],
        "aggregator_node": {
            "node_id": int(aggregator_id),
            "node_name": aggregator_name,
            "listen_port": int(aggregator_port),
            "host": aggregator_host,
        },
        "sender_desired_version": int(desired_versions.get(sender_id, 0)),
        "aggregator_desired_version": int(desired_versions.get(aggregator_id, 0)),
        "member_desired_versions": {
            str(mid): int(desired_versions.get(mid, 0))
            for mid in member_ids
        },
        "stale_desired_versions": {
            str(nid): int(desired_versions.get(nid, 0))
            for nid in stale_target_ids
            if nid in desired_versions
        },
        "precheck": {
            "issues": precheck_issues,
            "summary": precheck_summary,
        },
        "apply_fallback": {
            "queued": bool(fallback_queued_nodes),
            "mode": "agent_report",
            "nodes": fallback_queued_nodes,
        },
        "postcheck": postcheck,
    }


@router.post("/api/mptcp_tunnel/delete")
async def api_mptcp_tunnel_delete(payload: Dict[str, Any], user: str = Depends(require_login)):
    if not isinstance(payload, dict):
        return JSONResponse({"ok": False, "error": "payload 无效"}, status_code=400)
    sync_id = str(payload.get("sync_id") or "").strip()
    if not sync_id:
        return JSONResponse({"ok": False, "error": "sync_id 不能为空"}, status_code=400)

    try:
        sender_id = int(payload.get("sender_node_id") or 0)
    except Exception:
        sender_id = 0
    if sender_id <= 0:
        return JSONResponse({"ok": False, "error": "sender_node_id 无效"}, status_code=400)

    sender = get_node(sender_id)
    if not sender:
        return JSONResponse({"ok": False, "error": "入口节点不存在"}, status_code=404)

    def _parse_member_ids(raw: Any) -> List[int]:
        seq = raw if isinstance(raw, list) else []
        out: List[int] = []
        seen: set[int] = set()
        for item in seq:
            try:
                nid = int(item)
            except Exception:
                continue
            if nid <= 0 or nid in seen:
                continue
            seen.add(nid)
            out.append(nid)
        return out

    sender_pool = await load_pool_for_node(sender)
    denied_owner = _deny_if_sync_not_owned(user, sync_id, sender_pool)
    if isinstance(denied_owner, JSONResponse):
        return denied_owner

    ex_sender: Dict[str, Any] = {}
    try:
        for ep in sender_pool.get("endpoints") or []:
            if not isinstance(ep, dict):
                continue
            ex0 = ep.get("extra_config") or {}
            if not isinstance(ex0, dict):
                continue
            if str(ex0.get("sync_id") or "").strip() != sync_id:
                continue
            role = str(ex0.get("mptcp_role") or ex0.get("sync_role") or "").strip().lower()
            mode = str(ex0.get("forward_mode") or "").strip().lower()
            if role == "sender" or mode == "mptcp":
                ex_sender = ex0
                break
    except Exception:
        ex_sender = {}

    req_member_ids = _parse_member_ids(payload.get("member_node_ids"))
    if not req_member_ids:
        req_member_ids = _parse_member_ids(payload.get("mptcp_member_node_ids"))
    old_member_ids = _parse_member_ids(ex_sender.get("mptcp_member_node_ids"))

    req_agg_id = _coerce_int(
        payload.get("aggregator_node_id")
        or payload.get("mptcp_aggregator_node_id")
        or payload.get("receiver_node_id"),
        0,
    )
    old_agg_id = _coerce_int(ex_sender.get("mptcp_aggregator_node_id") or ex_sender.get("sync_peer_node_id"), 0)

    target_ids: List[int] = []
    seen_targets: set[int] = set()
    for nid in req_member_ids + old_member_ids + ([req_agg_id] if req_agg_id > 0 else []) + ([old_agg_id] if old_agg_id > 0 else []):
        if nid <= 0 or nid == sender_id or nid in seen_targets:
            continue
        seen_targets.add(nid)
        target_ids.append(int(nid))

    for nid in target_ids:
        peer = get_node(int(nid))
        policy_receiver_id = int(nid) if peer else int(sender_id)
        denied = _check_sync_policy(user, "mptcp", "delete", sender_id, policy_receiver_id)
        if isinstance(denied, JSONResponse):
            return denied

    remove_endpoints_by_sync_id(sender_pool, sync_id)

    target_nodes: Dict[int, Dict[str, Any]] = {}
    target_pools: Dict[int, Dict[str, Any]] = {}
    missing_targets: List[int] = []
    for nid in target_ids:
        node = get_node(int(nid))
        if not node:
            missing_targets.append(int(nid))
            continue
        pool = await load_pool_for_node(node)
        denied_owner = _deny_if_sync_not_owned(user, sync_id, pool)
        if isinstance(denied_owner, JSONResponse):
            return denied_owner
        remove_endpoints_by_sync_id(pool, sync_id)
        target_nodes[int(nid)] = node
        target_pools[int(nid)] = pool

    desired_versions: Dict[int, int] = {}
    try:
        try:
            upsert_rule_owner_map(node_id=sender_id, pool=sender_pool)
        except Exception:
            pass
        s_ver, _ = set_desired_pool(sender_id, sender_pool)
        desired_versions[int(sender_id)] = int(s_ver)
        for nid in target_ids:
            if nid not in target_nodes or nid not in target_pools:
                continue
            node = target_nodes[nid]
            pool = target_pools[nid]
            try:
                upsert_rule_owner_map(node_id=int(nid), pool=pool)
            except Exception:
                pass
            ver, _ = set_desired_pool(int(nid), pool)
            desired_versions[int(nid)] = int(ver)
    except Exception as exc:
        return JSONResponse({"ok": False, "error": f"多链路聚合删除失败：写入目标配置失败（{exc}）"}, status_code=500)

    apply_items: List[Tuple[Dict[str, Any], Dict[str, Any]]] = [(sender, sender_pool)]
    apply_items += [(target_nodes[nid], target_pools[nid]) for nid in target_ids if nid in target_nodes and nid in target_pools]
    apply_map: Dict[int, Tuple[Dict[str, Any], Dict[str, Any]]] = {}
    for node_obj, pool_obj in apply_items:
        nid = _coerce_int(node_obj.get("id"), 0)
        if nid > 0:
            apply_map[int(nid)] = (node_obj, pool_obj)
    fallback_queued_nodes: List[Dict[str, Any]] = []
    apply_errors = await _apply_pools_strict(apply_items)
    if apply_errors:
        fatal_errors: List[Dict[str, Any]] = []
        for item in apply_errors:
            cur = dict(item) if isinstance(item, dict) else {}
            nid = _coerce_int(cur.get("node_id"), 0)
            err_txt0 = str(cur.get("error") or "").strip()
            pair = apply_map.get(int(nid))
            can_fallback = (
                nid > 0
                and isinstance(pair, tuple)
                and len(pair) == 2
                and isinstance(pair[0], dict)
                and isinstance(pair[1], dict)
                and _is_apply_transport_failure(err_txt0)
            )
            if not can_fallback:
                fatal_errors.append(cur)
                continue
            node_obj, pool_obj = pair
            ok_q, new_ver, q_err = _queue_apply_via_report(int(nid), pool_obj)
            if not ok_q:
                cur["error"] = f"{err_txt0 or 'apply_failed'}；上报兜底排队失败：{q_err or 'queue_failed'}"
                fatal_errors.append(cur)
                continue
            desired_versions[int(nid)] = int(new_ver)
            fallback_queued_nodes.append(
                {
                    "node_id": int(nid),
                    "node_name": str(node_obj.get("name") or cur.get("node_name") or f"节点#{nid}"),
                    "desired_version": int(new_ver),
                    "reason": err_txt0 or "direct_apply_failed",
                }
            )
        apply_errors = fatal_errors
    if apply_errors:
        first = apply_errors[0]
        node_txt = str(first.get("node_name") or f"节点#{_coerce_int(first.get('node_id'), 0)}")
        err_txt = str(first.get("error") or "apply_failed")
        return JSONResponse(
            {
                "ok": False,
                "error": f"多链路聚合删除后下发失败：{node_txt}（{err_txt}）",
                "apply_errors": apply_errors,
                "queued_nodes": fallback_queued_nodes,
                "sync_id": sync_id,
            },
            status_code=502,
        )

    return {
        "ok": True,
        "mode": "mptcp",
        "sync_id": sync_id,
        "sender_pool": _filter_pool_for_user(user, sender_pool),
        "sender_desired_version": int(desired_versions.get(sender_id, 0)),
        "target_desired_versions": {
            str(nid): int(desired_versions.get(nid, 0))
            for nid in target_ids
            if nid in desired_versions
        },
        "missing_target_nodes": missing_targets,
        "apply_fallback": {
            "queued": bool(fallback_queued_nodes),
            "mode": "agent_report",
            "nodes": fallback_queued_nodes,
        },
    }


@router.post("/api/intranet_tunnel/save")
async def api_intranet_tunnel_save(payload: Dict[str, Any], user: str = Depends(require_login)):
    rule_user_ref = _resolve_rule_user(user)
    try:
        sender_id = int(payload.get("sender_node_id") or 0)
        receiver_id = int(payload.get("receiver_node_id") or 0)
    except Exception:
        sender_id = 0
        receiver_id = 0

    if sender_id <= 0 or receiver_id <= 0 or sender_id == receiver_id:
        return JSONResponse({"ok": False, "error": "sender_node_id / receiver_node_id 无效"}, status_code=400)
    is_async_job = bool(isinstance(payload, dict) and payload.get("_async_job") is True)
    denied = _check_sync_policy(user, "intranet", "save", sender_id, receiver_id)
    if isinstance(denied, JSONResponse):
        return denied

    sender = get_node(sender_id)
    receiver = get_node(receiver_id)
    if not sender or not receiver:
        return JSONResponse({"ok": False, "error": "节点不存在"}, status_code=404)

    if not bool(receiver.get("is_private") or False):
        return JSONResponse(
            {"ok": False, "error": "所选节点未标记为内网机器，请在节点设置中勾选“内网机器”"},
            status_code=400,
        )

    listen = str(payload.get("listen") or "").strip()
    remotes = payload.get("remotes") or []
    if isinstance(remotes, str):
        remotes = [x.strip() for x in remotes.splitlines() if x.strip()]
    if not isinstance(remotes, list):
        remotes = []
    remotes = [str(x).strip() for x in remotes if str(x).strip()]
    disabled = bool(payload.get("disabled", False))
    balance = str(payload.get("balance") or "roundrobin").strip() or "roundrobin"
    protocol = str(payload.get("protocol") or "tcp+udp").strip() or "tcp+udp"

    try:
        server_port = int(payload.get("server_port") or 18443)
    except Exception:
        server_port = 18443
    if server_port <= 0 or server_port > 65535:
        return JSONResponse({"ok": False, "error": "隧道端口无效"}, status_code=400)

    if not listen:
        return JSONResponse({"ok": False, "error": "listen 不能为空"}, status_code=400)
    if not remotes:
        return JSONResponse({"ok": False, "error": "目标地址不能为空"}, status_code=400)

    sync_id = str(payload.get("sync_id") or "").strip() or uuid.uuid4().hex

    sender_pool = await load_pool_for_node(sender)
    denied_owner = _deny_if_sync_not_owned(user, sync_id, sender_pool)
    if isinstance(denied_owner, JSONResponse):
        return denied_owner
    now_ts = int(datetime.now(timezone.utc).timestamp())
    existing_token, existing_token_grace = _extract_intranet_token_meta(sender_pool, sync_id, now_ts)
    req_token = str(payload.get("token") or "").strip()
    token = req_token or existing_token or uuid.uuid4().hex
    old_receiver_id: int = 0
    try:
        for ep in sender_pool.get("endpoints") or []:
            if not isinstance(ep, dict):
                continue
            ex0 = ep.get("extra_config") or {}
            if not isinstance(ex0, dict):
                continue
            if str(ex0.get("sync_id") or "") != str(sync_id):
                continue
            if bool(ex0.get("intranet_lock") is True):
                continue
            old_receiver_id = int(ex0.get("intranet_peer_node_id") or 0)
            break
    except Exception:
        old_receiver_id = 0

    old_receiver: Optional[Dict[str, Any]] = None
    old_receiver_pool: Optional[Dict[str, Any]] = None
    if old_receiver_id > 0 and old_receiver_id != receiver_id:
        old_receiver = get_node(old_receiver_id)
        if old_receiver:
            try:
                old_receiver_pool = await load_pool_for_node(old_receiver)
                denied_owner = _deny_if_sync_not_owned(user, sync_id, old_receiver_pool)
                if isinstance(denied_owner, JSONResponse):
                    return denied_owner
                remove_endpoints_by_sync_id(old_receiver_pool, sync_id)
                set_desired_pool(old_receiver_id, old_receiver_pool)
            except Exception:
                old_receiver = None
                old_receiver_pool = None

    override_host = normalize_host_input(str(payload.get("server_host") or ""))
    receiver_host = override_host or node_host_for_realm(receiver)
    if not receiver_host:
        return JSONResponse(
            {
                "ok": False,
                "error": "出口节点地址为空。请检查 receiver 节点 base_url 或填写 server_host。",
            },
            status_code=400,
        )

    # Sender is client in reverse-open mode: fetch receiver-side cert for TLS verification.
    server_cert_pem = ""
    cert_fetch_err = ""
    receiver_pool = await load_pool_for_node(receiver)
    denied_owner = _deny_if_sync_not_owned(user, sync_id, receiver_pool)
    if isinstance(denied_owner, JSONResponse):
        return denied_owner

    # Prefer existing cert already stored on sender-side synced rule when editing.
    server_cert_pem = _intranet_cert_from_existing_receiver_pool(sender_pool, sync_id)
    if not server_cert_pem:
        cached_cert, cached_err = _sender_cert_from_report_cache(receiver_id)
        if cached_cert:
            server_cert_pem = cached_cert
        else:
            cert_fetch_err = cached_err or ""
            try:
                receiver_target_base, receiver_target_verify, _receiver_target_route = node_agent_request_target(receiver)
                cert = await agent_get(
                    receiver_target_base,
                    receiver.get("api_key", ""),
                    "/api/v1/intranet/cert",
                    receiver_target_verify,
                    timeout=_sync_precheck_http_timeout(),
                )
                if isinstance(cert, dict) and cert.get("ok") is True:
                    server_cert_pem = str(cert.get("cert_pem") or "").strip()
                    cert_fetch_err = ""
                else:
                    cert_fetch_err = _safe_error_text(cert, cert_fetch_err or "cert_unavailable")
            except Exception as exc:
                server_cert_pem = ""
                msg = str(exc or "").strip()
                cert_fetch_err = msg or exc.__class__.__name__ or cert_fetch_err or "cert_fetch_failed"
                logger.warning(
                    "intranet cert fetch failed: receiver_id=%s receiver_base=%s err=%s",
                    receiver_id,
                    mask_url(str(receiver.get("base_url") or "")),
                    redact_log_text(cert_fetch_err),
                    exc_info=True,
                )

    now_iso = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    # Panel-only meta (remark / favorite)
    has_remark = "remark" in payload
    has_favorite = "favorite" in payload

    def _coerce_bool(v: Any) -> bool:
        if isinstance(v, bool):
            return v
        s = str(v or "").strip().lower()
        return s in ("1", "true", "yes", "y", "on")

    payload_tls_verify: Optional[bool] = None
    if "intranet_tls_verify" in payload:
        payload_tls_verify = _coerce_bool(payload.get("intranet_tls_verify"))
    tls_verify_required = bool(_INTRANET_FORCE_TLS_VERIFY or (payload_tls_verify is True))
    tls_verify_degraded_reason = ""
    if tls_verify_required and (not server_cert_pem):
        can_fail_open = bool(_INTRANET_TLS_VERIFY_FAIL_OPEN and (payload_tls_verify is not True))
        if can_fail_open:
            tls_verify_required = False
            tls_verify_degraded_reason = _intranet_cert_fetch_hint(cert_fetch_err or "cert_empty")
            logger.warning(
                "intranet tls verify degraded to fail-open: sender_id=%s receiver_id=%s reason=%s",
                sender_id,
                receiver_id,
                redact_log_text(cert_fetch_err or "cert_empty"),
            )
        else:
            hint = _intranet_cert_fetch_hint(cert_fetch_err or "cert_empty")
            return JSONResponse(
                {
                    "ok": False,
                    "error": f"已启用强制 TLS 证书校验，但无法获取出口节点证书：{hint}。",
                    "detail": cert_fetch_err or "cert_empty",
                },
                status_code=400,
            )
    tls_verify_enabled = bool(server_cert_pem) or tls_verify_required

    token_candidates, token_grace = _build_intranet_tokens(
        primary_token=token,
        previous_primary=existing_token,
        previous_grace=existing_token_grace,
        now_ts=now_ts,
    )

    def _find_meta(pool: Dict[str, Any]) -> Tuple[str, Optional[bool]]:
        try:
            for ep in (pool or {}).get("endpoints") or []:
                if not isinstance(ep, dict):
                    continue
                ex0 = ep.get("extra_config") or {}
                if not isinstance(ex0, dict):
                    continue
                if str(ex0.get("sync_id") or "") != str(sync_id):
                    continue
                r = str(ep.get("remark") or "").strip()
                f_raw = ep.get("favorite")
                f_val: Optional[bool] = None
                if f_raw is not None:
                    try:
                        f_val = bool(f_raw)
                    except Exception:
                        f_val = None
                return r, f_val
        except Exception:
            pass
        return "", None

    existing_remark = ""
    existing_fav: Optional[bool] = None
    if (not has_remark) or (not has_favorite):
        r1, f1 = _find_meta(sender_pool)
        r2, f2 = _find_meta(receiver_pool)
        existing_remark = r1 or r2 or ""
        existing_fav = f1 if f1 is not None else f2

    remark = str(payload.get("remark") or "").strip() if has_remark else str(existing_remark or "").strip()
    if len(remark) > 200:
        remark = remark[:200]
    favorite = _coerce_bool(payload.get("favorite")) if has_favorite else bool(existing_fav or False)

    has_qos = "qos" in payload
    if has_qos:
        qos, qos_err = _normalize_qos_payload(payload.get("qos"))
        if qos_err:
            return JSONResponse({"ok": False, "error": qos_err}, status_code=400)
    else:
        qos_sender = _find_sync_qos(sender_pool, sync_id)
        qos_receiver = _find_sync_qos(receiver_pool, sync_id)
        qos = qos_sender or qos_receiver

    has_acl = "acl" in payload
    if has_acl:
        intranet_acl, acl_err = _normalize_intranet_acl_payload(payload.get("acl"))
        if acl_err:
            return JSONResponse({"ok": False, "error": acl_err}, status_code=400)
    else:
        acl_sender = _find_sync_intranet_acl(sender_pool, sync_id)
        acl_receiver = _find_sync_intranet_acl(receiver_pool, sync_id)
        intranet_acl = acl_sender or acl_receiver

    sender_extra: Dict[str, Any] = {
        "intranet_role": "client",
        "intranet_peer_node_id": receiver_id,
        "intranet_peer_node_name": receiver.get("name"),
        "intranet_peer_host": receiver_host,
        "intranet_server_port": server_port,
        "intranet_token": token,
        "intranet_tokens": token_candidates,
        "intranet_server_cert_pem": server_cert_pem,
        "intranet_tls_verify": bool(tls_verify_enabled),
        "intranet_tls_verify_degraded_reason": tls_verify_degraded_reason,
        "intranet_sender_listen": listen,
        "intranet_original_remotes": remotes,
        "sync_role": "sender",
        "sync_peer_node_id": receiver_id,
        "sync_peer_node_name": receiver.get("name"),
        "sync_sender_listen": listen,
        "sync_original_remotes": remotes,
        "sync_receiver_port": server_port,
        "sync_updated_at": now_iso,
        "sync_id": sync_id,
        "intranet_updated_at": now_iso,
    }
    if token_grace:
        sender_extra["intranet_token_grace"] = token_grace
    if qos:
        sender_extra["qos"] = dict(qos)
    if intranet_acl:
        sender_extra["intranet_acl"] = dict(intranet_acl)

    sender_ep = {
        "listen": listen,
        "disabled": disabled,
        "balance": balance,
        "protocol": protocol,
        "remotes": remotes,
        "extra_config": sender_extra,
    }
    if qos:
        sender_ep["network"] = {"qos": dict(qos)}

    if remark:
        sender_ep["remark"] = remark
    if favorite:
        sender_ep["favorite"] = True
    stamp_endpoint_owner(sender_ep, rule_user_ref)

    receiver_extra: Dict[str, Any] = {
        "intranet_role": "server",
        "intranet_lock": True,
        "intranet_peer_node_id": sender_id,
        "intranet_peer_node_name": sender.get("name"),
        "intranet_public_host": receiver_host,
        "intranet_server_port": server_port,
        "intranet_token": token,
        "intranet_tokens": token_candidates,
        "intranet_sender_listen": listen,
        "intranet_original_remotes": remotes,
        "sync_role": "receiver",
        "sync_lock": True,
        "sync_from_node_id": sender_id,
        "sync_from_node_name": sender.get("name"),
        "sync_sender_listen": listen,
        "sync_original_remotes": remotes,
        "sync_updated_at": now_iso,
        "sync_id": sync_id,
        "intranet_updated_at": now_iso,
    }
    if token_grace:
        receiver_extra["intranet_token_grace"] = token_grace
    if qos:
        receiver_extra["qos"] = dict(qos)
    if intranet_acl:
        receiver_extra["intranet_acl"] = dict(intranet_acl)

    receiver_ep = {
        "listen": format_addr("0.0.0.0", 0),
        "disabled": disabled,
        "balance": balance,
        "protocol": protocol,
        "remotes": remotes,
        "extra_config": receiver_extra,
    }
    if qos:
        receiver_ep["network"] = {"qos": dict(qos)}

    if remark:
        receiver_ep["remark"] = remark
    if favorite:
        receiver_ep["favorite"] = True
    stamp_endpoint_owner(receiver_ep, rule_user_ref)

    upsert_endpoint_by_sync_id(sender_pool, sync_id, sender_ep)
    upsert_endpoint_by_sync_id(receiver_pool, sync_id, receiver_ep)

    # Save-time validation (sender+receiver): blocking errors + warning hints
    sender_warnings: List[Dict[str, Any]] = []
    receiver_warnings: List[Dict[str, Any]] = []
    try:
        sender_warnings = [i.__dict__ for i in validate_pool_inplace(sender_pool)]
        receiver_warnings = [i.__dict__ for i in validate_pool_inplace(receiver_pool)]
    except PoolValidationError as exc:
        return JSONResponse({"ok": False, "error": str(exc), "issues": [i.__dict__ for i in exc.issues]}, status_code=400)
    except Exception as exc:
        return JSONResponse({"ok": False, "error": f"内网穿透保存失败：规则校验异常（{exc}）"}, status_code=500)

    runtime_issues: List[Dict[str, Any]] = []
    # Async jobs should return quickly; runtime netprobe is kept for sync path only.
    skip_runtime_precheck = bool(is_async_job)
    sync_precheck_enabled = _sync_precheck_enabled()
    if sync_precheck_enabled and (not skip_runtime_precheck):
        i1, i2 = await asyncio.gather(
            _probe_node_rules_precheck(sender, sender_pool, "发送端"),
            _probe_node_rules_precheck(receiver, receiver_pool, "接收端"),
        )
        runtime_issues += list(i1 or [])
        runtime_issues += list(i2 or [])

    precheck_issues: List[Dict[str, Any]] = []
    precheck_seen: set[str] = set()
    for it in sender_warnings + receiver_warnings + runtime_issues:
        if isinstance(it, dict):
            _append_issue(precheck_issues, precheck_seen, it)

    precheck_summary = {
        "enabled": bool(sync_precheck_enabled and (not skip_runtime_precheck)),
        "source": (
            "static_validate+agent_netprobe_rules"
            if (sync_precheck_enabled and (not skip_runtime_precheck))
            else ("static_validate+runtime_skipped_async" if skip_runtime_precheck else "static_validate")
        ),
        "runtime_skipped_async": bool(skip_runtime_precheck),
        "issues": len(precheck_issues),
    }

    try:
        upsert_rule_owner_map(node_id=sender_id, pool=sender_pool)
        upsert_rule_owner_map(node_id=receiver_id, pool=receiver_pool)
    except Exception:
        pass

    s_ver, _ = set_desired_pool(sender_id, sender_pool)
    r_ver, _ = set_desired_pool(receiver_id, receiver_pool)

    apply_items: List[Tuple[Dict[str, Any], Dict[str, Any]]] = [(sender, sender_pool), (receiver, receiver_pool)]
    if old_receiver and isinstance(old_receiver_pool, dict):
        apply_items.append((old_receiver, old_receiver_pool))
    if is_async_job:
        for n, p in apply_items:
            try:
                schedule_apply_pool(n, p)
            except Exception:
                continue
    else:
        await _apply_pools_best_effort(apply_items)

    return {
        "ok": True,
        "sync_id": sync_id,
        "sender_pool": _filter_pool_for_user(user, sender_pool),
        "receiver_pool": _filter_pool_for_user(user, receiver_pool),
        "sender_desired_version": s_ver,
        "receiver_desired_version": r_ver,
        "tls_verify_degraded": bool(tls_verify_degraded_reason),
        "tls_verify_degraded_reason": tls_verify_degraded_reason,
        "precheck": {
            "issues": precheck_issues,
            "summary": precheck_summary,
        },
    }


@router.post("/api/intranet_tunnel/delete")
async def api_intranet_tunnel_delete(payload: Dict[str, Any], user: str = Depends(require_login)):
    sync_id = str(payload.get("sync_id") or "").strip()
    if not sync_id:
        return JSONResponse({"ok": False, "error": "sync_id 不能为空"}, status_code=400)
    is_async_job = bool(isinstance(payload, dict) and payload.get("_async_job") is True)

    try:
        sender_id = int(payload.get("sender_node_id") or 0)
        receiver_id = int(payload.get("receiver_node_id") or 0)
    except Exception:
        sender_id = 0
        receiver_id = 0

    if sender_id <= 0 or receiver_id <= 0 or sender_id == receiver_id:
        return JSONResponse({"ok": False, "error": "sender_node_id / receiver_node_id 无效"}, status_code=400)
    sender = get_node(sender_id)
    receiver = get_node(receiver_id)
    if not sender:
        return JSONResponse({"ok": False, "error": "公网入口节点不存在"}, status_code=404)
    # Receiver may be removed already; treat as sender-only stale-sync cleanup.
    receiver_missing = receiver is None
    policy_receiver_id = int(receiver_id) if not receiver_missing else int(sender_id)
    denied = _check_sync_policy(user, "intranet", "delete", sender_id, policy_receiver_id)
    if isinstance(denied, JSONResponse):
        return denied

    sender_pool = await load_pool_for_node(sender)
    receiver_pool = await load_pool_for_node(receiver) if receiver else {"endpoints": []}
    denied_owner = _deny_if_sync_not_owned(user, sync_id, sender_pool, receiver_pool if receiver else {})
    if isinstance(denied_owner, JSONResponse):
        return denied_owner

    remove_endpoints_by_sync_id(sender_pool, sync_id)
    if receiver:
        remove_endpoints_by_sync_id(receiver_pool, sync_id)

    s_ver, _ = set_desired_pool(sender_id, sender_pool)
    r_ver = 0
    if receiver:
        r_ver, _ = set_desired_pool(receiver_id, receiver_pool)

    if is_async_job:
        try:
            schedule_apply_pool(sender, sender_pool)
        except Exception:
            pass
        if receiver:
            try:
                schedule_apply_pool(receiver, receiver_pool)
            except Exception:
                pass
    else:
        apply_items: List[Tuple[Dict[str, Any], Dict[str, Any]]] = [(sender, sender_pool)]
        if receiver:
            apply_items.append((receiver, receiver_pool))
        await _apply_pools_best_effort(apply_items)

    return {
        "ok": True,
        "sync_id": sync_id,
        "sender_pool": _filter_pool_for_user(user, sender_pool),
        "receiver_pool": (_filter_pool_for_user(user, receiver_pool) if receiver else {"endpoints": []}),
        "sender_desired_version": s_ver,
        "receiver_desired_version": r_ver,
        "receiver_missing": bool(receiver_missing),
    }
