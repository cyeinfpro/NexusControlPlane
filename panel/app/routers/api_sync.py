from __future__ import annotations

import asyncio
import os
import secrets
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse

from ..clients.agent import agent_get, agent_post
from ..core.deps import require_login
from ..db import get_node, set_desired_pool
from ..services.apply import node_verify_tls
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
from ..utils.validate import PoolValidationError, validate_pool_inplace

router = APIRouter()


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


_SYNC_PRECHECK_ENABLED = _env_flag("REALM_SYNC_SAVE_PRECHECK_ENABLED", True)
_SYNC_PRECHECK_HTTP_TIMEOUT = _env_float("REALM_SYNC_SAVE_PRECHECK_HTTP_TIMEOUT", 4.5, 2.0, 20.0)
_SYNC_PRECHECK_PROBE_TIMEOUT = _env_float("REALM_SYNC_SAVE_PRECHECK_PROBE_TIMEOUT", 1.2, 0.2, 6.0)
_SYNC_APPLY_TIMEOUT = _env_float("REALM_SYNC_SAVE_APPLY_TIMEOUT", 3.0, 0.5, 20.0)
_SYNC_PRECHECK_MAX_ISSUES = 24


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

    bw_kbps = _coerce_nonneg_int(bw_kbps_raw)
    bw_mbps = _coerce_nonneg_int(bw_mbps_raw)
    max_conns = _coerce_nonneg_int(max_conns_raw)
    conn_rate = _coerce_nonneg_int(conn_rate_raw)

    if strict:
        if bw_kbps is None and _qos_has_value(bw_kbps_raw):
            return {}, "qos.bandwidth_kbps 必须是非负整数"
        if bw_mbps is None and _qos_has_value(bw_mbps_raw):
            return {}, "qos.bandwidth_mbps 必须是非负整数"
        if max_conns is None and _qos_has_value(max_conns_raw):
            return {}, "qos.max_conns 必须是非负整数"
        if conn_rate is None and _qos_has_value(conn_rate_raw):
            return {}, "qos.conn_rate 必须是非负整数"

    if bw_kbps is None and bw_mbps is not None:
        bw_kbps = int(bw_mbps) * 1024

    qos: Dict[str, int] = {}
    if bw_kbps is not None and bw_kbps > 0:
        qos["bandwidth_kbps"] = int(bw_kbps)
    if max_conns is not None and max_conns > 0:
        qos["max_conns"] = int(max_conns)
    if conn_rate is not None and conn_rate > 0:
        qos["conn_rate"] = int(conn_rate)
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


def _issue_key(issue: Dict[str, Any]) -> str:
    return (
        f"{issue.get('path') or ''}|{issue.get('code') or ''}|"
        f"{issue.get('severity') or ''}|{issue.get('message') or ''}"
    )


async def _apply_pool_best_effort(node: Dict[str, Any], pool: Dict[str, Any]) -> None:
    try:
        data = await agent_post(
            node.get("base_url", ""),
            node.get("api_key", ""),
            "/api/v1/pool",
            {"pool": pool},
            node_verify_tls(node),
            timeout=_SYNC_APPLY_TIMEOUT,
        )
        if isinstance(data, dict) and data.get("ok", True):
            await agent_post(
                node.get("base_url", ""),
                node.get("api_key", ""),
                "/api/v1/apply",
                {},
                node_verify_tls(node),
                timeout=_SYNC_APPLY_TIMEOUT,
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


def _pool_rules_for_probe(pool: Dict[str, Any]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    eps = pool.get("endpoints") if isinstance(pool.get("endpoints"), list) else []
    if not isinstance(eps, list):
        return out
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
        out.append(item)
    return out


async def _probe_node_rules_precheck(node: Dict[str, Any], pool: Dict[str, Any], node_label: str) -> List[Dict[str, Any]]:
    if not _SYNC_PRECHECK_ENABLED:
        return []

    rules_payload = _pool_rules_for_probe(pool)
    if not rules_payload:
        return []

    issues: List[Dict[str, Any]] = []
    seen: set[str] = set()
    body = {"mode": "rules", "rules": rules_payload, "timeout": _SYNC_PRECHECK_PROBE_TIMEOUT}

    try:
        data = await agent_post(
            node.get("base_url", ""),
            node.get("api_key", ""),
            "/api/v1/netprobe",
            body,
            node_verify_tls(node),
            timeout=_SYNC_PRECHECK_HTTP_TIMEOUT,
        )
    except Exception as exc:
        _append_issue(
            issues,
            seen,
            {
                "path": "endpoints",
                "message": f"{node_label}预检失败：无法连接 Agent 执行规则探测（{exc}）",
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


@router.post("/api/wss_tunnel/save")
async def api_wss_tunnel_save(payload: Dict[str, Any], user: str = Depends(require_login)):
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
    protocol = str(payload.get("protocol") or "tcp+udp").strip() or "tcp+udp"

    wss = payload.get("wss") or {}
    if not isinstance(wss, dict):
        wss = {}
    wss_host = str(wss.get("host") or "").strip()
    wss_path = str(wss.get("path") or "").strip()
    wss_sni = str(wss.get("sni") or "").strip()
    wss_tls = bool(wss.get("tls", True))
    wss_insecure = bool(wss.get("insecure", False))

    if (not wss_host) or (not wss_path) or (not wss_sni):
        rh, rp, rs = random_wss_params()
        if not wss_host:
            wss_host = wss_sni or rh
        if not wss_path:
            wss_path = rp
        if wss_path and not wss_path.startswith("/"):
            wss_path = "/" + wss_path
        if not wss_sni:
            wss_sni = wss_host or rs

    if wss_path and not wss_path.startswith("/"):
        wss_path = "/" + wss_path
    if not wss_sni:
        wss_sni = wss_host

    if not listen:
        return JSONResponse({"ok": False, "error": "listen 不能为空"}, status_code=400)
    if not remotes:
        return JSONResponse({"ok": False, "error": "目标地址不能为空"}, status_code=400)
    if not wss_host or not wss_path:
        return JSONResponse({"ok": False, "error": "WSS Host / Path 不能为空"}, status_code=400)

    sync_id = str(payload.get("sync_id") or "").strip() or uuid.uuid4().hex

    # If editing an existing synced rule and switching receiver node, remove old receiver-side rule.
    sender_pool = await load_pool_for_node(sender)
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
                remove_endpoints_by_sync_id(old_receiver_pool, sync_id)
                set_desired_pool(old_receiver_id, old_receiver_pool)
            except Exception:
                old_receiver = None
                old_receiver_pool = None

    # Receiver port policy:
    receiver_pool = await load_pool_for_node(receiver)
    existing_receiver_port = find_sync_listen_port(receiver_pool, sync_id, role="receiver")

    raw_receiver_port = payload.get("receiver_port")
    explicit_receiver_port = raw_receiver_port is not None and raw_receiver_port != ""
    receiver_port: Optional[int] = None
    if explicit_receiver_port:
        try:
            receiver_port = int(raw_receiver_port)
        except Exception:
            return JSONResponse({"ok": False, "error": "receiver_port 必须是数字"}, status_code=400)

    _lh, sender_listen_port = split_host_port(listen)
    if sender_listen_port is None:
        return JSONResponse({"ok": False, "error": "listen 格式不正确，请使用 0.0.0.0:端口"}, status_code=400)

    if receiver_port is None:
        receiver_port = existing_receiver_port
    if receiver_port is None:
        receiver_port = sender_listen_port

    if receiver_port <= 0 or receiver_port > 65535:
        return JSONResponse({"ok": False, "error": "receiver_port 端口范围必须是 1-65535"}, status_code=400)

    port_fixed = explicit_receiver_port or (existing_receiver_port is not None)
    if port_fixed:
        if port_used_by_other_sync(receiver_pool, receiver_port, sync_id):
            return JSONResponse(
                {"ok": False, "error": f"接收机端口 {receiver_port} 已被其他规则占用，请换一个端口"},
                status_code=400,
            )
    else:
        receiver_port = choose_receiver_port(receiver_pool, receiver_port, ignore_sync_id=sync_id)

    receiver_host = node_host_for_realm(receiver)
    if not receiver_host:
        return JSONResponse({"ok": False, "error": "接收机 base_url 无法解析主机名，请检查节点地址"}, status_code=400)
    sender_to_receiver = format_addr(receiver_host, receiver_port)

    now_iso = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    # Panel-only meta (remark / favorite)
    has_remark = "remark" in payload
    has_favorite = "favorite" in payload

    def _coerce_bool(v: Any) -> bool:
        if isinstance(v, bool):
            return v
        s = str(v or "").strip().lower()
        return s in ("1", "true", "yes", "y", "on")

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

    sender_extra: Dict[str, Any] = {
        "remote_transport": "ws",
        "remote_ws_host": wss_host,
        "remote_ws_path": wss_path,
        "remote_tls_enabled": bool(wss_tls),
        "remote_tls_insecure": bool(wss_insecure),
        "remote_tls_sni": wss_sni,
        # sync meta
        "sync_id": sync_id,
        "sync_role": "sender",
        "sync_peer_node_id": receiver_id,
        "sync_peer_node_name": receiver.get("name"),
        "sync_receiver_port": receiver_port,
        "sync_original_remotes": remotes,
        "sync_updated_at": now_iso,
    }
    if qos:
        sender_extra["qos"] = dict(qos)

    sender_ep = {
        "listen": listen,
        "disabled": disabled,
        "balance": balance,
        "protocol": protocol,
        "remotes": [sender_to_receiver],
        "extra_config": sender_extra,
    }
    if qos:
        sender_ep["network"] = {"qos": dict(qos)}

    if remark:
        sender_ep["remark"] = remark
    if favorite:
        sender_ep["favorite"] = True

    receiver_extra: Dict[str, Any] = {
        "listen_transport": "ws",
        "listen_ws_host": wss_host,
        "listen_ws_path": wss_path,
        "listen_tls_enabled": bool(wss_tls),
        "listen_tls_insecure": bool(wss_insecure),
        "listen_tls_servername": wss_sni,
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
    if qos:
        receiver_extra["qos"] = dict(qos)

    receiver_ep = {
        "listen": format_addr("0.0.0.0", receiver_port),
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
        return JSONResponse({"ok": False, "error": f"WSS 保存失败：规则校验异常（{exc}）"}, status_code=500)

    runtime_issues: List[Dict[str, Any]] = []
    if _SYNC_PRECHECK_ENABLED:
        runtime_issues += await _probe_node_rules_precheck(sender, sender_pool, "发送机")
        runtime_issues += await _probe_node_rules_precheck(receiver, receiver_pool, "接收机")

    precheck_issues: List[Dict[str, Any]] = []
    precheck_seen: set[str] = set()
    for it in sender_warnings + receiver_warnings + runtime_issues:
        if isinstance(it, dict):
            _append_issue(precheck_issues, precheck_seen, it)

    precheck_summary = {
        "enabled": bool(_SYNC_PRECHECK_ENABLED),
        "source": "static_validate+agent_netprobe_rules" if _SYNC_PRECHECK_ENABLED else "static_validate",
        "issues": len(precheck_issues),
    }

    s_ver, _ = set_desired_pool(sender_id, sender_pool)
    r_ver, _ = set_desired_pool(receiver_id, receiver_pool)

    apply_items: List[Tuple[Dict[str, Any], Dict[str, Any]]] = [(sender, sender_pool), (receiver, receiver_pool)]
    if old_receiver and isinstance(old_receiver_pool, dict):
        apply_items.append((old_receiver, old_receiver_pool))
    await _apply_pools_best_effort(apply_items)

    return {
        "ok": True,
        "sync_id": sync_id,
        "receiver_port": receiver_port,
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
    if not sender or not receiver:
        return JSONResponse({"ok": False, "error": "节点不存在"}, status_code=404)

    sender_pool = await load_pool_for_node(sender)
    receiver_pool = await load_pool_for_node(receiver)

    remove_endpoints_by_sync_id(sender_pool, sync_id)
    remove_endpoints_by_sync_id(receiver_pool, sync_id)

    s_ver, _ = set_desired_pool(sender_id, sender_pool)
    r_ver, _ = set_desired_pool(receiver_id, receiver_pool)

    await _apply_pools_best_effort([(sender, sender_pool), (receiver, receiver_pool)])

    return {
        "ok": True,
        "sync_id": sync_id,
        "sender_pool": sender_pool,
        "receiver_pool": receiver_pool,
        "sender_desired_version": s_ver,
        "receiver_desired_version": r_ver,
    }


@router.post("/api/intranet_tunnel/save")
async def api_intranet_tunnel_save(payload: Dict[str, Any], user: str = Depends(require_login)):
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
    token = str(payload.get("token") or "").strip() or uuid.uuid4().hex

    sender_pool = await load_pool_for_node(sender)
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
            if str(ex0.get("intranet_role") or "") != "server":
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
                remove_endpoints_by_sync_id(old_receiver_pool, sync_id)
                set_desired_pool(old_receiver_id, old_receiver_pool)
            except Exception:
                old_receiver = None
                old_receiver_pool = None

    override_host = normalize_host_input(str(payload.get("server_host") or ""))
    sender_host = override_host or node_host_for_realm(sender)
    if not sender_host:
        return JSONResponse(
            {
                "ok": False,
                "error": "公网入口地址为空。请检查节点 base_url 或在内网穿透中填写“公网入口地址(A)”。",
            },
            status_code=400,
        )

    # Best-effort: fetch A-side tunnel server cert and embed into B config for TLS verification.
    server_cert_pem = ""
    try:
        cert = await agent_get(
            sender.get("base_url", ""),
            sender.get("api_key", ""),
            "/api/v1/intranet/cert",
            node_verify_tls(sender),
        )
        if isinstance(cert, dict) and cert.get("ok") is True:
            server_cert_pem = str(cert.get("cert_pem") or "").strip()
    except Exception:
        server_cert_pem = ""

    receiver_pool = await load_pool_for_node(receiver)

    now_iso = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    # Panel-only meta (remark / favorite)
    has_remark = "remark" in payload
    has_favorite = "favorite" in payload

    def _coerce_bool(v: Any) -> bool:
        if isinstance(v, bool):
            return v
        s = str(v or "").strip().lower()
        return s in ("1", "true", "yes", "y", "on")

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

    sender_extra: Dict[str, Any] = {
        "intranet_role": "server",
        "intranet_peer_node_id": receiver_id,
        "intranet_peer_node_name": receiver.get("name"),
        "intranet_public_host": sender_host,
        "intranet_server_port": server_port,
        "intranet_token": token,
        "intranet_original_remotes": remotes,
        "sync_id": sync_id,
        "intranet_updated_at": now_iso,
    }
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

    receiver_extra: Dict[str, Any] = {
        "intranet_role": "client",
        "intranet_lock": True,
        "intranet_peer_node_id": sender_id,
        "intranet_peer_node_name": sender.get("name"),
        "intranet_peer_host": sender_host,
        "intranet_server_port": server_port,
        "intranet_token": token,
        "intranet_server_cert_pem": server_cert_pem,
        "intranet_tls_verify": bool(server_cert_pem),
        "intranet_sender_listen": listen,
        "intranet_original_remotes": remotes,
        "sync_id": sync_id,
        "intranet_updated_at": now_iso,
    }
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
    if _SYNC_PRECHECK_ENABLED:
        runtime_issues += await _probe_node_rules_precheck(sender, sender_pool, "公网入口")
        runtime_issues += await _probe_node_rules_precheck(receiver, receiver_pool, "内网出口")

    precheck_issues: List[Dict[str, Any]] = []
    precheck_seen: set[str] = set()
    for it in sender_warnings + receiver_warnings + runtime_issues:
        if isinstance(it, dict):
            _append_issue(precheck_issues, precheck_seen, it)

    precheck_summary = {
        "enabled": bool(_SYNC_PRECHECK_ENABLED),
        "source": "static_validate+agent_netprobe_rules" if _SYNC_PRECHECK_ENABLED else "static_validate",
        "issues": len(precheck_issues),
    }

    s_ver, _ = set_desired_pool(sender_id, sender_pool)
    r_ver, _ = set_desired_pool(receiver_id, receiver_pool)

    apply_items: List[Tuple[Dict[str, Any], Dict[str, Any]]] = [(sender, sender_pool), (receiver, receiver_pool)]
    if old_receiver and isinstance(old_receiver_pool, dict):
        apply_items.append((old_receiver, old_receiver_pool))
    await _apply_pools_best_effort(apply_items)

    return {
        "ok": True,
        "sync_id": sync_id,
        "sender_pool": sender_pool,
        "receiver_pool": receiver_pool,
        "sender_desired_version": s_ver,
        "receiver_desired_version": r_ver,
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
    if not sender or not receiver:
        return JSONResponse({"ok": False, "error": "节点不存在"}, status_code=404)

    sender_pool = await load_pool_for_node(sender)
    receiver_pool = await load_pool_for_node(receiver)

    remove_endpoints_by_sync_id(sender_pool, sync_id)
    remove_endpoints_by_sync_id(receiver_pool, sync_id)

    s_ver, _ = set_desired_pool(sender_id, sender_pool)
    r_ver, _ = set_desired_pool(receiver_id, receiver_pool)

    await _apply_pools_best_effort([(sender, sender_pool), (receiver, receiver_pool)])

    return {
        "ok": True,
        "sync_id": sync_id,
        "sender_pool": sender_pool,
        "receiver_pool": receiver_pool,
        "sender_desired_version": s_ver,
        "receiver_desired_version": r_ver,
    }
