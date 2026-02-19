from __future__ import annotations

import asyncio
import hashlib
import json
import os
import time
from typing import Any, Dict, List, Optional, Tuple

from fastapi import FastAPI

from ..clients.agent import agent_post
from ..core.bg_tasks import spawn_background_task
from ..db import (
    add_task,
    insert_netmon_samples,
    list_netmon_monitors,
    list_nodes_runtime,
    list_tasks,
    prune_netmon_samples,
    update_netmon_monitor,
)
from .apply import node_verify_tls


_NETMON_BG_ENABLED = (os.getenv("REALM_NETMON_BG_ENABLED") or "1").strip() not in ("0", "false", "False")
try:
    _NETMON_RETENTION_DAYS = int((os.getenv("REALM_NETMON_RETENTION_DAYS") or "7").strip() or 7)
except Exception:
    _NETMON_RETENTION_DAYS = 7
if _NETMON_RETENTION_DAYS < 1:
    _NETMON_RETENTION_DAYS = 1
if _NETMON_RETENTION_DAYS > 90:
    _NETMON_RETENTION_DAYS = 90

try:
    _NETMON_HTTP_TIMEOUT = float((os.getenv("REALM_NETMON_HTTP_TIMEOUT") or "8.0").strip() or 3.5)
except Exception:
    _NETMON_HTTP_TIMEOUT = 3.5
if _NETMON_HTTP_TIMEOUT < 1.5:
    _NETMON_HTTP_TIMEOUT = 1.5
if _NETMON_HTTP_TIMEOUT > 20:
    _NETMON_HTTP_TIMEOUT = 20.0

try:
    _NETMON_PROBE_TIMEOUT = float((os.getenv("REALM_NETMON_PROBE_TIMEOUT") or "2.5").strip() or 2.5)
except Exception:
    _NETMON_PROBE_TIMEOUT = 2.5
if _NETMON_PROBE_TIMEOUT < 0.5:
    _NETMON_PROBE_TIMEOUT = 0.5
if _NETMON_PROBE_TIMEOUT > 10:
    _NETMON_PROBE_TIMEOUT = 10.0

try:
    _NETMON_MAX_CONCURRENCY = int((os.getenv("REALM_NETMON_CONCURRENCY") or "40").strip() or 40)
except Exception:
    _NETMON_MAX_CONCURRENCY = 40
if _NETMON_MAX_CONCURRENCY < 4:
    _NETMON_MAX_CONCURRENCY = 4
if _NETMON_MAX_CONCURRENCY > 200:
    _NETMON_MAX_CONCURRENCY = 200

try:
    _NETMON_QUEUE_MAX_ATTEMPTS = int((os.getenv("REALM_NETMON_QUEUE_MAX_ATTEMPTS") or "2").strip() or 2)
except Exception:
    _NETMON_QUEUE_MAX_ATTEMPTS = 2
if _NETMON_QUEUE_MAX_ATTEMPTS < 1:
    _NETMON_QUEUE_MAX_ATTEMPTS = 1
if _NETMON_QUEUE_MAX_ATTEMPTS > 10:
    _NETMON_QUEUE_MAX_ATTEMPTS = 10

_NETMON_SEM = asyncio.Semaphore(_NETMON_MAX_CONCURRENCY)
_NETMON_BG_LAST_RUN: Dict[int, float] = {}


def _netmon_is_dispatch_error(err: Any) -> bool:
    msg = str(err or "").strip().lower()
    if not msg:
        return False
    if "agent 请求失败" in msg:
        return True
    tokens = (
        "all connection attempts failed",
        "connection refused",
        "connect timeout",
        "read timeout",
        "timed out",
        "name or service not known",
        "temporary failure in name resolution",
        "network is unreachable",
        "no route to host",
        "cannot assign requested address",
        "tls handshake",
        "ssl:",
    )
    return any(t in msg for t in tokens)


def _netmon_clean_mids_by_target(raw: Any) -> Dict[str, List[int]]:
    out: Dict[str, List[int]] = {}
    if not isinstance(raw, dict):
        return out
    for k, v in raw.items():
        target = str(k or "").strip()
        if not target:
            continue
        mids: List[int] = []
        rows = v if isinstance(v, list) else []
        for x in rows:
            try:
                mid = int(x)
            except Exception:
                continue
            if mid > 0 and mid not in mids:
                mids.append(mid)
        if mids:
            out[target] = mids
    return out


def _netmon_private_group_key(node_id: int, mode: str, tcp_port: int, mids_by_target: Dict[str, List[int]]) -> str:
    rows: List[str] = []
    for target in sorted(mids_by_target.keys()):
        mids = sorted(int(x) for x in (mids_by_target.get(target) or []) if int(x) > 0)
        if not mids:
            continue
        rows.append(f"{target}|{','.join(str(x) for x in mids)}")
    digest = hashlib.sha1("\n".join(rows).encode("utf-8")).hexdigest()[:16] if rows else "none"
    return f"{int(node_id)}:{str(mode or 'ping')}:{int(tcp_port)}:{digest}"


def _queue_private_probe_task(
    node_id: int,
    mode: str,
    tcp_port: int,
    mids_by_target: Dict[str, List[int]],
    ts_ms: int,
) -> bool:
    node_id_i = int(node_id or 0)
    if node_id_i <= 0:
        return False

    mode_s = str(mode or "ping").strip().lower()
    if mode_s not in ("ping", "tcping"):
        mode_s = "ping"

    try:
        tcp_port_i = int(tcp_port)
    except Exception:
        tcp_port_i = 443
    if tcp_port_i < 1 or tcp_port_i > 65535:
        tcp_port_i = 443

    clean_map = _netmon_clean_mids_by_target(mids_by_target)
    if not clean_map:
        return False

    targets = list(clean_map.keys())[:50]
    clean_map = {t: clean_map.get(t, []) for t in targets}
    if not targets:
        return False

    group_key = _netmon_private_group_key(node_id_i, mode_s, tcp_port_i, clean_map)

    try:
        rows = list_tasks(node_id=node_id_i, limit=200)
    except Exception:
        rows = []

    for row in rows:
        if not isinstance(row, dict):
            continue
        if str(row.get("type") or "").strip().lower() != "netmon_probe":
            continue
        status = str(row.get("status") or "").strip().lower()
        if status not in ("queued", "running"):
            continue
        payload = row.get("payload") if isinstance(row.get("payload"), dict) else {}
        if str(payload.get("group_key") or "") == group_key:
            return True

    try:
        add_task(
            node_id=node_id_i,
            task_type="netmon_probe",
            payload={
                "node_id": node_id_i,
                "mode": mode_s,
                "tcp_port": tcp_port_i,
                "timeout": float(_NETMON_PROBE_TIMEOUT),
                "targets": targets,
                "mids_by_target": clean_map,
                "queued_ts_ms": int(ts_ms),
                "group_key": group_key,
                "max_attempts": int(_NETMON_QUEUE_MAX_ATTEMPTS),
            },
            status="queued",
            progress=0,
            result={
                "queued": True,
                "op": "netmon_probe",
                "attempt": 0,
                "max_attempts": int(_NETMON_QUEUE_MAX_ATTEMPTS),
                "group_key": group_key,
            },
            error="",
        )
        return True
    except Exception:
        return False


def enabled() -> bool:
    return bool(_NETMON_BG_ENABLED)


def _netmon_chunk(items: List[Optional[str]], size: int) -> List[List[str]]:
    out: List[List[str]] = []
    buf: List[str] = []
    for x in items:
        if x is None:
            continue
        s = str(x)
        if not s:
            continue
        buf.append(s)
        if len(buf) >= size:
            out.append(buf)
            buf = []
    if buf:
        out.append(buf)
    return out


async def _netmon_call_agent(node: Dict[str, Any], body: Dict[str, Any], timeout: float) -> Dict[str, Any]:
    """Call agent /api/v1/netprobe with a global concurrency limit."""
    async with _NETMON_SEM:
        return await agent_post(
            node.get("base_url", ""),
            node.get("api_key", ""),
            "/api/v1/netprobe",
            body,
            node_verify_tls(node),
            timeout=timeout,
        )


async def _netmon_collect_due(monitors_due: List[Dict[str, Any]], nodes_map: Dict[int, Dict[str, Any]]) -> None:
    """Collect a batch of due monitors.

    This is an optimized collector that batches probes per-node/per-mode/per-port so we don't
    generate M*N HTTP calls (which can cause intermittent timeouts/failures when monitors scale).
    """

    if not monitors_due:
        return

    ts_ms = int(time.time() * 1000)

    # direct-call group key: (node_id, mode, tcp_port)
    groups: Dict[Tuple[int, str, int], Dict[str, Any]] = {}
    # push-queue group key (private nodes): (node_id, mode, tcp_port)
    private_groups: Dict[Tuple[int, str, int], Dict[str, Any]] = {}
    # per monitor status for last_run_msg
    mon_stat: Dict[int, Dict[str, Any]] = {}

    def _mon_node_ids(mon: Dict[str, Any]) -> List[int]:
        node_ids = mon.get("node_ids") if isinstance(mon.get("node_ids"), list) else None
        if node_ids is None:
            try:
                raw = json.loads(str(mon.get("node_ids_json") or "[]"))
            except Exception:
                raw = []
            node_ids = raw if isinstance(raw, list) else []
        cleaned: List[int] = []
        for x in node_ids:
            try:
                nid = int(x)
            except Exception:
                continue
            if nid > 0 and nid not in cleaned:
                cleaned.append(nid)
        return cleaned[:60]

    def _flush_last_run() -> None:
        for mid, stt in mon_stat.items():
            try:
                msg = "ok" if bool(stt.get("ok_any")) else (str(stt.get("err") or "failed"))
                update_netmon_monitor(int(mid), last_run_ts_ms=int(ts_ms), last_run_msg=msg)
            except Exception:
                pass

    # build groups
    for mon in monitors_due:
        try:
            mid = int(mon.get("id") or 0)
        except Exception:
            continue
        if mid <= 0:
            continue

        target = str(mon.get("target") or "").strip()
        if not target:
            continue

        mode = str(mon.get("mode") or "ping").strip().lower()
        if mode not in ("ping", "tcping"):
            mode = "ping"

        try:
            tcp_port = int(mon.get("tcp_port") or 443)
        except Exception:
            tcp_port = 443
        if tcp_port < 1 or tcp_port > 65535:
            tcp_port = 443

        node_ids = _mon_node_ids(mon)
        if not node_ids:
            # no nodes selected
            try:
                update_netmon_monitor(mid, last_run_ts_ms=ts_ms, last_run_msg="no_nodes")
            except Exception:
                pass
            continue

        mon_stat[mid] = {"ok_any": False, "err": "", "ts": ts_ms, "seen": 0}

        for nid in node_ids:
            node = nodes_map.get(int(nid))
            if not node:
                # record a synthetic failure so the monitor shows something meaningful
                mon_stat[mid]["seen"] += 1
                if not mon_stat[mid]["err"]:
                    mon_stat[mid]["err"] = "node_missing"
                continue
            if bool(node.get("is_private") or 0):
                key = (int(nid), mode, int(tcp_port))
                g = private_groups.get(key)
                if not g:
                    g = {"targets": [], "mids_by_target": {}}
                    private_groups[key] = g
                m = g["mids_by_target"].get(target)
                if not m:
                    g["mids_by_target"][target] = [mid]
                    g["targets"].append(target)
                else:
                    m.append(mid)
                continue
            key = (int(nid), mode, int(tcp_port))
            g = groups.get(key)
            if not g:
                g = {"targets": [], "mids_by_target": {}}
                groups[key] = g
            m = g["mids_by_target"].get(target)
            if not m:
                g["mids_by_target"][target] = [mid]
                g["targets"].append(target)
            else:
                m.append(mid)

    rows: List[tuple] = []

    def _should_retry_err(s: str) -> bool:
        s = (s or "").lower()
        for kw in (
            "timeout",
            "timed out",
            "temporar",
            "connection aborted",
            "connection reset",
            "broken pipe",
        ):
            if kw in s:
                return True
        return False

    async def _run_group(nid: int, mode: str, tcp_port: int, targets: List[str], mids_by_target: Dict[str, List[int]]):
        node = nodes_map.get(int(nid))
        if not node:
            # should not happen (filtered above)
            for t in targets:
                for mid in (mids_by_target.get(t) or []):
                    stt = mon_stat.get(int(mid))
                    if stt:
                        stt["seen"] += 1
                        if not stt["err"]:
                            stt["err"] = "node_missing"
                    rows.append((int(mid), int(nid), int(ts_ms), 0, None, "node_missing"))
            return

        # HTTP timeout should always be larger than probe timeout + overhead
        http_timeout = float(max(_NETMON_HTTP_TIMEOUT, float(_NETMON_PROBE_TIMEOUT) + 3.0))

        for chunk in _netmon_chunk(targets, 50):
            body = {
                "mode": mode,
                "targets": chunk,
                "tcp_port": int(tcp_port),
                "timeout": float(_NETMON_PROBE_TIMEOUT),
            }

            last: Optional[Dict[str, Any]] = None
            # at most 2 tries on transient failures
            for attempt in range(2):
                try:
                    data = await _netmon_call_agent(node, body, timeout=http_timeout)
                    last = data if isinstance(data, dict) else {"ok": False, "error": "bad_response"}
                except Exception as exc:
                    last = {"ok": False, "error": str(exc)}

                if not isinstance(last, dict) or last.get("ok") is not True:
                    err = str(last.get("error") if isinstance(last, dict) else last)
                    if attempt == 0 and _should_retry_err(err):
                        await asyncio.sleep(0.12)
                        continue
                    break

                # agent call ok
                break

            # parse results
            ok_call = isinstance(last, dict) and last.get("ok") is True
            res_map = last.get("results") if ok_call and isinstance(last.get("results"), dict) else {}

            for t in chunk:
                mids = mids_by_target.get(t) or []
                item = res_map.get(t) if isinstance(res_map, dict) else None

                if ok_call and isinstance(item, dict):
                    if item.get("ok"):
                        try:
                            v = float(item.get("latency_ms")) if item.get("latency_ms") is not None else None
                        except Exception:
                            v = None
                        for mid in mids:
                            mid_i = int(mid)
                            stt = mon_stat.get(mid_i)
                            if stt:
                                stt["seen"] += 1
                                stt["ok_any"] = True
                            rows.append((mid_i, int(nid), int(ts_ms), 1, v, None))
                        continue

                    # probe failed for this target
                    err = str(item.get("error") or "probe_failed")
                    if len(err) > 200:
                        err = err[:200] + "…"

                    # retry per-target once if it looks transient and we haven't retried the call already
                    if _should_retry_err(err):
                        # do a best-effort single-target retry (cheaper than re-running the whole chunk)
                        try:
                            one_body = {
                                "mode": mode,
                                "targets": [t],
                                "tcp_port": int(tcp_port),
                                "timeout": float(_NETMON_PROBE_TIMEOUT),
                            }
                            data2 = await _netmon_call_agent(node, one_body, timeout=http_timeout)
                            if isinstance(data2, dict) and data2.get("ok") is True:
                                rm2 = data2.get("results") if isinstance(data2.get("results"), dict) else {}
                                it2 = rm2.get(t) if isinstance(rm2, dict) else None
                                if isinstance(it2, dict) and it2.get("ok"):
                                    try:
                                        v = float(it2.get("latency_ms")) if it2.get("latency_ms") is not None else None
                                    except Exception:
                                        v = None
                                    for mid in mids:
                                        mid_i = int(mid)
                                        stt = mon_stat.get(mid_i)
                                        if stt:
                                            stt["seen"] += 1
                                            stt["ok_any"] = True
                                        rows.append((mid_i, int(nid), int(ts_ms), 1, v, None))
                                    continue
                                if isinstance(it2, dict) and it2.get("error"):
                                    err = str(it2.get("error"))
                        except Exception:
                            pass

                    for mid in mids:
                        mid_i = int(mid)
                        stt = mon_stat.get(mid_i)
                        if stt:
                            stt["seen"] += 1
                            if not stt["err"]:
                                stt["err"] = err
                        rows.append((mid_i, int(nid), int(ts_ms), 0, None, err))
                    continue

                # agent call failed or missing item
                err = "agent_failed"
                if isinstance(last, dict) and last.get("error"):
                    err = str(last.get("error"))
                if len(err) > 200:
                    err = err[:200] + "…"
                if _netmon_is_dispatch_error(err):
                    for mid in mids:
                        mid_i = int(mid)
                        stt = mon_stat.get(mid_i)
                        if stt:
                            stt["seen"] += 1
                            if not stt["err"]:
                                stt["err"] = "dispatch_failed"
                    continue
                for mid in mids:
                    mid_i = int(mid)
                    stt = mon_stat.get(mid_i)
                    if stt:
                        stt["seen"] += 1
                        if not stt["err"]:
                            stt["err"] = err
                    rows.append((mid_i, int(nid), int(ts_ms), 0, None, err))

    tasks: List[asyncio.Task] = []
    for (nid, mode, tcp_port), g in groups.items():
        targets = g.get("targets") or []
        mids_by_target = g.get("mids_by_target") or {}
        if not targets:
            continue
        tasks.append(
            asyncio.create_task(_run_group(int(nid), str(mode), int(tcp_port), list(targets), dict(mids_by_target)))
        )

    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)

    # Private nodes: enqueue probe task to be executed by agent push-report command path.
    for (nid, mode, tcp_port), g in private_groups.items():
        mids_map = _netmon_clean_mids_by_target(g.get("mids_by_target") or {})
        if not mids_map:
            continue
        queued = _queue_private_probe_task(int(nid), str(mode), int(tcp_port), mids_map, int(ts_ms))
        msg = "dispatch_queued" if queued else "dispatch_failed"
        mids_all: List[int] = []
        for arr in mids_map.values():
            for mid in arr:
                mid_i = int(mid)
                if mid_i > 0 and mid_i not in mids_all:
                    mids_all.append(mid_i)
        for mid_i in mids_all:
            stt = mon_stat.get(mid_i)
            if not stt:
                continue
            stt["seen"] += 1
            # Keep direct probe result as higher priority if we already have one.
            if bool(stt.get("ok_any")):
                continue
            if not str(stt.get("err") or "").strip():
                stt["err"] = msg

    # Persist samples (best-effort)
    try:
        if rows:
            insert_netmon_samples(rows)
    except Exception:
        pass

    # Update monitor last_run
    _flush_last_run()


async def _netmon_bg_loop() -> None:
    """Background loop that continuously collects NetMon monitors."""
    last_refresh = 0.0
    last_cleanup = 0.0
    monitors_cache: List[Dict[str, Any]] = []
    nodes_map: Dict[int, Dict[str, Any]] = {}

    while True:
        try:
            now = time.time()

            # Refresh config cache periodically
            if (now - last_refresh) >= 3.0:
                try:
                    monitors_cache = list_netmon_monitors()
                except Exception:
                    monitors_cache = []
                # Drop stale scheduler state for deleted/invalid monitors to avoid long-term growth.
                active_ids: set[int] = set()
                for mon in monitors_cache:
                    try:
                        mid = int((mon or {}).get("id") or 0)
                    except Exception:
                        mid = 0
                    if mid > 0:
                        active_ids.add(mid)
                for mid in list(_NETMON_BG_LAST_RUN.keys()):
                    if mid not in active_ids:
                        _NETMON_BG_LAST_RUN.pop(mid, None)
                try:
                    nodes_map = {
                        int(n.get("id") or 0): n
                        for n in list_nodes_runtime()
                        if int(n.get("id") or 0) > 0
                    }
                except Exception:
                    nodes_map = {}
                last_refresh = now

            # Schedule due monitors (batch)
            due: List[Dict[str, Any]] = []
            for mon in monitors_cache:
                try:
                    mid = int(mon.get("id") or 0)
                except Exception:
                    continue
                if mid <= 0:
                    continue
                if not bool(mon.get("enabled") or 0):
                    continue
                try:
                    interval = int(mon.get("interval_sec") or 5)
                except Exception:
                    interval = 5
                if interval < 1:
                    interval = 1
                if interval > 3600:
                    interval = 3600

                last = float(_NETMON_BG_LAST_RUN.get(mid, 0.0) or 0.0)
                if (now - last) >= float(interval):
                    _NETMON_BG_LAST_RUN[mid] = now
                    due.append(mon)

            if due:
                # Optimized collector: batch probes per node/mode/port to avoid overload.
                await _netmon_collect_due(due, nodes_map)

            # Cleanup old samples
            if (now - last_cleanup) >= 60.0:
                try:
                    cutoff_ms = int((now - (_NETMON_RETENTION_DAYS * 86400)) * 1000)
                    prune_netmon_samples(cutoff_ms)
                except Exception:
                    pass
                last_cleanup = now

        except Exception:
            # Never crash the loop
            pass

        await asyncio.sleep(1.0)


def start_background(app: FastAPI) -> None:
    """Start NetMon background collector (idempotent)."""
    if not _NETMON_BG_ENABLED:
        return
    task = getattr(app.state, "netmon_bg_task", None)
    if isinstance(task, asyncio.Task) and not task.done():
        return
    try:
        task = spawn_background_task(_netmon_bg_loop(), label="netmon")
    except Exception:
        pass
        return
    app.state.netmon_bg_task = task
    app.state.netmon_bg_started = True
