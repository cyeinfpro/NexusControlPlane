from __future__ import annotations

import asyncio
import os
import time
from typing import Any, Dict, List

from fastapi import FastAPI

from ..clients.agent import agent_post
from ..core.bg_tasks import spawn_background_task
from ..db import (
    add_site_check,
    add_site_event,
    list_nodes_runtime,
    list_sites_runtime,
    prune_site_checks,
    update_site_health,
)
from .apply import node_verify_tls

_SITE_MONITOR_ENABLED = (os.getenv("REALM_SITE_MONITOR_ENABLED") or "1").strip() not in ("0", "false", "False")
try:
    _SITE_MONITOR_INTERVAL = int((os.getenv("REALM_SITE_MONITOR_INTERVAL") or "60").strip() or 60)
except Exception:
    _SITE_MONITOR_INTERVAL = 60
if _SITE_MONITOR_INTERVAL < 15:
    _SITE_MONITOR_INTERVAL = 15
if _SITE_MONITOR_INTERVAL > 600:
    _SITE_MONITOR_INTERVAL = 600

try:
    _SITE_MONITOR_TIMEOUT = float((os.getenv("REALM_SITE_MONITOR_TIMEOUT") or "8").strip() or 8)
except Exception:
    _SITE_MONITOR_TIMEOUT = 8
if _SITE_MONITOR_TIMEOUT < 2:
    _SITE_MONITOR_TIMEOUT = 2
if _SITE_MONITOR_TIMEOUT > 20:
    _SITE_MONITOR_TIMEOUT = 20

try:
    _SITE_MONITOR_CONCURRENCY = int((os.getenv("REALM_SITE_MONITOR_CONCURRENCY") or "12").strip() or 12)
except Exception:
    _SITE_MONITOR_CONCURRENCY = 12
if _SITE_MONITOR_CONCURRENCY < 2:
    _SITE_MONITOR_CONCURRENCY = 2
if _SITE_MONITOR_CONCURRENCY > 80:
    _SITE_MONITOR_CONCURRENCY = 80

try:
    _SITE_MONITOR_RETENTION_DAYS = int((os.getenv("REALM_SITE_MONITOR_RETENTION_DAYS") or "7").strip() or 7)
except Exception:
    _SITE_MONITOR_RETENTION_DAYS = 7
if _SITE_MONITOR_RETENTION_DAYS < 1:
    _SITE_MONITOR_RETENTION_DAYS = 1
if _SITE_MONITOR_RETENTION_DAYS > 90:
    _SITE_MONITOR_RETENTION_DAYS = 90

try:
    _SITE_MONITOR_PRUNE_EVERY_SEC = float((os.getenv("REALM_SITE_MONITOR_PRUNE_EVERY_SEC") or "900").strip() or 900)
except Exception:
    _SITE_MONITOR_PRUNE_EVERY_SEC = 900.0
if _SITE_MONITOR_PRUNE_EVERY_SEC < 60.0:
    _SITE_MONITOR_PRUNE_EVERY_SEC = 60.0
if _SITE_MONITOR_PRUNE_EVERY_SEC > 24 * 3600:
    _SITE_MONITOR_PRUNE_EVERY_SEC = 24 * 3600

try:
    _SITE_MONITOR_CACHE_REFRESH_SEC = float(
        (os.getenv("REALM_SITE_MONITOR_CACHE_REFRESH_SEC") or "10").strip() or 10
    )
except Exception:
    _SITE_MONITOR_CACHE_REFRESH_SEC = 10.0
if _SITE_MONITOR_CACHE_REFRESH_SEC < 3.0:
    _SITE_MONITOR_CACHE_REFRESH_SEC = 3.0
if _SITE_MONITOR_CACHE_REFRESH_SEC > 300.0:
    _SITE_MONITOR_CACHE_REFRESH_SEC = 300.0

_SEM = asyncio.Semaphore(_SITE_MONITOR_CONCURRENCY)
_LAST_RUN: Dict[int, float] = {}


def enabled() -> bool:
    return bool(_SITE_MONITOR_ENABLED)


def _is_agent_unreachable_error(err: Any) -> bool:
    msg = str(err or "").strip().lower()
    if not msg:
        return False
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


async def _check_site(site: Dict[str, Any], node: Dict[str, Any]) -> None:
    async with _SEM:
        payload = {
            "domains": site.get("domains") or [],
            "type": site.get("type") or "static",
            "root_path": site.get("root_path") or "",
            "proxy_target": site.get("proxy_target") or "",
            "root_base": node.get("website_root_base") or "",
        }
        ok = False
        status_code = 0
        latency_ms = 0
        error = ""
        try:
            data = await agent_post(
                node.get("base_url", ""),
                node.get("api_key", ""),
                "/api/v1/website/health",
                payload,
                node_verify_tls(node),
                timeout=_SITE_MONITOR_TIMEOUT,
            )
            ok = bool(data.get("ok"))
            status_code = int(data.get("status_code") or 0)
            latency_ms = int(data.get("latency_ms") or 0)
            error = str(data.get("error") or "").strip()
        except Exception as exc:
            error = str(exc)
            # Panel -> Agent management path may be temporarily unreachable.
            # This does not prove the website itself is down, so mark as unknown.
            if _is_agent_unreachable_error(error):
                try:
                    update_site_health(
                        int(site.get("id") or 0),
                        "unknown",
                        health_code=0,
                        health_latency_ms=0,
                        health_error=error,
                    )
                except Exception:
                    pass
                return
            ok = False
            status_code = 0
            latency_ms = 0

        new_status = "ok" if ok else "fail"
        try:
            update_site_health(
                int(site.get("id") or 0),
                new_status,
                health_code=status_code,
                health_latency_ms=latency_ms,
                health_error=error,
            )
        except Exception:
            pass
        try:
            add_site_check(int(site.get("id") or 0), ok, status_code=status_code, latency_ms=latency_ms, error=error)
        except Exception:
            pass

        # status change alerts
        prev = str(site.get("health_status") or "").strip()
        if prev and prev != new_status:
            if new_status == "fail":
                try:
                    add_site_event(int(site.get("id") or 0), "health_alert", status="failed", error=error)
                except Exception:
                    pass
            elif new_status == "ok":
                try:
                    add_site_event(int(site.get("id") or 0), "health_recovered", status="success")
                except Exception:
                    pass


async def _site_monitor_loop() -> None:
    last_prune = 0.0
    last_refresh = 0.0
    sites_cache: List[Dict[str, Any]] = []
    nodes_map: Dict[int, Dict[str, Any]] = {}
    while True:
        if not enabled():
            await asyncio.sleep(10)
            continue
        try:
            now = time.time()
            if (not sites_cache) or (not nodes_map) or ((now - last_refresh) >= float(_SITE_MONITOR_CACHE_REFRESH_SEC)):
                sites_cache = list_sites_runtime()
                nodes = list_nodes_runtime()
                nodes_map = {int(n.get("id") or 0): n for n in nodes if int(n.get("id") or 0) > 0}
                # Drop stale run markers for deleted sites to avoid long-term growth.
                active_site_ids: set[int] = set()
                for s in sites_cache:
                    try:
                        sid = int((s or {}).get("id") or 0)
                    except Exception:
                        sid = 0
                    if sid > 0:
                        active_site_ids.add(sid)
                for sid in list(_LAST_RUN.keys()):
                    if sid not in active_site_ids:
                        _LAST_RUN.pop(sid, None)
                last_refresh = now

            due: List[Dict[str, Any]] = []
            for s in sites_cache:
                sid = int(s.get("id") or 0)
                last = _LAST_RUN.get(sid, 0.0)
                if (now - last) < _SITE_MONITOR_INTERVAL:
                    continue
                node = nodes_map.get(int(s.get("node_id") or 0))
                if not node:
                    continue
                due.append(s)
                _LAST_RUN[sid] = now

            if due:
                tasks = []
                for s in due:
                    node = nodes_map.get(int(s.get("node_id") or 0))
                    if not node:
                        continue
                    tasks.append(_check_site(s, node))
                if tasks:
                    await asyncio.gather(*tasks, return_exceptions=True)

            # prune old checks periodically (avoid frequent large DELETE locks).
            if (now - last_prune) >= float(_SITE_MONITOR_PRUNE_EVERY_SEC):
                try:
                    prune_site_checks(_SITE_MONITOR_RETENTION_DAYS)
                except Exception:
                    pass
                last_prune = now
        except Exception:
            pass
        await asyncio.sleep(5)


async def start_background(app: FastAPI) -> None:
    task = getattr(app.state, "site_monitor_task", None)
    if isinstance(task, asyncio.Task) and not task.done():
        return
    try:
        task = spawn_background_task(_site_monitor_loop(), label="site-monitor")
    except Exception:
        return
    app.state.site_monitor_task = task
    app.state.site_monitor_started = True
