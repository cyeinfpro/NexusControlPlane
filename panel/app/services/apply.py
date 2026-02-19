from __future__ import annotations

import asyncio
import threading
from typing import Any, Dict, Tuple
from urllib.parse import urlsplit

from ..clients.agent import agent_post
from ..core.bg_tasks import spawn_background_task
from ..utils.normalize import format_host_for_url


def node_verify_tls(node: Dict[str, Any]) -> bool:
    return bool(node.get("verify_tls", 0))


def _node_base_scheme(node: Dict[str, Any]) -> str:
    raw = str((node or {}).get("base_url") or "").strip()
    if "://" not in raw:
        raw = f"http://{raw}" if raw else "http://"
    try:
        scheme = str(urlsplit(raw).scheme or "http").strip().lower()
    except Exception:
        scheme = "http"
    if scheme not in ("http", "https"):
        scheme = "http"
    return scheme


def node_agent_request_target(node: Dict[str, Any]) -> Tuple[str, bool, str]:
    base_url = str((node or {}).get("base_url") or "").strip()
    verify_tls = bool(node_verify_tls(node))
    dt = (node or {}).get("direct_tunnel") if isinstance(node, dict) else {}
    if not isinstance(dt, dict) or not bool(dt.get("enabled")):
        return base_url, verify_tls, "base_url"

    direct_base = str(dt.get("direct_base_url") or "").strip()
    if direct_base:
        return direct_base, bool(dt.get("verify_tls")), "direct_tunnel"

    host = str(dt.get("public_host") or "").strip()
    try:
        listen_port = int(dt.get("listen_port") or 0)
    except Exception:
        listen_port = 0
    if host and 1 <= listen_port <= 65535:
        scheme = str(dt.get("scheme") or "").strip().lower()
        if scheme not in ("http", "https"):
            scheme = _node_base_scheme(node)
        direct_base = f"{scheme}://{format_host_for_url(host)}:{int(listen_port)}"
        return direct_base, bool(dt.get("verify_tls")), "direct_tunnel"

    return base_url, verify_tls, "base_url"


async def bg_apply_pool(node: Dict[str, Any], pool: Dict[str, Any]) -> None:
    """Best-effort: push pool to agent and apply in background (do not block HTTP responses)."""
    target_base_url, target_verify_tls, _target_route = node_agent_request_target(node)
    try:
        data = await agent_post(
            target_base_url,
            node["api_key"],
            "/api/v1/pool",
            {"pool": pool},
            target_verify_tls,
        )
        if isinstance(data, dict) and data.get("ok", True):
            await agent_post(target_base_url, node["api_key"], "/api/v1/apply", {}, target_verify_tls)
    except Exception:
        return


def schedule_apply_pool(node: Dict[str, Any], pool: Dict[str, Any]) -> None:
    """Schedule best-effort agent apply without blocking the request.

    Compatibility:
      - If there is a running event loop: create_task
      - Otherwise: run in a dedicated daemon thread
    """
    try:
        _ = asyncio.get_running_loop()
        spawn_background_task(bg_apply_pool(node, pool), label="apply-pool")
        return
    except RuntimeError:
        # no running loop in this thread
        pass
    except Exception:
        return

    try:
        def _runner() -> None:
            try:
                asyncio.run(bg_apply_pool(node, pool))
            except Exception:
                return

        threading.Thread(target=_runner, daemon=True, name="nexus-apply-pool").start()
    except Exception:
        return
