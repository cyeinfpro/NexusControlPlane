from __future__ import annotations

from typing import Any, Dict

from ..clients.agent import agent_get
from ..db import get_desired_pool, get_last_report
from .apply import node_agent_request_target
from .node_fetch import node_info_sources_order


async def get_pool_for_backup(node: Dict[str, Any]) -> Dict[str, Any]:
    """Get pool data for backup.

    Prefer panel-desired first, then report cache / agent pull by configured order.
    """
    if not isinstance(node, dict):
        return {"ok": False, "error": "invalid_node"}
    try:
        node_id = int(node.get("id") or 0)
    except Exception:
        node_id = 0
    desired_ver, desired_pool = get_desired_pool(node_id)
    if isinstance(desired_pool, dict):
        return {
            "ok": True,
            "pool": desired_pool,
            "desired_version": desired_ver,
            "source": "panel_desired",
        }

    rep: Any = None
    last_pull_err = ""
    for source in node_info_sources_order(force_pull=False):
        if source == "report":
            if rep is None:
                rep = get_last_report(node_id)
            if isinstance(rep, dict) and isinstance(rep.get("pool"), dict):
                return {"ok": True, "pool": rep.get("pool"), "source": "report_cache"}
            continue

        try:
            target_base_url, target_verify_tls, _target_route = node_agent_request_target(node)
            data = await agent_get(target_base_url, node.get("api_key", ""), "/api/v1/pool", target_verify_tls)
            if isinstance(data, dict) and isinstance(data.get("pool"), dict):
                return {"ok": True, "pool": data.get("pool"), "source": "agent_pull"}
            if isinstance(data, dict):
                last_pull_err = str(data.get("error") or "agent_return_invalid")
            else:
                last_pull_err = "agent_return_invalid"
        except Exception as exc:
            last_pull_err = str(exc)

    if isinstance(rep, dict) and isinstance(rep.get("pool"), dict):
        return {"ok": True, "pool": rep.get("pool"), "source": "report_cache", "stale": True}

    return {"ok": False, "error": last_pull_err or "无可用规则快照", "source": "fallback"}
