from __future__ import annotations

from typing import Any, Tuple

from .panel_config import setting_str


FETCH_ORDER_PUSH_FIRST = "push_first"
FETCH_ORDER_PULL_FIRST = "pull_first"


def normalize_node_info_fetch_order(raw: Any, default: str = FETCH_ORDER_PUSH_FIRST) -> str:
    s = str(raw or "").strip().lower().replace("-", "_")
    pull_aliases = {
        "pull_first",
        "pull",
        "direct",
        "direct_first",
        "panel_pull_first",
        "panel_first",
    }
    push_aliases = {
        "push_first",
        "push",
        "report",
        "report_first",
        "agent_push_first",
        "agent_first",
    }
    if s in pull_aliases:
        return FETCH_ORDER_PULL_FIRST
    if s in push_aliases:
        return FETCH_ORDER_PUSH_FIRST
    d = str(default or "").strip().lower().replace("-", "_")
    if d in pull_aliases:
        return FETCH_ORDER_PULL_FIRST
    return FETCH_ORDER_PUSH_FIRST


def node_info_fetch_order() -> str:
    raw = setting_str(
        "node_info_fetch_order",
        default=FETCH_ORDER_PUSH_FIRST,
        env_names=[
            "REALM_NODE_INFO_FETCH_ORDER",
            "REALM_NODE_DATA_FETCH_ORDER",
            "REALM_NODE_REPORT_FETCH_ORDER",
        ],
    )
    return normalize_node_info_fetch_order(raw, FETCH_ORDER_PUSH_FIRST)


def node_info_prefers_pull() -> bool:
    return node_info_fetch_order() == FETCH_ORDER_PULL_FIRST


def node_info_sources_order(force_pull: bool = False) -> Tuple[str, str]:
    if bool(force_pull):
        return ("pull", "report")
    if node_info_prefers_pull():
        return ("pull", "report")
    return ("report", "pull")
