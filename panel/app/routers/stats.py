"""
Stats Router - 统计与监控路由

包含:
- 流量/连接数历史
- 系统状态
- 性能指标
"""

from __future__ import annotations

import json
import time
from collections import defaultdict
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from ..db import (
    get_node,
    get_desired_pool,
    get_last_report,
)
from ..services import agent_get, agent_post
from .auth import require_login

router = APIRouter(prefix="/api/stats", tags=["stats"])


# ==================== 历史数据存储 ====================

# 内存中的历史数据缓存 (生产环境建议使用数据库)
# 结构: { node_id: { rule_idx: [ {ts, connections, rx_bytes, tx_bytes}, ... ] } }
_HISTORY_CACHE: Dict[int, Dict[int, List[Dict[str, Any]]]] = defaultdict(lambda: defaultdict(list))
_HISTORY_MAX_POINTS = 1440  # 最多保留 24 小时的分钟级数据


def _node_verify_tls(node: Dict[str, Any]) -> bool:
    """获取节点的 TLS 验证设置"""
    return bool(node.get("verify_tls", False))


def _is_report_fresh(node: Dict[str, Any], max_age_sec: int = 60) -> bool:
    """检查节点报告是否新鲜"""
    last_seen = node.get("last_seen_at")
    if not last_seen:
        return False
    try:
        dt = datetime.fromisoformat(last_seen.replace("Z", "+00:00"))
        age = (datetime.now(dt.tzinfo) - dt).total_seconds()
        return age < max_age_sec
    except Exception:
        return False


# ==================== 历史数据收集 ====================

def record_stats_snapshot(node_id: int, stats: Dict[str, Any]):
    """记录统计快照到历史"""
    rules = stats.get("rules", [])
    if not isinstance(rules, list):
        return
    
    ts = int(time.time() * 1000)
    node_history = _HISTORY_CACHE[node_id]
    
    for rule in rules:
        idx = rule.get("idx", -1)
        if idx < 0:
            continue
        
        point = {
            "ts": ts,
            "connections": rule.get("connections", 0),
            "connections_active": rule.get("connections_active", 0),
            "connections_total": rule.get("connections_total", 0),
            "rx_bytes": rule.get("rx_bytes", 0),
            "tx_bytes": rule.get("tx_bytes", 0),
        }
        
        history = node_history[idx]
        history.append(point)
        
        # 限制历史点数
        if len(history) > _HISTORY_MAX_POINTS:
            node_history[idx] = history[-_HISTORY_MAX_POINTS:]


# ==================== API 路由 ====================

@router.get("/nodes/{node_id}/history")
async def api_get_node_history(
    node_id: int,
    rule_idx: Optional[int] = None,
    since: Optional[int] = None,  # 毫秒时间戳
    limit: int = 360,
    user: str = Depends(require_login),
):
    """获取节点的历史统计数据"""
    node = get_node(node_id)
    if not node:
        return JSONResponse({"ok": False, "error": "节点不存在"}, status_code=404)
    
    node_history = _HISTORY_CACHE.get(node_id, {})
    
    # 先尝试从最新报告中更新历史
    if _is_report_fresh(node):
        rep = get_last_report(node_id)
        if isinstance(rep, dict) and isinstance(rep.get("stats"), dict):
            record_stats_snapshot(node_id, rep["stats"])
    
    result = {}
    
    if rule_idx is not None:
        # 获取单个规则的历史
        history = node_history.get(rule_idx, [])
        if since:
            history = [p for p in history if p["ts"] >= since]
        result[str(rule_idx)] = history[-limit:]
    else:
        # 获取所有规则的历史
        for idx, history in node_history.items():
            filtered = history
            if since:
                filtered = [p for p in history if p["ts"] >= since]
            result[str(idx)] = filtered[-limit:]
    
    return {
        "ok": True,
        "node_id": node_id,
        "history": result,
        "ts": int(time.time() * 1000),
    }


@router.get("/nodes/{node_id}/summary")
async def api_get_node_summary(
    node_id: int,
    user: str = Depends(require_login),
):
    """获取节点的统计摘要"""
    node = get_node(node_id)
    if not node:
        return JSONResponse({"ok": False, "error": "节点不存在"}, status_code=404)
    
    # 获取当前统计
    stats = None
    if _is_report_fresh(node):
        rep = get_last_report(node_id)
        if isinstance(rep, dict) and isinstance(rep.get("stats"), dict):
            stats = rep["stats"]
    
    if not stats:
        try:
            stats = await agent_get(
                node["base_url"], 
                node["api_key"], 
                "/api/v1/stats", 
                _node_verify_tls(node)
            )
        except Exception:
            stats = {"rules": []}
    
    rules = stats.get("rules", [])
    
    # 计算汇总
    total_connections = 0
    total_connections_active = 0
    total_rx_bytes = 0
    total_tx_bytes = 0
    enabled_count = 0
    disabled_count = 0
    online_count = 0
    offline_count = 0
    
    for rule in rules:
        total_connections += rule.get("connections", 0)
        total_connections_active += rule.get("connections_active", 0)
        total_rx_bytes += rule.get("rx_bytes", 0)
        total_tx_bytes += rule.get("tx_bytes", 0)
        
        if rule.get("disabled"):
            disabled_count += 1
        else:
            enabled_count += 1
        
        # 检查连通性
        health = rule.get("health", [])
        if isinstance(health, list) and health:
            if any(h.get("ok") for h in health if isinstance(h, dict)):
                online_count += 1
            elif not rule.get("disabled"):
                offline_count += 1
    
    # 获取历史趋势
    node_history = _HISTORY_CACHE.get(node_id, {})
    
    # 计算过去1小时的趋势
    one_hour_ago = int((time.time() - 3600) * 1000)
    hourly_rx = 0
    hourly_tx = 0
    
    for idx, history in node_history.items():
        filtered = [p for p in history if p["ts"] >= one_hour_ago]
        if len(filtered) >= 2:
            hourly_rx += filtered[-1].get("rx_bytes", 0) - filtered[0].get("rx_bytes", 0)
            hourly_tx += filtered[-1].get("tx_bytes", 0) - filtered[0].get("tx_bytes", 0)
    
    return {
        "ok": True,
        "node_id": node_id,
        "summary": {
            "total_rules": len(rules),
            "enabled_rules": enabled_count,
            "disabled_rules": disabled_count,
            "online_rules": online_count,
            "offline_rules": offline_count,
            "total_connections": total_connections,
            "total_connections_active": total_connections_active,
            "total_rx_bytes": total_rx_bytes,
            "total_tx_bytes": total_tx_bytes,
            "hourly_rx_bytes": max(0, hourly_rx),
            "hourly_tx_bytes": max(0, hourly_tx),
        },
        "ts": int(time.time() * 1000),
    }


@router.get("/nodes/{node_id}/sys")
async def api_get_sys(
    node_id: int,
    cached: int = 0,
    user: str = Depends(require_login),
):
    """获取节点系统信息"""
    node = get_node(node_id)
    if not node:
        return JSONResponse({"ok": False, "error": "节点不存在"}, status_code=404)
    
    sys_data = None
    source = None
    
    # Push-report cache
    if cached:
        rep = get_last_report(node_id)
        if isinstance(rep, dict) and isinstance(rep.get("sys"), dict):
            sys_data = dict(rep["sys"])
            sys_data["stale"] = not _is_report_fresh(node)
            source = "report"
    else:
        if _is_report_fresh(node):
            rep = get_last_report(node_id)
            if isinstance(rep, dict) and isinstance(rep.get("sys"), dict):
                sys_data = dict(rep["sys"])
                source = "report"
    
    # Fallback: 直连 Agent
    if sys_data is None:
        if cached:
            return {
                "ok": True,
                "sys": {
                    "ok": False,
                    "error": "Agent 尚未上报系统信息",
                    "source": "report",
                },
            }
        
        try:
            data = await agent_get(
                node["base_url"], 
                node["api_key"], 
                "/api/v1/sys", 
                _node_verify_tls(node)
            )
            if isinstance(data, dict) and data.get("ok") is True:
                sys_data = dict(data)
                source = "agent"
            else:
                return {"ok": False, "error": data.get("error") if isinstance(data, dict) else "响应格式异常"}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}
    
    sys_data["source"] = source or "unknown"
    return {"ok": True, "sys": sys_data}


@router.get("/nodes/{node_id}/graph")
async def api_get_graph(
    node_id: int,
    user: str = Depends(require_login),
):
    """获取节点规则拓扑图数据"""
    node = get_node(node_id)
    if not node:
        return JSONResponse({"ok": False, "error": "节点不存在"}, status_code=404)
    
    desired_ver, desired_pool = get_desired_pool(node_id)
    pool = desired_pool if isinstance(desired_pool, dict) else None
    
    if pool is None and _is_report_fresh(node):
        rep = get_last_report(node_id)
        if isinstance(rep, dict) and isinstance(rep.get("pool"), dict):
            pool = rep["pool"]
    
    if pool is None:
        try:
            data = await agent_get(
                node["base_url"], 
                node["api_key"], 
                "/api/v1/pool", 
                _node_verify_tls(node)
            )
            pool = data.get("pool") if isinstance(data, dict) else None
        except Exception as exc:
            return JSONResponse({"ok": False, "error": str(exc)}, status_code=502)
    
    endpoints = pool.get("endpoints", []) if isinstance(pool, dict) else []
    elements: List[Dict[str, Any]] = []
    
    for idx, endpoint in enumerate(endpoints):
        listen = endpoint.get("listen", f"listen-{idx}")
        listen_id = f"listen-{idx}"
        classes = ["listen"]
        
        if endpoint.get("disabled"):
            classes.append("disabled")
        if endpoint.get("favorite"):
            classes.append("favorite")
        
        elements.append({
            "data": {"id": listen_id, "label": listen},
            "classes": " ".join(classes)
        })
        
        remotes = endpoint.get("remotes") or ([endpoint.get("remote")] if endpoint.get("remote") else [])
        
        for r_idx, remote in enumerate(remotes):
            remote_id = f"remote-{idx}-{r_idx}"
            elements.append({
                "data": {"id": remote_id, "label": remote},
                "classes": "remote" + (" disabled" if endpoint.get("disabled") else ""),
            })
            
            ex = endpoint.get("extra_config") or {}
            edge_label = "WSS" if ex.get("listen_transport") == "ws" or ex.get("remote_transport") == "ws" else ""
            
            elements.append({
                "data": {"source": listen_id, "target": remote_id, "label": edge_label},
                "classes": "disabled" if endpoint.get("disabled") else "",
            })
    
    return {"ok": True, "elements": elements}


# ==================== 全局统计 ====================

@router.get("/global")
async def api_get_global_stats(user: str = Depends(require_login)):
    """获取全局统计摘要"""
    from ..db import list_nodes
    
    nodes = list_nodes()
    
    total_nodes = len(nodes)
    online_nodes = 0
    total_rules = 0
    enabled_rules = 0
    total_connections = 0
    total_rx_bytes = 0
    total_tx_bytes = 0
    
    for node in nodes:
        if _is_report_fresh(node):
            online_nodes += 1
            rep = get_last_report(node["id"])
            if isinstance(rep, dict):
                pool = rep.get("pool", {})
                stats = rep.get("stats", {})
                
                endpoints = pool.get("endpoints", []) if isinstance(pool, dict) else []
                total_rules += len(endpoints)
                enabled_rules += len([e for e in endpoints if not e.get("disabled")])
                
                rules = stats.get("rules", []) if isinstance(stats, dict) else []
                for rule in rules:
                    total_connections += rule.get("connections", 0)
                    total_rx_bytes += rule.get("rx_bytes", 0)
                    total_tx_bytes += rule.get("tx_bytes", 0)
    
    return {
        "ok": True,
        "summary": {
            "total_nodes": total_nodes,
            "online_nodes": online_nodes,
            "offline_nodes": total_nodes - online_nodes,
            "total_rules": total_rules,
            "enabled_rules": enabled_rules,
            "disabled_rules": total_rules - enabled_rules,
            "total_connections": total_connections,
            "total_rx_bytes": total_rx_bytes,
            "total_tx_bytes": total_tx_bytes,
        },
        "ts": int(time.time() * 1000),
    }
