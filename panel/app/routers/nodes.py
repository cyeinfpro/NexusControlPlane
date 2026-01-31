"""
Nodes Router - 节点管理路由

包含:
- 节点 CRUD
- 节点状态查询
- 规则管理
- 批量操作
"""

from __future__ import annotations

import json
import secrets
from datetime import datetime
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from ..db import (
    add_node,
    delete_node,
    get_node,
    get_node_by_api_key,
    get_node_by_base_url,
    get_desired_pool,
    get_last_report,
    list_nodes,
    set_desired_pool,
    update_node_basic,
)
from ..services import (
    agent_get,
    agent_post,
    agent_ping,
    validate_and_normalize,
    ValidationResult,
    DEFAULT_AGENT_PORT,
)
from .auth import require_login, require_login_page

router = APIRouter(tags=["nodes"])


# ==================== 工具函数 ====================

def _generate_api_key(length: int = 32) -> str:
    """生成 API Key"""
    return secrets.token_urlsafe(length)


def _extract_ip_for_display(base_url: str) -> str:
    """从 base_url 提取 IP/主机名用于显示"""
    try:
        if "://" not in base_url:
            base_url = f"http://{base_url}"
        parsed = urlparse(base_url)
        return parsed.hostname or base_url
    except Exception:
        return base_url


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


def _set_flash(request: Request, msg: str):
    """设置闪存消息"""
    request.session["flash"] = msg


def _flash(request: Request) -> str:
    """获取并清除闪存消息"""
    return request.session.pop("flash", "")


# ==================== 页面路由 ====================

@router.get("/nodes/new", response_class=HTMLResponse)
async def node_new_page(request: Request, user: str = Depends(require_login_page)):
    """添加节点页面"""
    from ..main import templates
    
    api_key = _generate_api_key()
    return templates.TemplateResponse(
        "nodes_new.html",
        {
            "request": request,
            "user": user,
            "flash": _flash(request),
            "title": "添加机器",
            "api_key": api_key,
            "default_port": DEFAULT_AGENT_PORT,
        },
    )


@router.get("/nodes/{node_id}", response_class=HTMLResponse)
async def node_detail_page(request: Request, node_id: int, user: str = Depends(require_login_page)):
    """节点详情页面"""
    from ..main import templates
    
    node = get_node(node_id)
    if not node:
        _set_flash(request, "节点不存在")
        return RedirectResponse(url="/", status_code=303)
    
    return templates.TemplateResponse(
        "node_detail.html",
        {
            "request": request,
            "user": user,
            "node": node,
            "flash": _flash(request),
            "title": f"节点 - {node.get('name', '')}",
        },
    )


# ==================== API 路由 ====================

@router.get("/api/nodes")
async def api_list_nodes(user: str = Depends(require_login)):
    """获取节点列表"""
    nodes = list_nodes()
    for n in nodes:
        n["display_ip"] = _extract_ip_for_display(n.get("base_url", ""))
        n["online"] = _is_report_fresh(n)
    return {"ok": True, "nodes": nodes}


@router.post("/api/nodes")
async def api_create_node(
    request: Request,
    user: str = Depends(require_login),
):
    """创建节点"""
    try:
        payload = await request.json()
    except Exception:
        return JSONResponse({"ok": False, "error": "Invalid JSON"}, status_code=400)
    
    name = str(payload.get("name", "")).strip()
    base_url = str(payload.get("base_url", "")).strip().rstrip("/")
    api_key = str(payload.get("api_key", "")).strip() or _generate_api_key()
    verify_tls = bool(payload.get("verify_tls", False))
    is_private = bool(payload.get("is_private", False))
    group_name = str(payload.get("group_name", "默认分组")).strip() or "默认分组"
    
    if not base_url:
        return JSONResponse({"ok": False, "error": "base_url 不能为空"}, status_code=400)
    
    # 检查重复
    existing = get_node_by_api_key(api_key) or get_node_by_base_url(base_url)
    if existing:
        return JSONResponse({"ok": False, "error": "节点已存在"}, status_code=400)
    
    if not name:
        name = _extract_ip_for_display(base_url)
    
    node_id = add_node(name, base_url, api_key, verify_tls=verify_tls, is_private=is_private, group_name=group_name)
    return {"ok": True, "node_id": node_id}


@router.post("/nodes/new")
async def node_new_action(
    request: Request,
    name: str = Form(""),
    group_name: str = Form("默认分组"),
    is_private: Optional[str] = Form(None),
    ip_address: str = Form(...),
    scheme: str = Form("http"),
    api_key: str = Form(""),
    verify_tls: Optional[str] = Form(None),
):
    """处理添加节点表单"""
    user = request.session.get("user")
    if not user:
        return RedirectResponse(url="/login", status_code=303)
    
    ip_address = ip_address.strip()
    api_key = api_key.strip() or _generate_api_key()
    scheme = scheme.strip().lower() or "http"
    
    if scheme not in ("http", "https"):
        _set_flash(request, "协议仅支持 http 或 https")
        return RedirectResponse(url="/nodes/new", status_code=303)
    
    if not ip_address:
        _set_flash(request, "IP 地址不能为空")
        return RedirectResponse(url="/nodes/new", status_code=303)
    
    if "://" not in ip_address:
        ip_address = f"{scheme}://{ip_address}"
    
    # 确保有端口
    if not any(f":{p}" in ip_address for p in range(1, 65536)):
        ip_address = f"{ip_address}:{DEFAULT_AGENT_PORT}"
    
    base_url = ip_address.rstrip("/")
    
    existing = get_node_by_api_key(api_key) or get_node_by_base_url(base_url)
    if existing:
        _set_flash(request, "节点已存在（API Key 或地址重复）")
        return RedirectResponse(url="/nodes/new", status_code=303)
    
    if not name:
        name = _extract_ip_for_display(base_url)
    
    node_id = add_node(
        name,
        base_url,
        api_key,
        verify_tls=bool(verify_tls),
        is_private=bool(is_private),
        group_name=group_name.strip() or "默认分组",
    )
    
    _set_flash(request, "节点添加成功")
    return RedirectResponse(url=f"/nodes/{node_id}", status_code=303)


@router.get("/api/nodes/{node_id}")
async def api_get_node(node_id: int, user: str = Depends(require_login)):
    """获取单个节点信息"""
    node = get_node(node_id)
    if not node:
        return JSONResponse({"ok": False, "error": "节点不存在"}, status_code=404)
    
    node["display_ip"] = _extract_ip_for_display(node.get("base_url", ""))
    node["online"] = _is_report_fresh(node)
    return {"ok": True, "node": node}


@router.put("/api/nodes/{node_id}")
async def api_update_node(
    node_id: int,
    request: Request,
    user: str = Depends(require_login),
):
    """更新节点信息"""
    node = get_node(node_id)
    if not node:
        return JSONResponse({"ok": False, "error": "节点不存在"}, status_code=404)
    
    try:
        payload = await request.json()
    except Exception:
        return JSONResponse({"ok": False, "error": "Invalid JSON"}, status_code=400)
    
    name = payload.get("name", node.get("name", ""))
    base_url = payload.get("base_url", node.get("base_url", ""))
    api_key = payload.get("api_key", node.get("api_key", ""))
    verify_tls = payload.get("verify_tls", node.get("verify_tls", False))
    is_private = payload.get("is_private", node.get("is_private", False))
    group_name = payload.get("group_name", node.get("group_name", "默认分组"))
    
    update_node_basic(
        node_id,
        name=str(name).strip(),
        base_url=str(base_url).strip().rstrip("/"),
        api_key=str(api_key).strip(),
        verify_tls=bool(verify_tls),
        is_private=bool(is_private),
        group_name=str(group_name).strip() or "默认分组",
    )
    
    return {"ok": True}


@router.delete("/api/nodes/{node_id}")
async def api_delete_node(node_id: int, user: str = Depends(require_login)):
    """删除节点"""
    node = get_node(node_id)
    if not node:
        return JSONResponse({"ok": False, "error": "节点不存在"}, status_code=404)
    
    delete_node(node_id)
    return {"ok": True}


@router.get("/api/nodes/{node_id}/ping")
async def api_ping_node(node_id: int, user: str = Depends(require_login)):
    """Ping 节点"""
    node = get_node(node_id)
    if not node:
        return JSONResponse({"ok": False, "error": "节点不存在"}, status_code=404)
    
    # Push-report mode
    if _is_report_fresh(node):
        rep = get_last_report(node_id)
        info = rep.get("info") if isinstance(rep, dict) else None
        return {
            "ok": True,
            "source": "report",
            "last_seen_at": node.get("last_seen_at"),
            "info": info,
        }
    
    info = await agent_ping(node["base_url"], node["api_key"], _node_verify_tls(node))
    if not info.get("ok"):
        return {"ok": False, "error": info.get("error", "offline")}
    return info


@router.get("/api/nodes/{node_id}/pool")
async def api_get_pool(node_id: int, user: str = Depends(require_login)):
    """获取节点规则池"""
    node = get_node(node_id)
    if not node:
        return JSONResponse({"ok": False, "error": "节点不存在"}, status_code=404)
    
    # 优先使用面板存储的期望配置
    desired_ver, desired_pool = get_desired_pool(node_id)
    if isinstance(desired_pool, dict):
        return {"ok": True, "pool": desired_pool, "desired_version": desired_ver, "source": "panel_desired"}
    
    # 尝试使用最后一次报告
    rep = get_last_report(node_id)
    if isinstance(rep, dict) and isinstance(rep.get("pool"), dict):
        return {"ok": True, "pool": rep.get("pool"), "source": "report_cache"}
    
    # 直连 Agent 获取
    try:
        data = await agent_get(node["base_url"], node["api_key"], "/api/v1/pool", _node_verify_tls(node))
        return data
    except Exception as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=502)


@router.post("/api/nodes/{node_id}/pool")
async def api_set_pool(
    node_id: int,
    request: Request,
    user: str = Depends(require_login),
):
    """设置节点规则池"""
    node = get_node(node_id)
    if not node:
        return JSONResponse({"ok": False, "error": "节点不存在"}, status_code=404)
    
    try:
        payload = await request.json()
    except Exception:
        return JSONResponse({"ok": False, "error": "Invalid JSON"}, status_code=400)
    
    pool = payload.get("pool")
    if not isinstance(pool, dict):
        return JSONResponse({"ok": False, "error": "pool 必须是对象"}, status_code=400)
    
    # 校验规则池
    validation = validate_and_normalize(pool)
    if not validation.valid:
        return JSONResponse({
            "ok": False,
            "error": "规则校验失败",
            "validation": validation.to_dict(),
        }, status_code=400)
    
    # 使用规范化后的规则池
    normalized_pool = validation.normalized_pool or pool
    
    # 存储到面板
    desired_ver, _ = set_desired_pool(node_id, normalized_pool)
    
    # 尝试推送到 Agent
    applied = False
    try:
        data = await agent_post(
            node["base_url"],
            node["api_key"],
            "/api/v1/pool",
            {"pool": normalized_pool},
            _node_verify_tls(node),
        )
        if isinstance(data, dict) and data.get("ok", True):
            applied = True
    except Exception:
        pass
    
    return {
        "ok": True,
        "desired_version": desired_ver,
        "applied": applied,
        "validation": validation.to_dict(),
    }


@router.post("/api/nodes/{node_id}/pool/validate")
async def api_validate_pool(
    node_id: int,
    request: Request,
    user: str = Depends(require_login),
):
    """校验规则池（不保存）"""
    node = get_node(node_id)
    if not node:
        return JSONResponse({"ok": False, "error": "节点不存在"}, status_code=404)
    
    try:
        payload = await request.json()
    except Exception:
        return JSONResponse({"ok": False, "error": "Invalid JSON"}, status_code=400)
    
    pool = payload.get("pool")
    if not isinstance(pool, dict):
        return JSONResponse({"ok": False, "error": "pool 必须是对象"}, status_code=400)
    
    validation = validate_and_normalize(pool)
    return {
        "ok": validation.valid,
        "validation": validation.to_dict(),
    }


@router.post("/api/nodes/{node_id}/apply")
async def api_apply_node(node_id: int, user: str = Depends(require_login)):
    """应用节点配置"""
    node = get_node(node_id)
    if not node:
        return JSONResponse({"ok": False, "error": "节点不存在"}, status_code=404)
    
    try:
        data = await agent_post(
            node["base_url"],
            node["api_key"],
            "/api/v1/apply",
            {},
            _node_verify_tls(node),
        )
        if not data.get("ok", True):
            return JSONResponse({"ok": False, "error": data.get("error", "Agent 应用配置失败")}, status_code=502)
        return data
    except Exception:
        # 推送模式回退
        desired_ver, desired_pool = get_desired_pool(node_id)
        if isinstance(desired_pool, dict):
            new_ver, _ = set_desired_pool(node_id, desired_pool)
            return {"ok": True, "queued": True, "desired_version": new_ver}
        return {"ok": False, "error": "Agent 无法访问，且面板无缓存规则"}


@router.get("/api/nodes/{node_id}/stats")
async def api_get_stats(node_id: int, user: str = Depends(require_login)):
    """获取节点规则统计"""
    node = get_node(node_id)
    if not node:
        return JSONResponse({"ok": False, "error": "节点不存在"}, status_code=404)
    
    # Push-report cache
    if _is_report_fresh(node):
        rep = get_last_report(node_id)
        if isinstance(rep, dict) and isinstance(rep.get("stats"), dict):
            out = rep["stats"]
            out["source"] = "report"
            return out
    
    try:
        data = await agent_get(node["base_url"], node["api_key"], "/api/v1/stats", _node_verify_tls(node))
        return data
    except Exception as exc:
        return {"ok": False, "error": str(exc), "rules": []}


# ==================== 批量操作 API ====================

@router.post("/api/nodes/{node_id}/rules/batch")
async def api_batch_rules(
    node_id: int,
    request: Request,
    user: str = Depends(require_login),
):
    """批量操作规则"""
    node = get_node(node_id)
    if not node:
        return JSONResponse({"ok": False, "error": "节点不存在"}, status_code=404)
    
    try:
        payload = await request.json()
    except Exception:
        return JSONResponse({"ok": False, "error": "Invalid JSON"}, status_code=400)
    
    action = payload.get("action")  # enable, disable, delete, copy
    indices = payload.get("indices", [])  # 规则索引列表
    
    if not isinstance(indices, list) or not indices:
        return JSONResponse({"ok": False, "error": "indices 必须是非空数组"}, status_code=400)
    
    # 获取当前规则池
    desired_ver, pool = get_desired_pool(node_id)
    if not isinstance(pool, dict):
        rep = get_last_report(node_id)
        pool = rep.get("pool") if isinstance(rep, dict) else None
    
    if not isinstance(pool, dict):
        return JSONResponse({"ok": False, "error": "无法获取当前规则池"}, status_code=400)
    
    endpoints = pool.get("endpoints", [])
    if not isinstance(endpoints, list):
        endpoints = []
    
    # 执行批量操作
    modified = False
    
    if action == "enable":
        for idx in indices:
            if 0 <= idx < len(endpoints):
                endpoints[idx]["disabled"] = False
                modified = True
    
    elif action == "disable":
        for idx in indices:
            if 0 <= idx < len(endpoints):
                endpoints[idx]["disabled"] = True
                modified = True
    
    elif action == "delete":
        # 从大到小删除，避免索引错位
        for idx in sorted(indices, reverse=True):
            if 0 <= idx < len(endpoints):
                endpoints.pop(idx)
                modified = True
    
    elif action == "copy":
        # 复制规则到末尾
        for idx in indices:
            if 0 <= idx < len(endpoints):
                import copy
                new_ep = copy.deepcopy(endpoints[idx])
                # 修改 listen 端口避免冲突
                new_ep["disabled"] = True  # 复制的规则默认暂停
                if new_ep.get("note"):
                    new_ep["note"] = f"[复制] {new_ep.get('note', '')}"
                else:
                    new_ep["note"] = "[复制]"
                endpoints.append(new_ep)
                modified = True
    
    else:
        return JSONResponse({"ok": False, "error": f"未知操作: {action}"}, status_code=400)
    
    if not modified:
        return {"ok": True, "modified": False}
    
    # 保存修改
    pool["endpoints"] = endpoints
    new_ver, _ = set_desired_pool(node_id, pool)
    
    # 尝试应用
    applied = False
    try:
        data = await agent_post(
            node["base_url"],
            node["api_key"],
            "/api/v1/pool",
            {"pool": pool},
            _node_verify_tls(node),
        )
        if isinstance(data, dict) and data.get("ok", True):
            await agent_post(node["base_url"], node["api_key"], "/api/v1/apply", {}, _node_verify_tls(node))
            applied = True
    except Exception:
        pass
    
    return {
        "ok": True,
        "modified": True,
        "desired_version": new_ver,
        "applied": applied,
        "rule_count": len(endpoints),
    }


@router.post("/api/nodes/{node_id}/rules/{rule_index}/metadata")
async def api_update_rule_metadata(
    node_id: int,
    rule_index: int,
    request: Request,
    user: str = Depends(require_login),
):
    """更新规则元数据（备注、标签、收藏）"""
    node = get_node(node_id)
    if not node:
        return JSONResponse({"ok": False, "error": "节点不存在"}, status_code=404)
    
    try:
        payload = await request.json()
    except Exception:
        return JSONResponse({"ok": False, "error": "Invalid JSON"}, status_code=400)
    
    # 获取当前规则池
    desired_ver, pool = get_desired_pool(node_id)
    if not isinstance(pool, dict):
        rep = get_last_report(node_id)
        pool = rep.get("pool") if isinstance(rep, dict) else None
    
    if not isinstance(pool, dict):
        return JSONResponse({"ok": False, "error": "无法获取当前规则池"}, status_code=400)
    
    endpoints = pool.get("endpoints", [])
    if not isinstance(endpoints, list):
        return JSONResponse({"ok": False, "error": "规则列表无效"}, status_code=400)
    
    if rule_index < 0 or rule_index >= len(endpoints):
        return JSONResponse({"ok": False, "error": "规则索引无效"}, status_code=400)
    
    ep = endpoints[rule_index]
    
    # 更新元数据
    if "note" in payload:
        ep["note"] = str(payload["note"])[:500]  # 限制长度
    
    if "tags" in payload:
        tags = payload["tags"]
        if isinstance(tags, list):
            ep["tags"] = [str(t)[:50] for t in tags[:10]]  # 最多10个标签，每个最多50字符
        elif isinstance(tags, str):
            ep["tags"] = [t.strip()[:50] for t in tags.split(",") if t.strip()][:10]
    
    if "favorite" in payload:
        ep["favorite"] = bool(payload["favorite"])
    
    # 保存
    pool["endpoints"] = endpoints
    new_ver, _ = set_desired_pool(node_id, pool)
    
    return {
        "ok": True,
        "desired_version": new_ver,
        "rule": ep,
    }
