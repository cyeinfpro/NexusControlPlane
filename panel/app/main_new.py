"""
Realm Pro Panel - Main Application

这是重构后的 main.py，将路由拆分为多个模块：
- routers/auth.py: 认证相关路由
- routers/nodes.py: 节点管理路由
- routers/stats.py: 统计监控路由

同时使用统一的服务层：
- services/agent_client.py: 统一的 Agent 通信客户端
- services/validators.py: 规则校验与规范化
"""

from __future__ import annotations

import asyncio
import json
import os
import time
import base64
import hmac
import hashlib
import secrets
import uuid
import io
import zipfile
from datetime import datetime
from urllib.parse import urlparse, urlencode
from pathlib import Path
from typing import Any, Dict, Optional, List

from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse, Response, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from .auth import ensure_secret_key, load_credentials, save_credentials, verify_login
from .db import (
    add_node,
    delete_node,
    ensure_db,
    get_group_orders,
    get_node,
    get_node_by_api_key,
    get_node_by_base_url,
    get_desired_pool,
    get_last_report,
    list_nodes,
    upsert_group_order,
    set_desired_pool,
    set_desired_pool_exact,
    set_desired_pool_version_exact,
    update_node_basic,
    update_node_report,
    set_agent_rollout_all,
    update_agent_status,

    # NetMon
    list_netmon_monitors,
    get_netmon_monitor,
    add_netmon_monitor,
    update_netmon_monitor,
    delete_netmon_monitor,
    list_netmon_samples,
    list_netmon_samples_range,
    list_netmon_samples_rollup,
    insert_netmon_samples,
    prune_netmon_samples,
    
    # Traffic History
    insert_traffic_history,
    list_traffic_history,
    list_traffic_history_rollup,
    prune_traffic_history,
)

# 使用新的统一服务
from .services import (
    agent_get,
    agent_post,
    agent_ping,
    validate_and_normalize,
    quick_validate,
    DEFAULT_AGENT_PORT,
)

# 路由在下方手动注册，避免循环导入

BASE_DIR = Path(__file__).resolve().parent.parent
TEMPLATES_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"


def _read_latest_agent_version() -> str:
    """Return latest agent version shipped with this panel."""
    zpath = STATIC_DIR / "realm-agent.zip"
    try:
        with zipfile.ZipFile(str(zpath), "r") as z:
            raw = z.read("agent/app/main.py").decode("utf-8", errors="ignore")
        import re
        m = re.search(r"FastAPI\([^\)]*version\s*=\s*['\"]([^'\"]+)['\"]", raw)
        if m:
            return str(m.group(1)).strip()
    except Exception:
        pass
    return ""


LATEST_AGENT_VERSION = _read_latest_agent_version()


def _parse_agent_version_from_ua(ua: str) -> str:
    try:
        import re
        m = re.search(r"realm-agent\/([0-9A-Za-z._-]+)", ua or "", re.I)
        return (m.group(1) if m else "")
    except Exception:
        return ""


def _ver_int(v: str) -> int:
    try:
        return int(str(v or '').strip())
    except Exception:
        return 0


def _file_sha256(p: Path) -> str:
    try:
        h = hashlib.sha256()
        with open(p, 'rb') as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b''):
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return ""


def _panel_asset_source() -> str:
    return (os.getenv("REALM_PANEL_ASSET_SOURCE") or "panel").strip().lower() or "panel"


def _agent_asset_urls(base_url: str) -> tuple[str, str, bool]:
    src = _panel_asset_source()
    if src == "github":
        sh_url = (os.getenv("REALM_PANEL_AGENT_SH_URL") or "").strip() or (
            "https://raw.githubusercontent.com/cyeinfpro/Realm/main/realm_agent.sh"
        )
        zip_url = (os.getenv("REALM_PANEL_AGENT_ZIP_URL") or "").strip() or (
            "https://github.com/cyeinfpro/Realm/archive/refs/heads/main.zip"
        )
        return sh_url, zip_url, True
    return f"{base_url}/static/realm_agent.sh", f"{base_url}/static/realm-agent.zip", False


def _panel_public_base_url(request: Request) -> str:
    cfg = (os.getenv("REALM_PANEL_PUBLIC_URL") or os.getenv("REALM_PANEL_URL") or "").strip()
    if cfg:
        cfg = cfg.rstrip('/')
        if '://' not in cfg:
            cfg = 'https://' + cfg
        return cfg
    return str(request.base_url).rstrip('/')


# ==================== 应用初始化 ====================

app = FastAPI(title="Realm Pro Panel", version="35")

# Session
secret = ensure_secret_key()
app.add_middleware(SessionMiddleware, secret_key=secret, session_cookie="realm_panel_sess")

# Static + templates
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

# DB init
ensure_db()


# ==================== 辅助函数 ====================

def _has_credentials() -> bool:
    return bool(load_credentials())


def _set_flash(request: Request, msg: str):
    request.session["flash"] = msg


def _flash(request: Request) -> str:
    return request.session.pop("flash", "")


def _generate_api_key(length: int = 32) -> str:
    return secrets.token_urlsafe(length)


def _extract_ip_for_display(base_url: str) -> str:
    try:
        if "://" not in base_url:
            base_url = f"http://{base_url}"
        parsed = urlparse(base_url)
        return parsed.hostname or base_url
    except Exception:
        return base_url


def _node_verify_tls(node: Dict[str, Any]) -> bool:
    return bool(node.get("verify_tls", False))


def _is_report_fresh(node: Dict[str, Any], max_age_sec: int = 60) -> bool:
    last_seen = node.get("last_seen_at")
    if not last_seen:
        return False
    try:
        dt = datetime.fromisoformat(last_seen.replace("Z", "+00:00"))
        age = (datetime.now(dt.tzinfo) - dt).total_seconds()
        return age < max_age_sec
    except Exception:
        return False


# ==================== 登录依赖 ====================

def require_login(request: Request) -> str:
    user = request.session.get("user")
    if not user:
        raise HTTPException(status_code=401, detail="Not logged in")
    return user


def require_login_page(request: Request) -> str:
    user = request.session.get("user")
    if not user:
        raise HTTPException(status_code=302, headers={"Location": "/login"})
    return user


# ==================== 认证路由 ====================

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    if not _has_credentials():
        return RedirectResponse(url="/setup", status_code=303)
    return templates.TemplateResponse(
        "login.html",
        {"request": request, "user": None, "flash": _flash(request), "title": "登录"},
    )


@app.post("/login")
async def login_action(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
):
    if not _has_credentials():
        _set_flash(request, "请先初始化面板账号")
        return RedirectResponse(url="/setup", status_code=303)
    if verify_login(username, password):
        request.session["user"] = username
        _set_flash(request, "登录成功")
        return RedirectResponse(url="/", status_code=303)
    _set_flash(request, "账号或密码错误")
    return RedirectResponse(url="/login", status_code=303)


@app.get("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/login", status_code=303)


@app.get("/setup", response_class=HTMLResponse)
async def setup_page(request: Request):
    if _has_credentials():
        return RedirectResponse(url="/login", status_code=303)
    return templates.TemplateResponse(
        "setup.html",
        {"request": request, "user": None, "flash": _flash(request), "title": "初始化账号"},
    )


@app.post("/setup")
async def setup_action(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    confirm: str = Form(...),
):
    if _has_credentials():
        return RedirectResponse(url="/login", status_code=303)
    if password != confirm:
        _set_flash(request, "两次输入的密码不一致")
        return RedirectResponse(url="/setup", status_code=303)
    try:
        save_credentials(username, password)
    except ValueError as exc:
        _set_flash(request, str(exc))
        return RedirectResponse(url="/setup", status_code=303)
    _set_flash(request, "账号已初始化，请登录")
    return RedirectResponse(url="/login", status_code=303)


# ==================== 主页面路由 ====================

@app.get("/", response_class=HTMLResponse)
async def index(request: Request, user: str = Depends(require_login_page)):
    nodes = list_nodes()
    group_orders = get_group_orders()

    def _gk(name: str) -> tuple[int, str]:
        n = (name or '').strip() or '默认分组'
        try:
            order = int(group_orders.get(n, 1000))
        except Exception:
            order = 1000
        return (order, n)

    def _gn(x: dict) -> str:
        g = str(x.get("group_name") or "").strip()
        return g or "默认分组"

    for n in nodes:
        n["display_ip"] = _extract_ip_for_display(n.get("base_url", ""))
        n["online"] = _is_report_fresh(n)
        n["group_name"] = _gn(n)
        if "agent_version" not in n:
            n["agent_version"] = str(n.get("agent_reported_version") or "").strip()

    nodes_sorted = sorted(
        nodes,
        key=lambda x: (
            _gk(_gn(x)),
            0 if bool(x.get("online")) else 1,
            -int(x.get("id") or 0),
        ),
    )

    dashboard_groups = []
    cur = None
    buf = []
    for n in nodes_sorted:
        g = _gn(n)
        if cur is None:
            cur = g
        if g != cur:
            dashboard_groups.append({
                "name": cur,
                "sort_order": _gk(cur)[0],
                "nodes": buf,
                "online": sum(1 for i in buf if i.get("online")),
                "total": len(buf),
            })
            cur = g
            buf = []
        buf.append(n)

    if cur is not None:
        dashboard_groups.append({
            "name": cur,
            "sort_order": _gk(cur)[0],
            "nodes": buf,
            "online": sum(1 for i in buf if i.get("online")),
            "total": len(buf),
        })

    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "user": (user or None),
            "nodes": nodes,
            "dashboard_groups": dashboard_groups,
            "flash": _flash(request),
            "title": "控制台",
        },
    )


@app.get("/nodes/new", response_class=HTMLResponse)
async def node_new_page(request: Request, user: str = Depends(require_login_page)):
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


@app.get("/nodes/{node_id}", response_class=HTMLResponse)
async def node_detail_page(request: Request, node_id: int, user: str = Depends(require_login_page)):
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


# ==================== 节点 API ====================

@app.get("/api/nodes")
async def api_list_nodes(user: str = Depends(require_login)):
    nodes = list_nodes()
    for n in nodes:
        n["display_ip"] = _extract_ip_for_display(n.get("base_url", ""))
        n["online"] = _is_report_fresh(n)
    return {"ok": True, "nodes": nodes}


@app.post("/api/nodes")
async def api_create_node(
    request: Request,
    user: str = Depends(require_login),
):
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
    
    existing = get_node_by_api_key(api_key) or get_node_by_base_url(base_url)
    if existing:
        return JSONResponse({"ok": False, "error": "节点已存在"}, status_code=400)
    
    if not name:
        name = _extract_ip_for_display(base_url)
    
    node_id = add_node(name, base_url, api_key, verify_tls=verify_tls, is_private=is_private, group_name=group_name)
    return {"ok": True, "node_id": node_id}


@app.get("/api/nodes/{node_id}")
async def api_get_node(node_id: int, user: str = Depends(require_login)):
    node = get_node(node_id)
    if not node:
        return JSONResponse({"ok": False, "error": "节点不存在"}, status_code=404)
    
    node["display_ip"] = _extract_ip_for_display(node.get("base_url", ""))
    node["online"] = _is_report_fresh(node)
    return {"ok": True, "node": node}


@app.delete("/api/nodes/{node_id}")
async def api_delete_node(node_id: int, user: str = Depends(require_login)):
    node = get_node(node_id)
    if not node:
        return JSONResponse({"ok": False, "error": "节点不存在"}, status_code=404)
    
    delete_node(node_id)
    return {"ok": True}


@app.get("/api/nodes/{node_id}/ping")
async def api_ping_node(node_id: int, user: str = Depends(require_login)):
    node = get_node(node_id)
    if not node:
        return JSONResponse({"ok": False, "error": "节点不存在"}, status_code=404)
    
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


@app.get("/api/nodes/{node_id}/pool")
async def api_get_pool(node_id: int, user: str = Depends(require_login)):
    node = get_node(node_id)
    if not node:
        return JSONResponse({"ok": False, "error": "节点不存在"}, status_code=404)
    
    desired_ver, desired_pool = get_desired_pool(node_id)
    if isinstance(desired_pool, dict):
        return {"ok": True, "pool": desired_pool, "desired_version": desired_ver, "source": "panel_desired"}
    
    rep = get_last_report(node_id)
    if isinstance(rep, dict) and isinstance(rep.get("pool"), dict):
        return {"ok": True, "pool": rep.get("pool"), "source": "report_cache"}
    
    try:
        data = await agent_get(node["base_url"], node["api_key"], "/api/v1/pool", _node_verify_tls(node))
        return data
    except Exception as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=502)


@app.post("/api/nodes/{node_id}/pool")
async def api_set_pool(
    node_id: int,
    request: Request,
    user: str = Depends(require_login),
):
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
    
    normalized_pool = validation.normalized_pool or pool
    desired_ver, _ = set_desired_pool(node_id, normalized_pool)
    
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


@app.post("/api/nodes/{node_id}/pool/validate")
async def api_validate_pool(
    node_id: int,
    request: Request,
    user: str = Depends(require_login),
):
    """校验规则池（不保存）"""
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


@app.post("/api/nodes/{node_id}/apply")
async def api_apply_node(node_id: int, user: str = Depends(require_login)):
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
        desired_ver, desired_pool = get_desired_pool(node_id)
        if isinstance(desired_pool, dict):
            new_ver, _ = set_desired_pool(node_id, desired_pool)
            return {"ok": True, "queued": True, "desired_version": new_ver}
        return {"ok": False, "error": "Agent 无法访问，且面板无缓存规则"}


@app.get("/api/nodes/{node_id}/stats")
async def api_get_stats(node_id: int, user: str = Depends(require_login)):
    node = get_node(node_id)
    if not node:
        return JSONResponse({"ok": False, "error": "节点不存在"}, status_code=404)
    
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

@app.post("/api/nodes/{node_id}/rules/batch")
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
    
    action = payload.get("action")
    indices = payload.get("indices", [])
    
    if not isinstance(indices, list) or not indices:
        return JSONResponse({"ok": False, "error": "indices 必须是非空数组"}, status_code=400)
    
    desired_ver, pool = get_desired_pool(node_id)
    if not isinstance(pool, dict):
        rep = get_last_report(node_id)
        pool = rep.get("pool") if isinstance(rep, dict) else None
    
    if not isinstance(pool, dict):
        return JSONResponse({"ok": False, "error": "无法获取当前规则池"}, status_code=400)
    
    endpoints = pool.get("endpoints", [])
    if not isinstance(endpoints, list):
        endpoints = []
    
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
        for idx in sorted(indices, reverse=True):
            if 0 <= idx < len(endpoints):
                endpoints.pop(idx)
                modified = True
    
    elif action == "copy":
        import copy
        for idx in indices:
            if 0 <= idx < len(endpoints):
                new_ep = copy.deepcopy(endpoints[idx])
                new_ep["disabled"] = True
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
    
    pool["endpoints"] = endpoints
    new_ver, _ = set_desired_pool(node_id, pool)
    
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


@app.post("/api/nodes/{node_id}/rules/{rule_index}/metadata")
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
    
    if "note" in payload:
        ep["note"] = str(payload["note"])[:500]
    
    if "tags" in payload:
        tags = payload["tags"]
        if isinstance(tags, list):
            ep["tags"] = [str(t)[:50] for t in tags[:10]]
        elif isinstance(tags, str):
            ep["tags"] = [t.strip()[:50] for t in tags.split(",") if t.strip()][:10]
    
    if "favorite" in payload:
        ep["favorite"] = bool(payload["favorite"])
    
    pool["endpoints"] = endpoints
    new_ver, _ = set_desired_pool(node_id, pool)
    
    return {
        "ok": True,
        "desired_version": new_ver,
        "rule": ep,
    }


# ==================== 流量历史 API ====================

@app.get("/api/nodes/{node_id}/traffic/history")
async def api_get_traffic_history(
    node_id: int,
    rule_idx: Optional[int] = None,
    since: Optional[int] = None,
    limit: int = 360,
    user: str = Depends(require_login),
):
    """获取流量历史数据"""
    node = get_node(node_id)
    if not node:
        return JSONResponse({"ok": False, "error": "节点不存在"}, status_code=404)
    
    history = list_traffic_history(
        node_id,
        rule_index=rule_idx,
        since_ts_ms=since or 0,
        limit=limit,
    )
    
    return {
        "ok": True,
        "node_id": node_id,
        "history": history,
        "ts": int(time.time() * 1000),
    }


@app.get("/api/nodes/{node_id}/traffic/rollup")
async def api_get_traffic_rollup(
    node_id: int,
    rule_idx: Optional[int] = None,
    since: Optional[int] = None,
    bucket: int = 60000,
    user: str = Depends(require_login),
):
    """获取聚合的流量历史数据"""
    node = get_node(node_id)
    if not node:
        return JSONResponse({"ok": False, "error": "节点不存在"}, status_code=404)
    
    history = list_traffic_history_rollup(
        node_id,
        rule_index=rule_idx,
        since_ts_ms=since or 0,
        bucket_ms=bucket,
    )
    
    return {
        "ok": True,
        "node_id": node_id,
        "data": history,  # Changed from 'history' to 'data' to match frontend
        "ts": int(time.time() * 1000),
    }


# ==================== 健康检查 ====================

@app.get("/health")
async def health():
    return {"ok": True, "ts": int(time.time() * 1000)}


@app.get("/api/version")
async def api_version():
    return {
        "ok": True,
        "panel_version": app.version,
        "agent_version": _read_latest_agent_version(),
    }


# 注意：原 main.py 中的其他路由（NetMon、Agent Report、备份恢复等）
# 可以继续添加到这里，或者进一步拆分到相应的 router 模块中
# 这里只展示了核心的重构部分
