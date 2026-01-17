from __future__ import annotations

import os
import time
import uuid
from typing import Any, Dict, Optional

import httpx
from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from .db import (
    consume_wss_pair,
    create_wss_pair,
    delete_agent,
    get_agent,
    list_agents,
    now,
    update_last_seen,
    upsert_agent,
)

APP_TITLE = "Realm Pro Panel"
APP_VERSION = "15.0"

app = FastAPI(title=APP_TITLE, version=APP_VERSION)

BASE_DIR = os.path.dirname(__file__)
TEMPLATES = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))
app.mount(
    "/static",
    StaticFiles(directory=os.path.join(BASE_DIR, "static")),
    name="static",
)


def _normalize_api_url(api_url: str) -> str:
    api_url = api_url.strip().rstrip("/")
    if not api_url:
        raise ValueError("api_url empty")
    if not (api_url.startswith("http://") or api_url.startswith("https://")):
        api_url = "http://" + api_url
    return api_url


def _agent_client(agent: Dict[str, Any]) -> httpx.AsyncClient:
    verify = bool(int(agent.get("verify_tls", 0)))
    headers = {"Authorization": f"Bearer {agent['token']}"}
    return httpx.AsyncClient(timeout=10.0, verify=verify, headers=headers)


async def _agent_get(agent: Dict[str, Any], path: str) -> Dict[str, Any]:
    url = agent["api_url"].rstrip("/") + path
    async with _agent_client(agent) as client:
        r = await client.get(url)
        r.raise_for_status()
        return r.json()


async def _agent_post(agent: Dict[str, Any], path: str, json_data: Dict[str, Any]) -> Dict[str, Any]:
    url = agent["api_url"].rstrip("/") + path
    async with _agent_client(agent) as client:
        r = await client.post(url, json=json_data)
        r.raise_for_status()
        return r.json()


async def _agent_put(agent: Dict[str, Any], path: str, json_data: Dict[str, Any]) -> Dict[str, Any]:
    url = agent["api_url"].rstrip("/") + path
    async with _agent_client(agent) as client:
        r = await client.put(url, json=json_data)
        r.raise_for_status()
        return r.json()


async def _agent_delete(agent: Dict[str, Any], path: str) -> Dict[str, Any]:
    url = agent["api_url"].rstrip("/") + path
    async with _agent_client(agent) as client:
        r = await client.delete(url)
        r.raise_for_status()
        return r.json()


def _human_ts(ts: int) -> str:
    if not ts:
        return "-"
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    agents = list_agents()
    # Show recent activity only; status fetched on the client side.
    for a in agents:
        a["added_at_h"] = _human_ts(int(a.get("added_at", 0)))
        a["last_seen_h"] = _human_ts(int(a.get("last_seen", 0)))
    return TEMPLATES.TemplateResponse(
        "index.html",
        {
            "request": request,
            "agents": agents,
            "version": APP_VERSION,
        },
    )


@app.post("/agents/add")
async def add_agent(
    request: Request,
    name: str = Form(...),
    api_url: str = Form(...),
    token: str = Form(...),
    verify_tls: Optional[str] = Form(None),
):
    try:
        api_url_n = _normalize_api_url(api_url)
    except Exception:
        return RedirectResponse(url="/?err=bad_api_url", status_code=302)

    name = name.strip() or "Agent"
    token = token.strip()
    if not token:
        return RedirectResponse(url="/?err=missing_token", status_code=302)

    agent_id = str(uuid.uuid4())
    upsert_agent(agent_id, name, api_url_n, token, verify_tls=bool(verify_tls))
    return RedirectResponse(url=f"/agents/{agent_id}", status_code=302)


@app.get("/agents/{agent_id}", response_class=HTMLResponse)
async def agent_detail(request: Request, agent_id: str):
    agent = get_agent(agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="agent not found")

    # Load quick snapshots server-side so the page is usable even if JS fails
    rules = []
    status = None
    err = ""
    try:
        rules = await _agent_get(agent, "/api/rules")
        status = await _agent_get(agent, "/api/service")
        update_last_seen(agent_id, now())
    except Exception as e:
        err = str(e)

    return TEMPLATES.TemplateResponse(
        "agent.html",
        {
            "request": request,
            "agent": agent,
            "rules": rules,
            "status": status,
            "err": err,
            "version": APP_VERSION,
        },
    )


@app.post("/agents/{agent_id}/delete")
async def agent_delete(agent_id: str):
    delete_agent(agent_id)
    return RedirectResponse(url="/", status_code=302)


# -----------------------------
# Panel API: proxy to Agent
# -----------------------------

@app.get("/api/agents")
async def api_agents():
    return {"agents": list_agents(), "ts": int(time.time())}


@app.get("/api/agents/{agent_id}/service")
async def api_agent_service(agent_id: str):
    agent = get_agent(agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="agent not found")
    try:
        data = await _agent_get(agent, "/api/service")
        update_last_seen(agent_id, now())
        return data
    except Exception as e:
        raise HTTPException(status_code=502, detail=str(e))


@app.get("/api/agents/{agent_id}/rules")
async def api_agent_rules(agent_id: str):
    agent = get_agent(agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="agent not found")
    try:
        data = await _agent_get(agent, "/api/rules")
        update_last_seen(agent_id, now())
        return {"rules": data}
    except Exception as e:
        raise HTTPException(status_code=502, detail=str(e))


@app.post("/api/agents/{agent_id}/rules")
async def api_agent_add_rule(agent_id: str, payload: Dict[str, Any]):
    """Add a rule.

    WSS pairing rules:
    - If payload['type'] == 'wss_server': generate + store pairing code, return it.
    - If payload['type'] == 'wss_client' and payload contains 'wss_pair_code': auto fill wss params.
    """
    agent = get_agent(agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="agent not found")

    try:
        rule_type = (payload.get("type") or "tcp_udp").strip()

        # If client uses pairing code, pull params from db
        if rule_type == "wss_client":
            pair_code = (payload.get("wss_pair_code") or "").strip()
            if pair_code:
                pair = consume_wss_pair(pair_code, mark_used=True)
                if not pair:
                    raise HTTPException(status_code=400, detail="对接码无效/已过期/已使用")
                payload["wss_host"] = pair["wss_host"]
                payload["wss_path"] = pair["wss_path"]
                payload["wss_sni"] = pair["wss_sni"]
                payload["wss_insecure"] = bool(pair.get("wss_insecure", True))

        # Actually create on agent
        rule = await _agent_post(agent, "/api/rules", payload)
        update_last_seen(agent_id, now())

        # If server side, create pairing code for the other side
        pair_code_out = ""
        if rule_type == "wss_server":
            wss_host = (payload.get("wss_host") or "www.bing.com").strip() or "www.bing.com"
            wss_path = (payload.get("wss_path") or "/ws").strip() or "/ws"
            # Client SNI default to host
            wss_sni = (payload.get("wss_sni") or wss_host).strip() or wss_host
            # For self-signed default, client usually needs insecure.
            wss_insecure = bool(payload.get("wss_insecure", True))
            pair = create_wss_pair(
                wss_host=wss_host,
                wss_path=wss_path,
                wss_sni=wss_sni,
                wss_insecure=wss_insecure,
                created_by_agent_id=str(agent_id),
            )
            pair_code_out = pair["code"]

        return {"rule": rule, "pair_code": pair_code_out}

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=502, detail=str(e))


@app.put("/api/agents/{agent_id}/rules/{rule_id}")
async def api_agent_update_rule(agent_id: str, rule_id: str, payload: Dict[str, Any]):
    agent = get_agent(agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="agent not found")
    try:
        data = await _agent_put(agent, f"/api/rules/{rule_id}", payload)
        update_last_seen(agent_id, now())
        return {"rule": data}
    except Exception as e:
        raise HTTPException(status_code=502, detail=str(e))


@app.post("/api/agents/{agent_id}/rules/{rule_id}/toggle")
async def api_agent_toggle_rule(agent_id: str, rule_id: str, payload: Dict[str, Any]):
    agent = get_agent(agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="agent not found")
    try:
        data = await _agent_post(agent, f"/api/rules/{rule_id}/toggle", payload)
        update_last_seen(agent_id, now())
        return {"rule": data}
    except Exception as e:
        raise HTTPException(status_code=502, detail=str(e))


@app.delete("/api/agents/{agent_id}/rules/{rule_id}")
async def api_agent_delete_rule(agent_id: str, rule_id: str):
    agent = get_agent(agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="agent not found")
    try:
        data = await _agent_delete(agent, f"/api/rules/{rule_id}")
        update_last_seen(agent_id, now())
        return data
    except Exception as e:
        raise HTTPException(status_code=502, detail=str(e))


@app.post("/api/agents/{agent_id}/apply")
async def api_agent_apply(agent_id: str):
    agent = get_agent(agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="agent not found")
    try:
        data = await _agent_post(agent, "/api/apply", {})
        update_last_seen(agent_id, now())
        return data
    except Exception as e:
        raise HTTPException(status_code=502, detail=str(e))


@app.get("/health")
async def health():
    return {"ok": True, "version": APP_VERSION, "ts": int(time.time())}


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    # Never lock the UI in a blank screen
    return JSONResponse(status_code=500, content={"detail": str(exc)})
