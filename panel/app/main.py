from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
import time
from typing import Any, Dict, List, Optional

import requests
from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from db import init_db, list_nodes, get_node, add_node, delete_node, save_pair, get_pair, purge_pairs

APP_VERSION = "18.0"

PANEL_USER = os.environ.get("PANEL_USER", "admin")
PANEL_PASS_HASH = os.environ.get("PANEL_PASS_HASH", "")
PANEL_SECRET = os.environ.get("PANEL_SECRET", "") or secrets.token_hex(32)

app = FastAPI(title="Realm Panel", version=APP_VERSION)
app.add_middleware(SessionMiddleware, secret_key=PANEL_SECRET, session_cookie="realm_panel", max_age=3600*24)

templates = Jinja2Templates(directory=os.path.join(os.path.dirname(__file__), "templates"))
app.mount("/static", StaticFiles(directory=os.path.join(os.path.dirname(__file__), "static")), name="static")


@app.on_event("startup")
def _startup() -> None:
    init_db()


def _is_authed(request: Request) -> bool:
    return bool(request.session.get("authed"))


def _require_auth(request: Request) -> None:
    if not _is_authed(request):
        raise HTTPException(status_code=401, detail="login required")


def _pbkdf2_verify(pw: str, stored: str) -> bool:
    """stored format: pbkdf2_sha256$ITER$SALT$HASH"""
    try:
        algo, it_s, salt_b64, hash_b64 = stored.split("$", 3)
        if algo != "pbkdf2_sha256":
            return False
        it = int(it_s)
        salt = base64.urlsafe_b64decode(salt_b64 + "==")
        got = hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"), salt, it)
        got_b64 = base64.urlsafe_b64encode(got).decode("utf-8").rstrip("=")
        return hmac.compare_digest(got_b64, hash_b64)
    except Exception:
        return False


def _agent_request(node: Dict[str, Any], method: str, path: str, json_body: Optional[Dict[str, Any]] = None, params: Optional[Dict[str, Any]] = None) -> requests.Response:
    base = str(node["base_url"]).rstrip("/")
    url = base + path
    headers = {"Authorization": f"Bearer {node['token']}"}
    return requests.request(method, url, headers=headers, json=json_body, params=params, timeout=5)


def _safe_json(resp: requests.Response) -> Dict[str, Any]:
    try:
        return resp.json()
    except Exception:
        return {"ok": False, "error": resp.text}


@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    if not _is_authed(request):
        return RedirectResponse("/login", status_code=302)
    return templates.TemplateResponse("index.html", {"request": request, "version": APP_VERSION})


@app.get("/login", response_class=HTMLResponse)
def login_get(request: Request):
    return templates.TemplateResponse("login.html", {"request": request, "version": APP_VERSION, "error": None})


@app.post("/login", response_class=HTMLResponse)
def login_post(request: Request, username: str = Form(...), password: str = Form(...)):
    ok_user = (username or "").strip() == PANEL_USER
    ok_pass = _pbkdf2_verify(password or "", PANEL_PASS_HASH)
    if ok_user and ok_pass:
        request.session["authed"] = True
        return RedirectResponse("/", status_code=302)
    return templates.TemplateResponse("login.html", {"request": request, "version": APP_VERSION, "error": "用户名或密码错误"})


@app.get("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login", status_code=302)


@app.get("/node/{node_id}", response_class=HTMLResponse)
def node_page(request: Request, node_id: int):
    if not _is_authed(request):
        return RedirectResponse("/login", status_code=302)
    node = get_node(node_id)
    if not node:
        return RedirectResponse("/", status_code=302)
    return templates.TemplateResponse("node.html", {"request": request, "node": node, "version": APP_VERSION})


# -------- Panel API (for front-end) --------

@app.get("/api/nodes")
def api_nodes(request: Request):
    _require_auth(request)
    purge_pairs()
    nodes = list_nodes()
    out = []
    for n in nodes:
        st = {"ok": False, "realm_running": False}
        try:
            resp = _agent_request(n, "GET", "/api/status")
            if resp.status_code == 200:
                st = _safe_json(resp)
        except Exception:
            st = {"ok": False}
        out.append({"node": n, "status": st})
    return {"ok": True, "nodes": out}


@app.post("/api/nodes/add")
def api_nodes_add(request: Request, name: str = Form(...), base_url: str = Form(...), token: str = Form(...)):
    _require_auth(request)
    nid = add_node(name, base_url, token)
    return RedirectResponse(f"/node/{nid}", status_code=302)


@app.post("/api/nodes/{node_id}/delete")
def api_nodes_delete(request: Request, node_id: int):
    _require_auth(request)
    delete_node(node_id)
    return RedirectResponse("/", status_code=302)


@app.get("/api/node/{node_id}/rules")
def api_node_rules(request: Request, node_id: int):
    _require_auth(request)
    node = get_node(node_id)
    if not node:
        raise HTTPException(404)
    resp = _agent_request(node, "GET", "/api/rules")
    return JSONResponse(status_code=resp.status_code, content=_safe_json(resp))


@app.get("/api/node/{node_id}/status")
def api_node_status(request: Request, node_id: int):
    _require_auth(request)
    node = get_node(node_id)
    if not node:
        raise HTTPException(404)
    resp = _agent_request(node, "GET", "/api/status")
    return JSONResponse(status_code=resp.status_code, content=_safe_json(resp))


@app.get("/api/node/{node_id}/health")
def api_node_health(request: Request, node_id: int):
    _require_auth(request)
    node = get_node(node_id)
    if not node:
        raise HTTPException(404)
    resp = _agent_request(node, "GET", "/api/health")
    return JSONResponse(status_code=resp.status_code, content=_safe_json(resp))


@app.get("/api/node/{node_id}/logs")
def api_node_logs(request: Request, node_id: int, lines: int = 200):
    _require_auth(request)
    node = get_node(node_id)
    if not node:
        raise HTTPException(404)
    resp = _agent_request(node, "GET", "/api/logs", params={"lines": lines})
    return JSONResponse(status_code=resp.status_code, content=_safe_json(resp))


@app.post("/api/node/{node_id}/apply")
def api_node_apply(request: Request, node_id: int):
    _require_auth(request)
    node = get_node(node_id)
    if not node:
        raise HTTPException(404)
    resp = _agent_request(node, "POST", "/api/apply")
    return JSONResponse(status_code=resp.status_code, content=_safe_json(resp))


@app.post("/api/node/{node_id}/rule")
def api_node_add_rule(
    request: Request,
    node_id: int,
    local_port: int = Form(...),
    protocol: str = Form("tcp+udp"),
    mode: str = Form("tcp_udp"),
    algo: str = Form("round_robin"),
    targets_text: str = Form(""),
    wss_host: str = Form(""),
    wss_path: str = Form(""),
    wss_sni: str = Form(""),
    wss_insecure: str = Form(""),
    wss_cert: str = Form(""),
    wss_key: str = Form(""),
    pair_code: str = Form(""),
):
    _require_auth(request)
    node = get_node(node_id)
    if not node:
        raise HTTPException(404)

    targets = [ln.strip() for ln in (targets_text or "").splitlines() if ln.strip()]

    # Pair code used by WSS send side to auto-fill parameters
    if pair_code and mode == "wss_send":
        payload = get_pair(pair_code)
        if not payload:
            raise HTTPException(status_code=400, detail="配对码无效或已过期")
        wss_host = payload.get("host", "")
        wss_path = payload.get("path", "")
        wss_sni = payload.get("sni", "")
        wss_insecure = "1" if payload.get("insecure") else ""

    body = {
        "local_port": int(local_port),
        "protocol": protocol,
        "mode": mode,
        "algo": algo,
        "targets": targets,
        "wss_host": wss_host or None,
        "wss_path": wss_path or None,
        "wss_sni": wss_sni or None,
        "wss_insecure": bool(wss_insecure),
        "wss_cert": wss_cert or None,
        "wss_key": wss_key or None,
    }

    resp = _agent_request(node, "POST", "/api/rules", json_body=body)
    data = _safe_json(resp)

    # If WSS receive side: generate pair code for sender to auto-fill
    pairing: Optional[str] = None
    if resp.status_code == 200 and mode == "wss_recv":
        try:
            st = _safe_json(_agent_request(node, "GET", "/api/status"))
            public_host = st.get("public_host") or node["base_url"].split("://")[-1].split(":")[0]
        except Exception:
            public_host = node["base_url"].split("://")[-1].split(":")[0]

        # short human-friendly code
        pairing = secrets.token_urlsafe(8).replace("-", "").replace("_", "")[:10]
        save_pair(
            pairing,
            {
                "host": public_host,
                "path": (wss_path or "/ws"),
                "sni": (wss_sni or public_host),
                "insecure": bool(wss_insecure),
                "created": int(time.time()),
                "note": f"node:{node_id} port:{local_port}",
            },
            ttl_sec=6 * 3600,
        )

    return JSONResponse(status_code=resp.status_code, content={"agent": data, "pairing_code": pairing})


@app.post("/api/node/{node_id}/rule/{rid}/pause")
def api_node_pause_rule(request: Request, node_id: int, rid: str, paused: bool = True):
    _require_auth(request)
    node = get_node(node_id)
    if not node:
        raise HTTPException(404)
    resp = _agent_request(node, "POST", f"/api/rules/{rid}/pause", params={"paused": str(paused).lower()})
    return JSONResponse(status_code=resp.status_code, content=_safe_json(resp))


@app.delete("/api/node/{node_id}/rule/{rid}")
def api_node_delete_rule(request: Request, node_id: int, rid: str):
    _require_auth(request)
    node = get_node(node_id)
    if not node:
        raise HTTPException(404)
    resp = _agent_request(node, "DELETE", f"/api/rules/{rid}")
    return JSONResponse(status_code=resp.status_code, content=_safe_json(resp))
