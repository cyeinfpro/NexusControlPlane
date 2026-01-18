from __future__ import annotations

import os
import secrets
from typing import Any, Dict, Optional

import httpx
from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware
from starlette.templating import Jinja2Templates

from .auth import verify_password
from .db import (
    init_db,
    list_nodes,
    get_node,
    add_node,
    delete_node,
    save_pair,
    get_pair,
    purge_pairs,
)

APP_NAME = "Realm Pro Panel"


def env(name: str, default: Optional[str] = None) -> str:
    val = os.environ.get(name)
    if val is None or val == "":
        if default is None:
            raise RuntimeError(f"Missing env: {name}")
        return default
    return val


def is_logged_in(request: Request) -> bool:
    return bool(request.session.get("authed"))


def require_login(request: Request):
    if not is_logged_in(request):
        raise HTTPException(status_code=401, detail="Not logged in")


def redirect_to_login(request: Request) -> RedirectResponse:
    return RedirectResponse(url="/login", status_code=302)


app = FastAPI(title=APP_NAME)

# session secret
SESSION_SECRET = os.environ.get("SESSION_SECRET") or secrets.token_hex(32)
app.add_middleware(SessionMiddleware, secret_key=SESSION_SECRET, https_only=False)

BASE_DIR = os.path.dirname(__file__)
TEMPLATES_DIR = os.path.join(BASE_DIR, "templates")
STATIC_DIR = os.path.join(BASE_DIR, "static")

app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

templates = Jinja2Templates(directory=TEMPLATES_DIR)

# init DB
init_db()


@app.get("/health")
def health() -> Dict[str, Any]:
    return {"ok": True}


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse(
        "login.html",
        {
            "request": request,
            "app_name": APP_NAME,
            "error": None,
        },
    )


@app.post("/login")
def login_submit(request: Request, username: str = Form(...), password: str = Form(...)):
    admin_user = env("ADMIN_USER", "admin")
    admin_hash = env("ADMIN_PASS_HASH")

    if username != admin_user or not verify_password(password, admin_hash):
        return templates.TemplateResponse(
            "login.html",
            {
                "request": request,
                "app_name": APP_NAME,
                "error": "用户名或密码错误",
            },
            status_code=401,
        )

    request.session["authed"] = True
    return RedirectResponse(url="/", status_code=302)


@app.get("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/login", status_code=302)


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    if not is_logged_in(request):
        return redirect_to_login(request)

    nodes = list_nodes()
    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "app_name": APP_NAME,
            "nodes": nodes,
        },
    )


# ------------------ Nodes API ------------------

@app.get("/api/nodes")
def api_nodes(request: Request):
    require_login(request)
    return {"nodes": list_nodes()}


@app.post("/api/nodes")
def api_add_node(
    request: Request,
    name: str = Form(...),
    base_url: str = Form(...),
    token: str = Form(...),
):
    require_login(request)
    nid = add_node(name=name.strip(), base_url=base_url.strip(), token=token.strip())
    return {"ok": True, "id": nid}


@app.delete("/api/nodes/{node_id}")
def api_delete_node(request: Request, node_id: int):
    require_login(request)
    delete_node(node_id)
    return {"ok": True}


@app.get("/nodes/{node_id}", response_class=HTMLResponse)
def node_detail(request: Request, node_id: int):
    if not is_logged_in(request):
        return redirect_to_login(request)

    node = get_node(node_id)
    if not node:
        raise HTTPException(404, "node not found")

    return templates.TemplateResponse(
        "node.html",
        {
            "request": request,
            "app_name": APP_NAME,
            "node": node,
        },
    )


async def agent_request(node: Dict[str, Any], method: str, path: str, json: Any = None) -> Any:
    url = node["base_url"].rstrip("/") + path
    headers = {"Authorization": f"Bearer {node['token']}"}
    timeout = httpx.Timeout(8.0)
    async with httpx.AsyncClient(timeout=timeout) as client:
        r = await client.request(method, url, headers=headers, json=json)
        if r.status_code == 401:
            raise HTTPException(502, "Agent auth failed")
        if r.status_code >= 400:
            raise HTTPException(502, f"Agent error: {r.text}")
        return r.json()


@app.get("/api/nodes/{node_id}/status")
async def api_node_status(request: Request, node_id: int):
    require_login(request)
    node = get_node(node_id)
    if not node:
        raise HTTPException(404, "node not found")
    data = await agent_request(node, "GET", "/api/status")
    return data


@app.get("/api/nodes/{node_id}/rules")
async def api_node_rules(request: Request, node_id: int):
    require_login(request)
    node = get_node(node_id)
    if not node:
        raise HTTPException(404, "node not found")
    data = await agent_request(node, "GET", "/api/rules")
    return data


@app.post("/api/nodes/{node_id}/rules")
async def api_node_add_rule(request: Request, node_id: int):
    require_login(request)
    node = get_node(node_id)
    if not node:
        raise HTTPException(404, "node not found")

    body = await request.json()
    data = await agent_request(node, "POST", "/api/rules", json=body)
    return data


@app.post("/api/nodes/{node_id}/apply")
async def api_node_apply(request: Request, node_id: int):
    require_login(request)
    node = get_node(node_id)
    if not node:
        raise HTTPException(404, "node not found")
    data = await agent_request(node, "POST", "/api/apply")
    return data


@app.post("/api/pairs/create")
def api_create_pair(request: Request):
    require_login(request)
    payload = request.query_params

    # Generate WSS parameters (receiver side)
    host = payload.get("host") or "www.bing.com"
    path = payload.get("path") or "/ws"
    sni = payload.get("sni") or host
    insecure = payload.get("insecure") or "0"

    code = secrets.token_urlsafe(8)
    save_pair(code=code, host=host, path=path, sni=sni, insecure=insecure)
    return {"ok": True, "code": code, "host": host, "path": path, "sni": sni, "insecure": insecure}


@app.get("/api/pairs/{code}")
def api_get_pair(request: Request, code: str):
    require_login(request)
    purge_pairs()
    pair = get_pair(code)
    if not pair:
        raise HTTPException(404, "pair not found")
    return {"ok": True, "pair": pair}


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    # JSON fallback
    if request.url.path.startswith("/api/"):
        return JSONResponse({"ok": False, "error": exc.detail}, status_code=exc.status_code)
    return templates.TemplateResponse(
        "error.html",
        {
            "request": request,
            "app_name": APP_NAME,
            "status": exc.status_code,
            "message": exc.detail,
        },
        status_code=exc.status_code,
    )
