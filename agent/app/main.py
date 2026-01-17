from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, Field

from config import load_config
from storage import load_rules, save_rules, new_rule_id, find_rule, now_ts
from realmctl import (
    build_realm_toml,
    write_realm_toml,
    systemctl_is_active,
    systemctl_restart,
    journal_tail,
    tcp_probe,
    parse_host_port,
    count_connections,
)

APP_VERSION = "18.0"

app = FastAPI(title="Realm Agent", version=APP_VERSION)


def _auth(request: Request) -> None:
    cfg = load_config()
    token = cfg.token
    got = request.headers.get("authorization", "")
    if got.lower().startswith("bearer "):
        got = got[7:].strip()
    else:
        got = request.headers.get("x-token", "").strip()
    if not token or got != token:
        raise HTTPException(status_code=401, detail="unauthorized")


class RuleIn(BaseModel):
    local_port: int = Field(..., ge=1, le=65535)
    protocol: str = Field(default="tcp+udp")  # tcp / udp / tcp+udp
    mode: str = Field(default="tcp_udp")      # tcp_udp / wss_send / wss_recv
    targets: List[str] = Field(default_factory=list)
    algo: str = Field(default="round_robin")

    wss_host: Optional[str] = None
    wss_path: Optional[str] = None
    wss_sni: Optional[str] = None
    wss_insecure: Optional[bool] = None

    wss_cert: Optional[str] = None
    wss_key: Optional[str] = None


class RuleOut(BaseModel):
    id: str
    local_port: int
    protocol: str
    mode: str
    targets: List[str]
    algo: str
    paused: bool
    created_at: int
    updated_at: int

    wss_host: Optional[str] = None
    wss_path: Optional[str] = None
    wss_sni: Optional[str] = None
    wss_insecure: Optional[bool] = None
    wss_cert: Optional[str] = None
    wss_key: Optional[str] = None


def _sanitize_targets(ts: List[str]) -> List[str]:
    out: List[str] = []
    for t in ts:
        t = str(t).strip()
        if not t:
            continue
        out.append(t)
    return out


@app.get("/api/ping")
def ping() -> Dict[str, Any]:
    # no auth
    return {"ok": True, "version": APP_VERSION}


@app.get("/api/status")
def status(request: Request) -> Dict[str, Any]:
    _auth(request)
    cfg = load_config()
    rules = load_rules()
    realm_running = systemctl_is_active(os.environ.get("REALM_SERVICE", "realm.service"))
    connections: Dict[int, int] = {}
    for r in rules:
        try:
            lp = int(r.get("local_port"))
            connections[lp] = count_connections(lp)
        except Exception:
            continue
    return {
        "ok": True,
        "agent_version": APP_VERSION,
        "public_host": cfg.public_host,
        "realm_running": realm_running,
        "rule_count": len(rules),
        "connections": connections,
    }


@app.get("/api/rules", response_model=List[RuleOut])
def list_rules(request: Request):
    _auth(request)
    return load_rules()


@app.post("/api/rules", response_model=RuleOut)
def add_rule(rule: RuleIn, request: Request):
    _auth(request)
    rules = load_rules()

    if any(int(r.get("local_port")) == rule.local_port for r in rules):
        raise HTTPException(status_code=400, detail="local_port already exists")

    rid = new_rule_id()
    now = now_ts()
    obj = {
        "id": rid,
        "local_port": int(rule.local_port),
        "protocol": str(rule.protocol),
        "mode": str(rule.mode),
        "targets": _sanitize_targets(rule.targets),
        "algo": str(rule.algo),
        "paused": False,
        "created_at": now,
        "updated_at": now,
        "wss_host": rule.wss_host,
        "wss_path": rule.wss_path,
        "wss_sni": rule.wss_sni,
        "wss_insecure": bool(rule.wss_insecure) if rule.wss_insecure is not None else False,
        "wss_cert": rule.wss_cert,
        "wss_key": rule.wss_key,
    }

    if obj["mode"] in ("wss_send", "wss_recv") and not obj["wss_path"]:
        obj["wss_path"] = "/ws"

    rules.append(obj)
    save_rules(rules)
    return obj


@app.put("/api/rules/{rid}", response_model=RuleOut)
def update_rule(rid: str, rule: RuleIn, request: Request):
    _auth(request)
    rules = load_rules()
    obj = find_rule(rules, rid)
    if not obj:
        raise HTTPException(status_code=404, detail="not found")

    # port conflict if changed
    if int(rule.local_port) != int(obj.get("local_port")):
        if any(int(r.get("local_port")) == int(rule.local_port) for r in rules):
            raise HTTPException(status_code=400, detail="local_port already exists")

    obj.update(
        {
            "local_port": int(rule.local_port),
            "protocol": str(rule.protocol),
            "mode": str(rule.mode),
            "targets": _sanitize_targets(rule.targets),
            "algo": str(rule.algo),
            "wss_host": rule.wss_host,
            "wss_path": rule.wss_path,
            "wss_sni": rule.wss_sni,
            "wss_insecure": bool(rule.wss_insecure) if rule.wss_insecure is not None else False,
            "wss_cert": rule.wss_cert,
            "wss_key": rule.wss_key,
            "updated_at": now_ts(),
        }
    )

    if obj["mode"] in ("wss_send", "wss_recv") and not obj.get("wss_path"):
        obj["wss_path"] = "/ws"

    save_rules(rules)
    return obj


@app.post("/api/rules/{rid}/pause")
def pause_rule(rid: str, request: Request, paused: bool = True, apply: bool = True):
    _auth(request)
    rules = load_rules()
    obj = find_rule(rules, rid)
    if not obj:
        raise HTTPException(status_code=404, detail="not found")
    obj["paused"] = bool(paused)
    obj["updated_at"] = now_ts()
    save_rules(rules)

    if apply:
        rules = load_rules()
        toml = build_realm_toml(rules)
        ok, msg = write_realm_toml(toml)
        if not ok:
            raise HTTPException(status_code=500, detail=msg)
        ok, msg = systemctl_restart(os.environ.get("REALM_SERVICE", "realm.service"))
        if not ok:
            raise HTTPException(status_code=500, detail=f"restart realm failed: {msg}")
    return {"ok": True, "paused": obj["paused"]}


@app.delete("/api/rules/{rid}")
def delete_rule(rid: str, request: Request, apply: bool = True):
    _auth(request)
    rules = load_rules()
    new_rules = [r for r in rules if str(r.get("id")) != rid]
    if len(new_rules) == len(rules):
        raise HTTPException(status_code=404, detail="not found")
    save_rules(new_rules)

    if apply:
        toml = build_realm_toml(new_rules)
        ok, msg = write_realm_toml(toml)
        if not ok:
            raise HTTPException(status_code=500, detail=msg)
        ok, msg = systemctl_restart(os.environ.get("REALM_SERVICE", "realm.service"))
        if not ok:
            raise HTTPException(status_code=500, detail=f"restart realm failed: {msg}")
    return {"ok": True}


@app.post("/api/apply")
def apply_rules(request: Request):
    _auth(request)
    rules = load_rules()
    toml = build_realm_toml(rules)
    ok, msg = write_realm_toml(toml)
    if not ok:
        raise HTTPException(status_code=500, detail=msg)

    ok, msg = systemctl_restart(os.environ.get("REALM_SERVICE", "realm.service"))
    if not ok:
        raise HTTPException(status_code=500, detail=f"restart realm failed: {msg}")
    return {"ok": True}


@app.get("/api/logs")
def logs(request: Request, lines: int = 200):
    _auth(request)
    lines = max(50, min(1000, int(lines)))
    return {"ok": True, "logs": journal_tail(os.environ.get("REALM_SERVICE", "realm.service"), lines=lines)}


@app.get("/api/health")
def health(request: Request):
    _auth(request)
    rules = load_rules()
    result = []
    for r in rules:
        targets = r.get("targets") or []
        items = []
        for t in targets:
            host, port = parse_host_port(str(t))
            if not port:
                items.append({"target": t, "ok": False})
                continue
            ok = tcp_probe(host, port, timeout=1.0)
            items.append({"target": t, "ok": ok})
        result.append({"id": r.get("id"), "local_port": r.get("local_port"), "targets": items})
    return {"ok": True, "health": result}
