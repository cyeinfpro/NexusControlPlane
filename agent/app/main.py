from __future__ import annotations

import json
import os
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import Depends, FastAPI, HTTPException, Request
from pydantic import BaseModel, Field

APP_NAME = "Realm Agent"

CONFIG_PATH = Path(os.environ.get("REALM_CONFIG", "/etc/realm/config.json"))


def _run(cmd: List[str]) -> str:
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    return (p.stdout or "").strip()


def _systemctl_show(service: str, prop: str) -> str:
    out = _run(["systemctl", "show", service, f"-p{prop}"])
    if "=" in out:
        return out.split("=", 1)[1].strip()
    return ""


def _systemctl_is_active(service: str) -> bool:
    return _run(["systemctl", "is-active", service]) == "active"


def _count_tcp_connections(port: int) -> int:
    # Count ESTAB connections with destination port = port
    # Works on Debian12 with iproute2
    try:
        out = _run(["bash", "-lc", f"ss -Hnt state established sport = :{port} 2>/dev/null | wc -l"])
        return int(out.strip() or 0)
    except Exception:
        return 0


def _ensure_config() -> Dict[str, Any]:
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    if not CONFIG_PATH.exists():
        base = {
            "log": {"level": "off", "output": "stdout"},
            "dns": {"mode": "ipv4_and_ipv6", "protocol": "tcp+udp", "min-ttl": 0, "max-ttl": 86400, "cache-size": 32},
            "endpoints": [],
        }
        CONFIG_PATH.write_text(json.dumps(base, ensure_ascii=False, indent=2), encoding="utf-8")
    try:
        return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except Exception:
        raise HTTPException(status_code=500, detail=f"Invalid JSON: {CONFIG_PATH}")


def _save_config(cfg: Dict[str, Any]) -> None:
    CONFIG_PATH.write_text(json.dumps(cfg, ensure_ascii=False, indent=2), encoding="utf-8")


def _token_required(request: Request) -> None:
    token = os.environ.get("AGENT_TOKEN", "").strip()
    if not token:
        return
    auth = request.headers.get("authorization", "")
    if not auth.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing Bearer token")
    got = auth.split(" ", 1)[1].strip()
    if got != token:
        raise HTTPException(status_code=403, detail="Invalid token")


def auth_dep(request: Request) -> None:
    _token_required(request)


class RuleCreate(BaseModel):
    name: str = Field(default="rule")
    listen_port: int = Field(ge=1, le=65535)
    targets: List[str] = Field(default_factory=list)
    balance: str = Field(default="round_robin")  # round_robin | ip_hash


app = FastAPI(title=APP_NAME)


@app.get("/health")
def health() -> Dict[str, Any]:
    return {"ok": True, "app": APP_NAME, "ts": int(time.time())}


@app.get("/status", dependencies=[Depends(auth_dep)])
def status() -> Dict[str, Any]:
    cfg = _ensure_config()
    endpoints = cfg.get("endpoints", []) or []

    ports: List[Dict[str, Any]] = []
    for ep in endpoints:
        listen = str(ep.get("listen", ""))
        # expected: 0.0.0.0:PORT
        port = None
        if ":" in listen:
            try:
                port = int(listen.rsplit(":", 1)[1])
            except Exception:
                port = None
        if port:
            ports.append({"listen": listen, "connections": _count_tcp_connections(port)})

    return {
        "realm_service_active": _systemctl_is_active("realm.service"),
        "realm_service_substate": _systemctl_show("realm.service", "SubState"),
        "endpoints": len(endpoints),
        "ports": ports,
        "config_path": str(CONFIG_PATH),
        "config_mtime": int(CONFIG_PATH.stat().st_mtime) if CONFIG_PATH.exists() else 0,
        "ts": int(time.time()),
    }


@app.get("/rules", dependencies=[Depends(auth_dep)])
def list_rules() -> Dict[str, Any]:
    cfg = _ensure_config()
    endpoints = cfg.get("endpoints", []) or []

    rules: List[Dict[str, Any]] = []
    for idx, ep in enumerate(endpoints):
        listen = str(ep.get("listen", ""))
        remote = ep.get("remote")
        extra = ep.get("extra_remotes") or []
        targets = []
        if remote:
            targets.append(str(remote))
        targets.extend([str(x) for x in extra])
        rules.append(
            {
                "id": idx,
                "listen": listen,
                "targets": targets,
                "balance": ep.get("balance", ""),
                "raw": ep,
            }
        )

    return {"rules": rules}


@app.post("/rules", dependencies=[Depends(auth_dep)])
def add_rule(payload: RuleCreate) -> Dict[str, Any]:
    if not payload.targets:
        raise HTTPException(status_code=400, detail="targets cannot be empty")

    cfg = _ensure_config()
    endpoints = cfg.get("endpoints", []) or []

    listen = f"0.0.0.0:{payload.listen_port}"
    remote = payload.targets[0]
    extra = payload.targets[1:]

    # realm balance format example: "roundrobin: 1,1,1"
    w = ",".join(["1"] * len(payload.targets))
    algo = "roundrobin" if payload.balance.lower() in ("round_robin", "roundrobin") else "iphash"
    balance = f"{algo}: {w}"

    endpoints.append(
        {
            "listen": listen,
            "remote": remote,
            "extra_remotes": extra,
            "balance": balance,
        }
    )

    cfg["endpoints"] = endpoints
    _save_config(cfg)
    return {"ok": True, "count": len(endpoints)}


@app.delete("/rules/{rule_id}", dependencies=[Depends(auth_dep)])
def delete_rule(rule_id: int) -> Dict[str, Any]:
    cfg = _ensure_config()
    endpoints = cfg.get("endpoints", []) or []
    if rule_id < 0 or rule_id >= len(endpoints):
        raise HTTPException(status_code=404, detail="rule not found")
    endpoints.pop(rule_id)
    cfg["endpoints"] = endpoints
    _save_config(cfg)
    return {"ok": True, "count": len(endpoints)}


@app.post("/apply", dependencies=[Depends(auth_dep)])
def apply() -> Dict[str, Any]:
    out = _run(["systemctl", "restart", "realm.service"])
    active = _systemctl_is_active("realm.service")
    return {"ok": active, "restart_output": out}
