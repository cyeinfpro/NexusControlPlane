from __future__ import annotations

import json
import os
from dataclasses import dataclass

CFG_DIR = os.environ.get("REALM_AGENT_ETC", "/etc/realm-agent")
CFG_PATH = os.path.join(CFG_DIR, "config.json")
RULES_PATH = os.path.join(CFG_DIR, "rules.json")


@dataclass
class AgentConfig:
    token: str
    public_host: str


def ensure_cfg_dir() -> None:
    os.makedirs(CFG_DIR, exist_ok=True)


def load_config() -> AgentConfig:
    ensure_cfg_dir()
    if not os.path.exists(CFG_PATH):
        raise FileNotFoundError(CFG_PATH)
    with open(CFG_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)
    return AgentConfig(token=str(data.get("token", "")), public_host=str(data.get("public_host", "")))


def save_config(token: str, public_host: str) -> None:
    ensure_cfg_dir()
    with open(CFG_PATH, "w", encoding="utf-8") as f:
        json.dump({"token": token, "public_host": public_host}, f, ensure_ascii=False, indent=2)
