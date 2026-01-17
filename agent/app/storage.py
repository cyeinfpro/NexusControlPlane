from __future__ import annotations

import json
import os
import time
import uuid
from typing import Any, Dict, List, Optional

from config import RULES_PATH, ensure_cfg_dir


def load_rules() -> List[Dict[str, Any]]:
    ensure_cfg_dir()
    if not os.path.exists(RULES_PATH):
        with open(RULES_PATH, "w", encoding="utf-8") as f:
            f.write("[]")
    with open(RULES_PATH, "r", encoding="utf-8") as f:
        try:
            data = json.load(f)
        except Exception:
            data = []
    if not isinstance(data, list):
        data = []
    return data


def save_rules(rules: List[Dict[str, Any]]) -> None:
    ensure_cfg_dir()
    with open(RULES_PATH, "w", encoding="utf-8") as f:
        json.dump(rules, f, ensure_ascii=False, indent=2)


def new_rule_id() -> str:
    return uuid.uuid4().hex[:12]


def find_rule(rules: List[Dict[str, Any]], rid: str) -> Optional[Dict[str, Any]]:
    for r in rules:
        if str(r.get("id")) == rid:
            return r
    return None


def now_ts() -> int:
    return int(time.time())
