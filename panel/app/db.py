from __future__ import annotations

import json
import os
import sqlite3
import time
from typing import Any, Dict, List, Optional, Tuple

DB_PATH = os.environ.get("REALM_PANEL_DB", "/opt/realm-panel/data/panel.db")


def _ensure_dir() -> None:
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)


def conn() -> sqlite3.Connection:
    _ensure_dir()
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    return c


def init_db() -> None:
    with conn() as c:
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS nodes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                base_url TEXT NOT NULL,
                token TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );
            """
        )
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS wss_pairs (
                code TEXT PRIMARY KEY,
                payload TEXT NOT NULL,
                expires_at INTEGER NOT NULL
            );
            """
        )


def list_nodes() -> List[Dict[str, Any]]:
    with conn() as c:
        cur = c.execute("SELECT * FROM nodes ORDER BY id DESC")
        return [dict(r) for r in cur.fetchall()]


def get_node(node_id: int) -> Optional[Dict[str, Any]]:
    with conn() as c:
        cur = c.execute("SELECT * FROM nodes WHERE id=?", (node_id,))
        row = cur.fetchone()
        return dict(row) if row else None


def add_node(name: str, base_url: str, token: str) -> int:
    with conn() as c:
        cur = c.execute(
            "INSERT INTO nodes (name, base_url, token, created_at) VALUES (?, ?, ?, ?)",
            (name.strip(), base_url.rstrip("/"), token.strip(), int(time.time())),
        )
        return int(cur.lastrowid)


def delete_node(node_id: int) -> None:
    with conn() as c:
        c.execute("DELETE FROM nodes WHERE id=?", (node_id,))


def save_pair(code: str, payload: Dict[str, Any], ttl_sec: int = 3600) -> None:
    expires_at = int(time.time()) + int(ttl_sec)
    with conn() as c:
        c.execute(
            "INSERT OR REPLACE INTO wss_pairs (code, payload, expires_at) VALUES (?, ?, ?)",
            (code, json.dumps(payload, ensure_ascii=False), expires_at),
        )


def get_pair(code: str) -> Optional[Dict[str, Any]]:
    now = int(time.time())
    with conn() as c:
        cur = c.execute("SELECT payload, expires_at FROM wss_pairs WHERE code=?", (code.strip(),))
        row = cur.fetchone()
        if not row:
            return None
        if int(row["expires_at"]) < now:
            c.execute("DELETE FROM wss_pairs WHERE code=?", (code.strip(),))
            return None
        try:
            return json.loads(row["payload"])
        except Exception:
            return None


def purge_pairs() -> None:
    now = int(time.time())
    with conn() as c:
        c.execute("DELETE FROM wss_pairs WHERE expires_at < ?", (now,))
