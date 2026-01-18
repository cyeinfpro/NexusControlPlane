from __future__ import annotations

import os
import sqlite3
import time
from typing import Any, Dict, List, Optional


def _db_path() -> str:
    # default: /opt/realm-panel/data/panel.db (systemd sets DB_PATH)
    return os.environ.get(
        "DB_PATH",
        os.path.join(os.path.dirname(__file__), "..", "data", "panel.db"),
    )


def _connect() -> sqlite3.Connection:
    path = os.path.abspath(_db_path())
    os.makedirs(os.path.dirname(path), exist_ok=True)
    conn = sqlite3.connect(path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    conn = _connect()
    cur = conn.cursor()

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS nodes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            base_url TEXT NOT NULL,
            token TEXT NOT NULL,
            created_at INTEGER NOT NULL
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS pairs (
            code TEXT PRIMARY KEY,
            host TEXT NOT NULL,
            path TEXT NOT NULL,
            sni TEXT NOT NULL,
            insecure TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL
        )
        """
    )

    conn.commit()
    conn.close()


def list_nodes() -> List[Dict[str, Any]]:
    conn = _connect()
    cur = conn.cursor()
    cur.execute("SELECT id, name, base_url, token, created_at FROM nodes ORDER BY id DESC")
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


def get_node(node_id: int) -> Optional[Dict[str, Any]]:
    conn = _connect()
    cur = conn.cursor()
    cur.execute(
        "SELECT id, name, base_url, token, created_at FROM nodes WHERE id = ?",
        (node_id,),
    )
    r = cur.fetchone()
    conn.close()
    return dict(r) if r else None


def add_node(name: str, base_url: str, token: str) -> int:
    conn = _connect()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO nodes (name, base_url, token, created_at) VALUES (?, ?, ?, ?)",
        (name, base_url, token, int(time.time())),
    )
    conn.commit()
    node_id = int(cur.lastrowid)
    conn.close()
    return node_id


def delete_node(node_id: int) -> None:
    conn = _connect()
    cur = conn.cursor()
    cur.execute("DELETE FROM nodes WHERE id = ?", (node_id,))
    conn.commit()
    conn.close()


def save_pair(code: str, host: str, path: str, sni: str, insecure: str, ttl_seconds: int = 24 * 3600) -> None:
    now = int(time.time())
    expires_at = now + ttl_seconds
    conn = _connect()
    cur = conn.cursor()
    cur.execute(
        "INSERT OR REPLACE INTO pairs (code, host, path, sni, insecure, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (code, host, path, sni, insecure, now, expires_at),
    )
    conn.commit()
    conn.close()


def get_pair(code: str) -> Optional[Dict[str, Any]]:
    conn = _connect()
    cur = conn.cursor()
    cur.execute(
        "SELECT code, host, path, sni, insecure, created_at, expires_at FROM pairs WHERE code = ?",
        (code,),
    )
    r = cur.fetchone()
    conn.close()
    if not r:
        return None
    row = dict(r)
    # hide timestamps for UI consumption
    return {
        "code": row["code"],
        "host": row["host"],
        "path": row["path"],
        "sni": row["sni"],
        "insecure": row["insecure"],
    }


def purge_pairs() -> None:
    now = int(time.time())
    conn = _connect()
    cur = conn.cursor()
    cur.execute("DELETE FROM pairs WHERE expires_at < ?", (now,))
    conn.commit()
    conn.close()
