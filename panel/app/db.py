from __future__ import annotations

import os
import sqlite3
import time
from typing import Any, Dict, List, Optional

DB_PATH = os.getenv("REALM_PANEL_DB", "/etc/realm-panel/panel.db")


def _connect() -> sqlite3.Connection:
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def now() -> int:
    return int(time.time())


def init_db() -> None:
    """Create tables if they don't exist.

    This function is idempotent and safe to call frequently.
    """
    with _connect() as conn:
        c = conn.cursor()

        c.execute(
            """
            CREATE TABLE IF NOT EXISTS agents (
              id TEXT PRIMARY KEY,
              name TEXT NOT NULL,
              api_url TEXT NOT NULL,
              token TEXT NOT NULL,
              verify_tls INTEGER NOT NULL DEFAULT 0,
              added_at INTEGER NOT NULL,
              last_seen INTEGER NOT NULL DEFAULT 0
            );
            """
        )

        c.execute(
            """
            CREATE TABLE IF NOT EXISTS wss_pairs (
              code TEXT PRIMARY KEY,
              created_at INTEGER NOT NULL,
              expires_at INTEGER NOT NULL,
              used INTEGER NOT NULL DEFAULT 0,
              created_by_agent_id TEXT,
              wss_host TEXT NOT NULL,
              wss_path TEXT NOT NULL,
              wss_sni TEXT NOT NULL,
              wss_insecure INTEGER NOT NULL DEFAULT 1
            );
            """
        )

        # Migration helper: older v14 table name
        try:
            c.execute("DROP TABLE IF EXISTS pair_codes")
        except Exception:
            pass

        conn.commit()


def upsert_agent(agent_id: str, name: str, api_url: str, token: str, verify_tls: bool = False) -> None:
    init_db()
    with _connect() as conn:
        conn.execute(
            """
            INSERT INTO agents(id, name, api_url, token, verify_tls, added_at, last_seen)
            VALUES(?,?,?,?,?,?,?)
            ON CONFLICT(id) DO UPDATE SET
              name=excluded.name,
              api_url=excluded.api_url,
              token=excluded.token,
              verify_tls=excluded.verify_tls
            """,
            (agent_id, name, api_url, token, 1 if verify_tls else 0, now(), now()),
        )
        conn.commit()


def delete_agent(agent_id: str) -> None:
    init_db()
    with _connect() as conn:
        conn.execute("DELETE FROM agents WHERE id=?", (agent_id,))
        conn.commit()


def get_agent(agent_id: str) -> Optional[Dict[str, Any]]:
    init_db()
    with _connect() as conn:
        row = conn.execute(
            "SELECT id, name, api_url, token, verify_tls, added_at, last_seen FROM agents WHERE id=?",
            (agent_id,),
        ).fetchone()
    return dict(row) if row else None


def list_agents() -> List[Dict[str, Any]]:
    init_db()
    with _connect() as conn:
        rows = conn.execute(
            "SELECT id, name, api_url, token, verify_tls, added_at, last_seen FROM agents ORDER BY added_at DESC"
        ).fetchall()
    return [dict(r) for r in rows]


def update_last_seen(agent_id: str, ts: int) -> None:
    init_db()
    with _connect() as conn:
        conn.execute("UPDATE agents SET last_seen=? WHERE id=?", (ts, agent_id))
        conn.commit()


def create_wss_pair(
    wss_host: str,
    wss_path: str,
    wss_sni: str,
    wss_insecure: bool = True,
    created_by_agent_id: str = "",
    ttl_seconds: int = 86400,
) -> Dict[str, Any]:
    """Create a WSS pairing code so the other side can auto-fill params."""
    import secrets

    init_db()
    code = f"{secrets.randbelow(1000000):06d}"
    created_at = now()
    expires_at = created_at + ttl_seconds

    with _connect() as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO wss_pairs(
              code, created_at, expires_at, used, created_by_agent_id,
              wss_host, wss_path, wss_sni, wss_insecure
            ) VALUES(?,?,?,?,?,?,?,?,?)
            """,
            (
                code,
                created_at,
                expires_at,
                0,
                created_by_agent_id or "",
                wss_host,
                wss_path,
                wss_sni,
                1 if wss_insecure else 0,
            ),
        )
        conn.commit()

    return {
        "code": code,
        "created_at": created_at,
        "expires_at": expires_at,
        "used": 0,
        "wss_host": wss_host,
        "wss_path": wss_path,
        "wss_sni": wss_sni,
        "wss_insecure": bool(wss_insecure),
    }


def get_wss_pair(code: str) -> Optional[Dict[str, Any]]:
    init_db()
    with _connect() as conn:
        row = conn.execute(
            "SELECT code, created_at, expires_at, used, created_by_agent_id, wss_host, wss_path, wss_sni, wss_insecure FROM wss_pairs WHERE code=?",
            (code,),
        ).fetchone()
    return dict(row) if row else None


def consume_wss_pair(code: str, mark_used: bool = True) -> Optional[Dict[str, Any]]:
    """Return pairing params if valid; optionally mark as used."""
    row = get_wss_pair(code)
    if not row:
        return None

    t = now()
    if int(row["expires_at"]) < t:
        return None
    if int(row.get("used", 0)) == 1:
        # single-use by default
        return None

    if mark_used:
        with _connect() as conn:
            conn.execute("UPDATE wss_pairs SET used=1 WHERE code=?", (code,))
            conn.commit()

    row["wss_insecure"] = bool(int(row.get("wss_insecure", 1)))
    return row
