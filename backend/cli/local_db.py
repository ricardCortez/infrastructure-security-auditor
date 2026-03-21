"""SQLite-backed local storage for PSI CLI — no server required."""
import os
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

# Tests can override via monkeypatch.setattr(local_db, "DB_PATH", ...)
DB_PATH: Path = (
    Path(os.environ["PSI_DB_PATH"]) if os.environ.get("PSI_DB_PATH")
    else Path.home() / ".psi" / "psi.db"
)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS assets (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    hostname    TEXT    NOT NULL,
    ip_address  TEXT,
    asset_type  TEXT    DEFAULT 'server',
    criticality TEXT    DEFAULT 'medium',
    created_at  TEXT    DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS findings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id    INTEGER,
    title       TEXT    NOT NULL,
    severity    TEXT    DEFAULT 'MEDIUM',
    cvss_score  REAL,
    cwe         TEXT,
    description TEXT,
    remediation TEXT,
    plugin_id   TEXT,
    source      TEXT    DEFAULT 'manual',
    status      TEXT    DEFAULT 'OPEN',
    created_at  TEXT    DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS scan_jobs (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id     INTEGER,
    job_type     TEXT,
    status       TEXT DEFAULT 'queued',
    target       TEXT,
    scan_type    TEXT DEFAULT 'full',
    started_at   TEXT,
    completed_at TEXT,
    created_at   TEXT DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS reports (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    format         TEXT,
    path           TEXT,
    findings_count INTEGER DEFAULT 0,
    created_at     TEXT DEFAULT (datetime('now'))
);
"""


def _conn() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db() -> None:
    """Create all tables if they don't exist."""
    with _conn() as c:
        c.executescript(_SCHEMA)


def get_all(table: str, filters: Optional[Dict[str, Any]] = None) -> List[Dict]:
    """Return all rows from *table*, optionally filtered by exact-match *filters*."""
    init_db()
    with _conn() as c:
        if filters:
            where = " AND ".join(f"{k} = ?" for k in filters)
            rows = c.execute(f"SELECT * FROM {table} WHERE {where}",
                             list(filters.values())).fetchall()
        else:
            rows = c.execute(f"SELECT * FROM {table}").fetchall()
    return [dict(r) for r in rows]


def get_by_id(table: str, row_id: int) -> Optional[Dict]:
    """Return a single row by primary key, or None."""
    init_db()
    with _conn() as c:
        row = c.execute(f"SELECT * FROM {table} WHERE id = ?", (row_id,)).fetchone()
    return dict(row) if row else None


def insert(table: str, data: Dict[str, Any]) -> Dict:
    """Insert *data* into *table* and return the full inserted row."""
    init_db()
    cols = ", ".join(data.keys())
    placeholders = ", ".join("?" * len(data))
    with _conn() as c:
        cur = c.execute(f"INSERT INTO {table} ({cols}) VALUES ({placeholders})",
                        list(data.values()))
        c.commit()
        row_id = cur.lastrowid
    return get_by_id(table, row_id)


def update(table: str, row_id: int, data: Dict[str, Any]) -> Optional[Dict]:
    """Update row by *row_id* and return the updated row."""
    init_db()
    sets = ", ".join(f"{k} = ?" for k in data)
    with _conn() as c:
        c.execute(f"UPDATE {table} SET {sets} WHERE id = ?",
                  list(data.values()) + [row_id])
        c.commit()
    return get_by_id(table, row_id)


def delete_by_id(table: str, row_id: int) -> bool:
    """Delete row by *row_id*. Returns True if a row was deleted."""
    init_db()
    with _conn() as c:
        cur = c.execute(f"DELETE FROM {table} WHERE id = ?", (row_id,))
        c.commit()
    return cur.rowcount > 0
