"""
Persistent storage for KeyCrawl findings.

IMPORTANT SAFETY DESIGN:
- Only redacted findings are ever stored (value_redacted, context, metadata).
- The raw secret `value` is NEVER written to the database.
- This module is intentionally separate so that both the web UI and the CLI
  can contribute to the same collection of discovered (redacted) secrets.
- Storing raw private keys or API secrets would turn this into a credential
  harvesting tool. We deliberately do not support that.

Use this for legitimate security testing / leak detection on systems you own
or have explicit permission to scan.
"""

from __future__ import annotations

import asyncio
import os
import time
from typing import Any

import aiosqlite

DB_PATH = os.getenv("KEYCRAWL_DB", "findings.db")


async def init_db() -> None:
    """Initialize the SQLite database with tables for scans and redacted findings."""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                target TEXT NOT NULL,
                started_at REAL NOT NULL,
                finished_at REAL,
                pages_crawled INTEGER DEFAULT 0
            )
        """)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT,
                discovered_at REAL NOT NULL,
                url TEXT NOT NULL,
                secret_type TEXT NOT NULL,
                value_redacted TEXT NOT NULL,
                context TEXT,
                entropy REAL,
                pattern_name TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans(id)
            )
        """)
        await db.execute("CREATE INDEX IF NOT EXISTS idx_findings_type ON findings(secret_type)")
        await db.execute("CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id)")
        await db.commit()


async def save_scan_result(
    scan_id: str,
    target: str,
    started_at: float,
    finished_at: float | None,
    pages_crawled: int,
    findings: list[dict[str, Any]],
) -> None:
    """
    Persist a scan and its findings.

    `findings` must be a list of dictionaries that contain ONLY safe fields:
    - url
    - secret_type
    - value_redacted
    - context
    - entropy
    - pattern_name

    Raw secret values must have been removed before calling this function.
    """
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "INSERT OR REPLACE INTO scans (id, target, started_at, finished_at, pages_crawled) VALUES (?, ?, ?, ?, ?)",
            (scan_id, target, started_at, finished_at, pages_crawled),
        )
        now = time.time()
        for f in findings:
            await db.execute(
                """INSERT INTO findings
                   (scan_id, discovered_at, url, secret_type, value_redacted, context, entropy, pattern_name)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    scan_id,
                    now,
                    f.get("url"),
                    f.get("secret_type"),
                    f.get("value_redacted"),
                    f.get("context"),
                    f.get("entropy"),
                    f.get("pattern_name"),
                ),
            )
        await db.commit()


async def get_all_findings(secret_type: str | None = None, limit: int = 1000) -> list[dict]:
    """Return collected redacted findings, newest first."""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        if secret_type:
            cursor = await db.execute(
                "SELECT * FROM findings WHERE secret_type = ? ORDER BY discovered_at DESC LIMIT ?",
                (secret_type, limit),
            )
        else:
            cursor = await db.execute(
                "SELECT * FROM findings ORDER BY discovered_at DESC LIMIT ?",
                (limit,),
            )
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]


async def get_category_counts() -> list[dict]:
    """Return counts per secret category."""
    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute(
            "SELECT secret_type, COUNT(*) as count FROM findings GROUP BY secret_type ORDER BY count DESC"
        )
        rows = await cursor.fetchall()
        return [{"secret_type": r[0], "count": r[1]} for r in rows]


async def get_high_risk_findings(limit: int = 500) -> list[dict]:
    """Convenience: findings that look like private keys or high-value secrets."""
    high_risk_types = (
        "Solana Private Key",
        "Solana Private Key (raw base58)",
        "Private Key (PEM/OpenSSH)",
        "SSH Private Key (old)",
    )
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        placeholders = ",".join("?" * len(high_risk_types))
        cursor = await db.execute(
            f"SELECT * FROM findings WHERE secret_type IN ({placeholders}) ORDER BY discovered_at DESC LIMIT ?",
            (*high_risk_types, limit),
        )
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]


# -----------------------------
# Sync convenience wrappers (useful for CLI)
# -----------------------------
def init_db_sync() -> None:
    asyncio.run(init_db())


def save_redacted_scan_sync(
    scan_id: str,
    target: str,
    started_at: float,
    finished_at: float | None,
    pages_crawled: int,
    safe_findings: list[dict[str, Any]],
) -> None:
    """Save redacted findings from a synchronous context (e.g. CLI)."""
    asyncio.run(
        save_scan_result(
            scan_id=scan_id,
            target=target,
            started_at=started_at,
            finished_at=finished_at,
            pages_crawled=pages_crawled,
            findings=safe_findings,
        )
    )


def get_all_findings_sync(secret_type: str | None = None, limit: int = 1000) -> list[dict]:
    return asyncio.run(get_all_findings(secret_type=secret_type, limit=limit))


def get_category_counts_sync() -> list[dict]:
    return asyncio.run(get_category_counts())


def get_high_risk_findings_sync(limit: int = 500) -> list[dict]:
    return asyncio.run(get_high_risk_findings(limit=limit))
