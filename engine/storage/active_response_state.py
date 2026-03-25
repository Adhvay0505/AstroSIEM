#!/usr/bin/env python3
"""
Stateful active response tracking for AstroSIEM.

Tracks active responses that have duration/auto-revert, repeated offenders,
and response history.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


ENGINE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = ENGINE_DIR / "storage" / "active-response-state.sqlite"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class ActiveResponseStore:
    def __init__(self, db_path: Path = DB_PATH):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    @contextmanager
    def connect(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def _init_db(self) -> None:
        with self.connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS active_responses (
                    response_id TEXT PRIMARY KEY,
                    entity_type TEXT NOT NULL,
                    entity_value TEXT NOT NULL,
                    action_type TEXT NOT NULL,
                    action_name TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'active',
                    triggered_by_finding_id TEXT,
                    triggered_by_alert_id TEXT,
                    duration_seconds INTEGER,
                    started_at TEXT NOT NULL,
                    expires_at TEXT,
                    reverted_at TEXT,
                    output TEXT,
                    error_message TEXT,
                    UNIQUE(entity_type, entity_value, action_name, status)
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS repeated_offenders (
                    entity_type TEXT NOT NULL,
                    entity_value TEXT NOT NULL,
                    offense_count INTEGER DEFAULT 1,
                    first_offense_at TEXT,
                    last_offense_at TEXT,
                    current_block_duration INTEGER DEFAULT 0,
                    PRIMARY KEY (entity_type, entity_value)
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS response_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    response_id TEXT NOT NULL,
                    entity_type TEXT NOT NULL,
                    entity_value TEXT NOT NULL,
                    action_type TEXT NOT NULL,
                    action_name TEXT NOT NULL,
                    status TEXT NOT NULL,
                    triggered_by TEXT,
                    created_at TEXT NOT NULL,
                    details_json TEXT NOT NULL DEFAULT '{}'
                )
                """
            )

    def start_response(
        self,
        response_id: str,
        entity_type: str,
        entity_value: str,
        action_type: str,
        action_name: str,
        triggered_by_finding_id: str = "",
        triggered_by_alert_id: str = "",
        duration_seconds: int = 0,
        output: str = "",
    ) -> Dict[str, Any]:
        now = utc_now()
        expires_at = None
        if duration_seconds > 0:
            expires_dt = datetime.now(timezone.utc).timestamp() + duration_seconds
            expires_at = datetime.fromtimestamp(expires_dt, timezone.utc).isoformat()

        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO active_responses (
                    response_id, entity_type, entity_value, action_type, action_name,
                    status, triggered_by_finding_id, triggered_by_alert_id,
                    duration_seconds, started_at, expires_at, output
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(response_id) DO UPDATE SET
                    status = excluded.status,
                    reverted_at = excluded.reverted_at,
                    output = excluded.output
                """,
                (
                    response_id,
                    entity_type,
                    entity_value,
                    action_type,
                    action_name,
                    "active",
                    triggered_by_finding_id,
                    triggered_by_alert_id,
                    duration_seconds,
                    now,
                    expires_at,
                    output,
                ),
            )
            conn.execute(
                """
                INSERT INTO response_history (
                    response_id, entity_type, entity_value, action_type, action_name,
                    status, triggered_by, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    response_id,
                    entity_type,
                    entity_value,
                    action_type,
                    action_name,
                    "started",
                    triggered_by_finding_id or triggered_by_alert_id,
                    now,
                ),
            )

        return {
            "response_id": response_id,
            "entity_type": entity_type,
            "entity_value": entity_value,
            "status": "active",
            "started_at": now,
            "expires_at": expires_at,
        }

    def end_response(
        self,
        response_id: str,
        status: str = "reverted",
        error_message: str = "",
    ) -> Optional[Dict[str, Any]]:
        now = utc_now()
        with self.connect() as conn:
            conn.execute(
                """
                UPDATE active_responses
                SET status = ?, reverted_at = ?, error_message = ?
                WHERE response_id = ?
                """,
                (status, now, error_message, response_id),
            )
            conn.execute(
                """
                INSERT INTO response_history (
                    response_id, entity_type, entity_value, action_type, action_name,
                    status, triggered_by, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    response_id,
                    "",
                    "",
                    "",
                    "",
                    f"ended_{status}",
                    "",
                    now,
                ),
            )
            row = conn.execute(
                "SELECT * FROM active_responses WHERE response_id = ?",
                (response_id,),
            ).fetchone()
        return dict(row) if row else None

    def get_active_responses(
        self,
        entity_type: str = "",
        entity_value: str = "",
    ) -> List[Dict[str, Any]]:
        query = "SELECT * FROM active_responses WHERE status = 'active'"
        params = []
        if entity_type:
            query += " AND entity_type = ?"
            params.append(entity_type)
        if entity_value:
            query += " AND entity_value = ?"
            params.append(entity_value)
        query += " ORDER BY started_at DESC"

        with self.connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [dict(row) for row in rows]

    def get_response_history(
        self,
        entity_type: str = "",
        entity_value: str = "",
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        query = "SELECT * FROM response_history WHERE 1=1"
        params = []
        if entity_type:
            query += " AND entity_type = ?"
            params.append(entity_type)
        if entity_value:
            query += " AND entity_value = ?"
            params.append(entity_value)
        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)

        with self.connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [dict(row) for row in rows]

    def record_offense(
        self,
        entity_type: str,
        entity_value: str,
    ) -> Dict[str, Any]:
        now = utc_now()
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO repeated_offenders (
                    entity_type, entity_value, offense_count, first_offense_at, last_offense_at
                ) VALUES (?, ?, 1, ?, ?)
                ON CONFLICT(entity_type, entity_value) DO UPDATE SET
                    offense_count = offense_count + 1,
                    last_offense_at = excluded.last_offense_at
                """,
                (entity_type, entity_value, now, now),
            )
            row = conn.execute(
                "SELECT * FROM repeated_offenders WHERE entity_type = ? AND entity_value = ?",
                (entity_type, entity_value),
            ).fetchone()
        return dict(row) if row else {}

    def get_offenders(
        self,
        min_offenses: int = 2,
    ) -> List[Dict[str, Any]]:
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT * FROM repeated_offenders
                WHERE offense_count >= ?
                ORDER BY offense_count DESC
                """,
                (min_offenses,),
            ).fetchall()
        return [dict(row) for row in rows]

    def get_offender(
        self,
        entity_type: str,
        entity_value: str,
    ) -> Optional[Dict[str, Any]]:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT * FROM repeated_offenders WHERE entity_type = ? AND entity_value = ?",
                (entity_type, entity_value),
            ).fetchone()
        return dict(row) if row else None

    def calculate_block_duration(
        self,
        entity_type: str,
        entity_value: str,
        base_duration: int = 3600,
        multiplier_per_offense: float = 2.0,
        max_duration: int = 86400,
    ) -> int:
        offender = self.get_offender(entity_type, entity_value)
        if not offender:
            return base_duration

        offense_count = offender.get("offense_count", 1)
        duration = int(base_duration * (multiplier_per_offense ** (offense_count - 1)))
        return min(duration, max_duration)

    def check_active_block(
        self,
        entity_type: str,
        entity_value: str,
        action_name: str = "",
    ) -> Optional[Dict[str, Any]]:
        with self.connect() as conn:
            query = "SELECT * FROM active_responses WHERE status = 'active' AND entity_type = ? AND entity_value = ?"
            params = [entity_type, entity_value]
            if action_name:
                query += " AND action_name = ?"
                params.append(action_name)
            row = conn.execute(query, params).fetchone()
        return dict(row) if row else None

    def expire_responses(self) -> int:
        now = datetime.now(timezone.utc).isoformat()
        with self.connect() as conn:
            expired = conn.execute(
                """
                SELECT response_id FROM active_responses
                WHERE status = 'active' AND expires_at IS NOT NULL AND expires_at <= ?
                """,
                (now,),
            ).fetchall()

            count = 0
            for row in expired:
                response_id = row["response_id"]
                conn.execute(
                    """
                    UPDATE active_responses
                    SET status = 'expired', reverted_at = ?
                    WHERE response_id = ?
                    """,
                    (now, response_id),
                )
                conn.execute(
                    """
                    INSERT INTO response_history (
                        response_id, entity_type, entity_value, action_type, action_name,
                        status, triggered_by, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (response_id, "", "", "", "", "expired_auto", "", now),
                )
                count += 1
        return count

    def summarize(self) -> Dict[str, Any]:
        with self.connect() as conn:
            active = conn.execute(
                "SELECT COUNT(*) as count FROM active_responses WHERE status = 'active'"
            ).fetchone()["count"]
            total_history = conn.execute(
                "SELECT COUNT(*) as count FROM response_history"
            ).fetchone()["count"]
            offenders = conn.execute(
                "SELECT COUNT(*) as count FROM repeated_offenders"
            ).fetchone()["count"]
            high_offenders = conn.execute(
                "SELECT COUNT(*) as count FROM repeated_offenders WHERE offense_count >= 3"
            ).fetchone()["count"]

        return {
            "active_responses": active,
            "total_history": total_history,
            "repeated_offenders": offenders,
            "high_offenders": high_offenders,
        }
