#!/usr/bin/env python3
"""
Entity risk scoring for AstroSIEM.

Provides persistent risk scores per entity (host, user, IP) with accumulation
and decay over time.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


ENGINE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = ENGINE_DIR / "storage" / "risk-scores.sqlite"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class RiskScoreStore:
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
                CREATE TABLE IF NOT EXISTS entity_risk_scores (
                    entity_type TEXT NOT NULL,
                    entity_id TEXT NOT NULL,
                    risk_score REAL DEFAULT 0,
                    risk_factors_json TEXT NOT NULL DEFAULT '[]',
                    alert_count INTEGER DEFAULT 0,
                    last_updated TEXT,
                    last_alert_id TEXT,
                    PRIMARY KEY (entity_type, entity_id)
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS risk_finding_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    entity_type TEXT NOT NULL,
                    entity_id TEXT NOT NULL,
                    alert_id TEXT,
                    risk_delta REAL NOT NULL,
                    factor_type TEXT NOT NULL,
                    factor_detail TEXT,
                    created_at TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS risk_config (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                )
                """
            )
            self._set_default_config(conn)

    def _set_default_config(self, conn: sqlite3.Connection) -> None:
        defaults = {
            "decay_half_life_days": "7",
            "critical_threshold": "70",
            "high_threshold": "50",
            "medium_threshold": "30",
            "auto_escalate_critical": "true",
            "auto_escalate_high": "false",
        }
        for key, value in defaults.items():
            conn.execute(
                "INSERT OR IGNORE INTO risk_config (key, value) VALUES (?, ?)",
                (key, value),
            )

    def get_config(self, key: str, default: str = "") -> str:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT value FROM risk_config WHERE key = ?", (key,)
            ).fetchone()
            return row["value"] if row else default

    def get_all_config(self) -> Dict[str, str]:
        with self.connect() as conn:
            rows = conn.execute("SELECT key, value FROM risk_config").fetchall()
            return {row["key"]: row["value"] for row in rows}

    def update_config(self, key: str, value: str) -> None:
        with self.connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO risk_config (key, value) VALUES (?, ?)",
                (key, value),
            )

    def get_entity_risk(
        self, entity_type: str, entity_id: str
    ) -> Optional[Dict[str, Any]]:
        with self.connect() as conn:
            row = conn.execute(
                """
                SELECT * FROM entity_risk_scores
                WHERE entity_type = ? AND entity_id = ?
                """,
                (entity_type, entity_id),
            ).fetchone()
            if not row:
                return None
            return {
                "entity_type": row["entity_type"],
                "entity_id": row["entity_id"],
                "risk_score": row["risk_score"],
                "risk_factors": json.loads(row["risk_factors_json"] or "[]"),
                "alert_count": row["alert_count"],
                "last_updated": row["last_updated"],
                "last_alert_id": row["last_alert_id"],
            }

    def get_all_entity_risks(self) -> List[Dict[str, Any]]:
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT * FROM entity_risk_scores
                ORDER BY risk_score DESC
                """
            ).fetchall()
        return [
            {
                "entity_type": row["entity_type"],
                "entity_id": row["entity_id"],
                "risk_score": row["risk_score"],
                "risk_factors": json.loads(row["risk_factors_json"] or "[]"),
                "alert_count": row["alert_count"],
                "last_updated": row["last_updated"],
                "last_alert_id": row["last_alert_id"],
            }
            for row in rows
        ]

    def add_risk(
        self,
        entity_type: str,
        entity_id: str,
        risk_delta: float,
        factor_type: str,
        factor_detail: str = "",
        alert_id: str = "",
    ) -> Dict[str, Any]:
        now = utc_now()
        existing = self.get_entity_risk(entity_type, entity_id)

        current_score = existing["risk_score"] if existing else 0
        current_factors = existing["risk_factors"] if existing else []
        current_alert_count = existing["alert_count"] if existing else 0

        new_score = min(100, current_score + risk_delta)

        new_factor = {
            "type": factor_type,
            "detail": factor_detail,
            "added_at": now,
            "delta": risk_delta,
        }
        current_factors.append(new_factor)

        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO entity_risk_scores (
                    entity_type, entity_id, risk_score, risk_factors_json,
                    alert_count, last_updated, last_alert_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(entity_type, entity_id) DO UPDATE SET
                    risk_score = excluded.risk_score,
                    risk_factors_json = excluded.risk_factors_json,
                    alert_count = alert_count + 1,
                    last_updated = excluded.last_updated,
                    last_alert_id = excluded.last_alert_id
                """,
                (
                    entity_type,
                    entity_id,
                    new_score,
                    json.dumps(current_factors),
                    current_alert_count + 1,
                    now,
                    alert_id or existing.get("last_alert_id", "") if existing else "",
                ),
            )
            conn.execute(
                """
                INSERT INTO risk_finding_history (
                    entity_type, entity_id, alert_id, risk_delta,
                    factor_type, factor_detail, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    entity_type,
                    entity_id,
                    alert_id,
                    risk_delta,
                    factor_type,
                    factor_detail,
                    now,
                ),
            )

        return {
            "entity_type": entity_type,
            "entity_id": entity_id,
            "risk_score": new_score,
            "risk_delta": risk_delta,
            "factor_type": factor_type,
            "factor_detail": factor_detail,
        }

    def set_risk(
        self,
        entity_type: str,
        entity_id: str,
        risk_score: float,
        risk_factors: Optional[List[Dict[str, Any]]] = None,
        alert_id: str = "",
    ) -> None:
        now = utc_now()
        factors_json = json.dumps(risk_factors or [])
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO entity_risk_scores (
                    entity_type, entity_id, risk_score, risk_factors_json,
                    alert_count, last_updated, last_alert_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(entity_type, entity_id) DO UPDATE SET
                    risk_score = excluded.risk_score,
                    risk_factors_json = excluded.risk_factors_json,
                    last_updated = excluded.last_updated,
                    last_alert_id = excluded.last_alert_id
                """,
                (
                    entity_type,
                    entity_id,
                    min(100, max(0, risk_score)),
                    factors_json,
                    1 if risk_score > 0 else 0,
                    now,
                    alert_id,
                ),
            )

    def decay_risk(self, entity_type: str, entity_id: str) -> Optional[float]:
        half_life_days = float(self.get_config("decay_half_life_days", "7"))
        existing = self.get_entity_risk(entity_type, entity_id)
        if not existing or existing["risk_score"] == 0:
            return None

        decay_factor = 0.5 ** (1 / half_life_days)
        new_score = existing["risk_score"] * decay_factor
        new_score = max(0, round(new_score, 2))

        now = utc_now()
        with self.connect() as conn:
            conn.execute(
                """
                UPDATE entity_risk_scores
                SET risk_score = ?, last_updated = ?
                WHERE entity_type = ? AND entity_id = ?
                """,
                (new_score, now, entity_type, entity_id),
            )

        return new_score

    def decay_all_risk(self) -> int:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT entity_type, entity_id, risk_score FROM entity_risk_scores"
            ).fetchall()

        half_life_days = float(self.get_config("decay_half_life_days", "7"))
        decay_factor = 0.5 ** (1 / half_life_days)

        count = 0
        now = utc_now()
        for row in rows:
            if row["risk_score"] > 0:
                new_score = max(0, round(row["risk_score"] * decay_factor, 2))
                conn.execute(
                    """
                    UPDATE entity_risk_scores
                    SET risk_score = ?, last_updated = ?
                    WHERE entity_type = ? AND entity_id = ?
                    """,
                    (new_score, now, row["entity_type"], row["entity_id"]),
                )
                count += 1
        return count

    def reset_risk(self, entity_type: str, entity_id: str) -> bool:
        with self.connect() as conn:
            conn.execute(
                "DELETE FROM entity_risk_scores WHERE entity_type = ? AND entity_id = ?",
                (entity_type, entity_id),
            )
            return True

    def get_risk_history(
        self, entity_type: str, entity_id: str, limit: int = 50
    ) -> List[Dict[str, Any]]:
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT * FROM risk_finding_history
                WHERE entity_type = ? AND entity_id = ?
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (entity_type, entity_id, limit),
            ).fetchall()
        return [
            {
                "id": row["id"],
                "entity_type": row["entity_type"],
                "entity_id": row["entity_id"],
                "alert_id": row["alert_id"],
                "risk_delta": row["risk_delta"],
                "factor_type": row["factor_type"],
                "factor_detail": row["factor_detail"],
                "created_at": row["created_at"],
            }
            for row in rows
        ]

    def get_high_risk_entities(self, threshold: float = 50) -> List[Dict[str, Any]]:
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT * FROM entity_risk_scores
                WHERE risk_score >= ?
                ORDER BY risk_score DESC
                """,
                (threshold,),
            ).fetchall()
        return [
            {
                "entity_type": row["entity_type"],
                "entity_id": row["entity_id"],
                "risk_score": row["risk_score"],
                "risk_factors": json.loads(row["risk_factors_json"] or "[]"),
                "alert_count": row["alert_count"],
                "last_updated": row["last_updated"],
            }
            for row in rows
        ]

    def summarize(self) -> Dict[str, Any]:
        with self.connect() as conn:
            total = conn.execute(
                "SELECT COUNT(*) as count FROM entity_risk_scores WHERE risk_score > 0"
            ).fetchone()["count"]
            critical = conn.execute(
                "SELECT COUNT(*) as count FROM entity_risk_scores WHERE risk_score >= ?",
                (70,),
            ).fetchone()["count"]
            high = conn.execute(
                "SELECT COUNT(*) as count FROM entity_risk_scores WHERE risk_score >= ? AND risk_score < ?",
                (50, 70),
            ).fetchone()["count"]
            medium = conn.execute(
                "SELECT COUNT(*) as count FROM entity_risk_scores WHERE risk_score >= ? AND risk_score < ?",
                (30, 50),
            ).fetchone()["count"]
            avg_score = (
                conn.execute(
                    "SELECT AVG(risk_score) as avg FROM entity_risk_scores WHERE risk_score > 0"
                ).fetchone()["avg"]
                or 0
            )

        return {
            "total_entities_at_risk": total,
            "critical_risk": critical,
            "high_risk": high,
            "medium_risk": medium,
            "average_risk_score": round(avg_score, 1),
            "config": self.get_all_config(),
        }
