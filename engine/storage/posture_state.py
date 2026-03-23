#!/usr/bin/env python3
"""
Persistent posture and policy findings for AstroSIEM.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


ENGINE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = ENGINE_DIR / "storage" / "posture-state.sqlite"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def json_dumps(value: Any) -> str:
    return json.dumps(value if value is not None else [], sort_keys=True)


def json_loads(value: Optional[str], default: Any) -> Any:
    if not value:
        return default
    try:
        return json.loads(value)
    except Exception:
        return default


class PostureStateStore:
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
                CREATE TABLE IF NOT EXISTS posture_findings (
                    finding_id TEXT PRIMARY KEY,
                    dedup_key TEXT UNIQUE NOT NULL,
                    host_name TEXT NOT NULL,
                    check_id TEXT NOT NULL,
                    title TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'open',
                    summary TEXT NOT NULL DEFAULT '',
                    recommendation TEXT NOT NULL DEFAULT '',
                    rationale TEXT NOT NULL DEFAULT '',
                    evidence_json TEXT NOT NULL DEFAULT '[]',
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS posture_responses (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    finding_id TEXT NOT NULL,
                    action_name TEXT NOT NULL,
                    action_type TEXT NOT NULL,
                    status TEXT NOT NULL,
                    output TEXT NOT NULL DEFAULT '',
                    triggered_at TEXT NOT NULL,
                    UNIQUE(finding_id, action_name)
                )
                """
            )

    def _row_to_finding(self, row: sqlite3.Row) -> Dict[str, Any]:
        return {
            "finding_id": row["finding_id"],
            "dedup_key": row["dedup_key"],
            "host_name": row["host_name"],
            "check_id": row["check_id"],
            "title": row["title"],
            "severity": row["severity"],
            "status": row["status"],
            "summary": row["summary"],
            "recommendation": row["recommendation"],
            "rationale": row["rationale"],
            "evidence": json_loads(row["evidence_json"], []),
            "first_seen": row["first_seen"],
            "last_seen": row["last_seen"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "responses": self.list_responses_for_finding(row["finding_id"]),
        }

    def sync_findings(self, findings: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
        now = utc_now()
        active_keys = set()
        with self.connect() as conn:
            for finding in findings:
                active_keys.add(finding["dedup_key"])
                existing = conn.execute(
                    "SELECT * FROM posture_findings WHERE dedup_key = ?",
                    (finding["dedup_key"],),
                ).fetchone()
                if existing:
                    conn.execute(
                        """
                        UPDATE posture_findings
                        SET title = ?, severity = ?, status = 'open', summary = ?, recommendation = ?,
                            rationale = ?, evidence_json = ?, last_seen = ?, updated_at = ?
                        WHERE dedup_key = ?
                        """,
                        (
                            finding["title"],
                            finding["severity"],
                            finding.get("summary", ""),
                            finding.get("recommendation", ""),
                            finding.get("rationale", ""),
                            json_dumps(finding.get("evidence", [])),
                            finding["last_seen"],
                            now,
                            finding["dedup_key"],
                        ),
                    )
                else:
                    conn.execute(
                        """
                        INSERT INTO posture_findings (
                            finding_id, dedup_key, host_name, check_id, title, severity, status,
                            summary, recommendation, rationale, evidence_json, first_seen, last_seen,
                            created_at, updated_at
                        ) VALUES (?, ?, ?, ?, ?, ?, 'open', ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            finding["finding_id"],
                            finding["dedup_key"],
                            finding["host_name"],
                            finding["check_id"],
                            finding["title"],
                            finding["severity"],
                            finding.get("summary", ""),
                            finding.get("recommendation", ""),
                            finding.get("rationale", ""),
                            json_dumps(finding.get("evidence", [])),
                            finding["first_seen"],
                            finding["last_seen"],
                            now,
                            now,
                        ),
                    )

            if active_keys:
                placeholders = ",".join("?" for _ in active_keys)
                conn.execute(
                    f"""
                    UPDATE posture_findings
                    SET status = 'resolved', updated_at = ?
                    WHERE dedup_key NOT IN ({placeholders}) AND status = 'open'
                    """,
                    (now, *active_keys),
                )
            else:
                conn.execute(
                    "UPDATE posture_findings SET status = 'resolved', updated_at = ? WHERE status = 'open'",
                    (now,),
                )

        return self.list_findings(include_resolved=True)

    def list_findings(self, include_resolved: bool = False) -> List[Dict[str, Any]]:
        query = "SELECT * FROM posture_findings"
        if not include_resolved:
            query += " WHERE status != 'resolved'"
        query += " ORDER BY CASE severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 ELSE 1 END DESC, last_seen DESC"
        with self.connect() as conn:
            rows = conn.execute(query).fetchall()
        return [self._row_to_finding(row) for row in rows]

    def list_responses_for_finding(self, finding_id: str) -> List[Dict[str, Any]]:
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT action_name, action_type, status, output, triggered_at
                FROM posture_responses
                WHERE finding_id = ?
                ORDER BY triggered_at ASC
                """,
                (finding_id,),
            ).fetchall()
        return [
            {
                "action_name": row["action_name"],
                "action_type": row["action_type"],
                "status": row["status"],
                "output": row["output"],
                "triggered_at": row["triggered_at"],
            }
            for row in rows
        ]

    def response_already_recorded(self, finding_id: str, action_name: str) -> bool:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT 1 FROM posture_responses WHERE finding_id = ? AND action_name = ?",
                (finding_id, action_name),
            ).fetchone()
        return bool(row)

    def record_response(
        self,
        *,
        finding_id: str,
        action_name: str,
        action_type: str,
        status: str,
        output: str,
    ) -> None:
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO posture_responses (finding_id, action_name, action_type, status, output, triggered_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(finding_id, action_name) DO UPDATE SET
                    status = excluded.status,
                    output = excluded.output,
                    triggered_at = excluded.triggered_at
                """,
                (finding_id, action_name, action_type, status, output[:4000], utc_now()),
            )

    def summary(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        open_findings = [finding for finding in findings if finding.get("status") != "resolved"]
        return {
            "generated_at": utc_now(),
            "total_findings": len(open_findings),
            "critical_findings": sum(1 for item in open_findings if item.get("severity") == "critical"),
            "high_findings": sum(1 for item in open_findings if item.get("severity") == "high"),
            "medium_findings": sum(1 for item in open_findings if item.get("severity") == "medium"),
            "affected_hosts": len({item.get("host_name") for item in open_findings if item.get("host_name")}),
            "resolved_findings": sum(1 for item in findings if item.get("status") == "resolved"),
            "automated_actions": sum(len(item.get("responses") or []) for item in findings),
        }
