#!/usr/bin/env python3
"""
Persistent alert state and suppression storage for AstroSIEM.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


ENGINE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = ENGINE_DIR / "storage" / "alerts-state.sqlite"

OPEN_STATUSES = {"new", "investigating", "escalated"}


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


class AlertStateStore:
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
                CREATE TABLE IF NOT EXISTS alerts (
                    alert_id TEXT PRIMARY KEY,
                    dedup_key TEXT UNIQUE NOT NULL,
                    rule_id TEXT NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT,
                    severity TEXT NOT NULL,
                    confidence INTEGER NOT NULL,
                    priority_score INTEGER NOT NULL DEFAULT 0,
                    status TEXT NOT NULL DEFAULT 'new',
                    owner TEXT NOT NULL DEFAULT '',
                    disposition TEXT NOT NULL DEFAULT '',
                    notes TEXT NOT NULL DEFAULT '',
                    suppressed INTEGER NOT NULL DEFAULT 0,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    event_count INTEGER NOT NULL DEFAULT 0,
                    source_count INTEGER NOT NULL DEFAULT 0,
                    summary TEXT,
                    recommended_action TEXT,
                    coverage_summary TEXT,
                    scope_summary TEXT,
                    why_this_fired TEXT,
                    evidence_preview TEXT,
                    telemetry_sources_json TEXT NOT NULL DEFAULT '[]',
                    entities_json TEXT NOT NULL DEFAULT '{}',
                    mitre_json TEXT NOT NULL DEFAULT '[]',
                    compliance_json TEXT NOT NULL DEFAULT '[]',
                    recommendations_json TEXT NOT NULL DEFAULT '[]',
                    evidence_json TEXT NOT NULL DEFAULT '[]'
                )
                """
            )
            self._ensure_columns(
                conn,
                "alerts",
                {
                    "priority_score": "INTEGER NOT NULL DEFAULT 0",
                    "why_this_fired": "TEXT",
                },
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS suppressions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    rule_id TEXT,
                    dedup_key TEXT,
                    host_name TEXT,
                    source_ip TEXT,
                    user_name TEXT,
                    reason TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    expires_at TEXT,
                    active INTEGER NOT NULL DEFAULT 1
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS cases (
                    case_id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'open',
                    severity TEXT NOT NULL DEFAULT 'medium',
                    owner TEXT NOT NULL DEFAULT '',
                    summary TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS case_alerts (
                    case_id TEXT NOT NULL,
                    alert_id TEXT NOT NULL,
                    linked_at TEXT NOT NULL,
                    PRIMARY KEY (case_id, alert_id)
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS case_comments (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_id TEXT NOT NULL,
                    author TEXT NOT NULL DEFAULT '',
                    comment TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
                """
            )

    def _ensure_columns(self, conn: sqlite3.Connection, table: str, columns: Dict[str, str]) -> None:
        existing = {
            row["name"]
            for row in conn.execute(f"PRAGMA table_info({table})").fetchall()
        }
        for name, ddl in columns.items():
            if name not in existing:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {ddl}")

    def _row_to_alert(self, row: sqlite3.Row) -> Dict[str, Any]:
        return {
            "alert_id": row["alert_id"],
            "dedup_key": row["dedup_key"],
            "rule_id": row["rule_id"],
            "title": row["title"],
            "description": row["description"],
            "severity": row["severity"],
            "confidence": row["confidence"],
            "priority_score": row["priority_score"],
            "status": row["status"],
            "owner": row["owner"],
            "disposition": row["disposition"],
            "notes": row["notes"],
            "suppressed": bool(row["suppressed"]),
            "first_seen": row["first_seen"],
            "last_seen": row["last_seen"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "event_count": row["event_count"],
            "source_count": row["source_count"],
            "summary": row["summary"],
            "recommended_action": row["recommended_action"],
            "coverage_summary": row["coverage_summary"],
            "scope_summary": row["scope_summary"],
            "why_this_fired": row["why_this_fired"],
            "evidence_preview": row["evidence_preview"],
            "telemetry_sources": json_loads(row["telemetry_sources_json"], []),
            "entities": json_loads(row["entities_json"], {}),
            "mitre": json_loads(row["mitre_json"], []),
            "compliance": json_loads(row["compliance_json"], []),
            "recommendations": json_loads(row["recommendations_json"], []),
            "evidence": json_loads(row["evidence_json"], []),
        }

    def _row_to_suppression(self, row: sqlite3.Row) -> Dict[str, Any]:
        return {
            "id": row["id"],
            "rule_id": row["rule_id"],
            "dedup_key": row["dedup_key"],
            "host_name": row["host_name"],
            "source_ip": row["source_ip"],
            "user_name": row["user_name"],
            "reason": row["reason"],
            "created_at": row["created_at"],
            "expires_at": row["expires_at"],
            "active": bool(row["active"]),
        }

    def _row_to_case(self, row: sqlite3.Row) -> Dict[str, Any]:
        comments = self.list_case_comments(row["case_id"])
        linked_alerts = self.list_case_alerts(row["case_id"])
        return {
            "case_id": row["case_id"],
            "title": row["title"],
            "status": row["status"],
            "severity": row["severity"],
            "owner": row["owner"],
            "summary": row["summary"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "linked_alerts": linked_alerts,
            "comment_count": len(comments),
            "latest_comment": comments[-1] if comments else None,
        }

    def list_active_suppressions(self) -> List[Dict[str, Any]]:
        now = utc_now()
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT * FROM suppressions
                WHERE active = 1 AND (expires_at IS NULL OR expires_at > ?)
                ORDER BY created_at DESC
                """,
                (now,),
            ).fetchall()
        return [self._row_to_suppression(row) for row in rows]

    def suppression_matches(self, alert: Dict[str, Any]) -> bool:
        entities = alert.get("entities", {}) or {}
        hosts = set(entities.get("hosts", []))
        source_ips = set(entities.get("source_ips", []))
        users = set(entities.get("users", []))
        for suppression in self.list_active_suppressions():
            if suppression.get("dedup_key") and suppression["dedup_key"] != alert["dedup_key"]:
                continue
            if suppression.get("rule_id") and suppression["rule_id"] != alert["rule_id"]:
                continue
            if suppression.get("host_name") and suppression["host_name"] not in hosts:
                continue
            if suppression.get("source_ip") and suppression["source_ip"] not in source_ips:
                continue
            if suppression.get("user_name") and suppression["user_name"] not in users:
                continue
            return True
        return False

    def sync_alerts(self, detected_alerts: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
        now = utc_now()
        active_keys = set()
        with self.connect() as conn:
            for alert in detected_alerts:
                active_keys.add(alert["dedup_key"])
                suppressed = 1 if self.suppression_matches(alert) else 0
                existing = conn.execute(
                    "SELECT * FROM alerts WHERE dedup_key = ?",
                    (alert["dedup_key"],),
                ).fetchone()
                if existing:
                    status = existing["status"]
                    if suppressed:
                        status = "suppressed"
                    elif status in {"resolved", "false_positive", "suppressed"}:
                        status = "new"
                    conn.execute(
                        """
                        UPDATE alerts
                        SET rule_id = ?, title = ?, description = ?, severity = ?, confidence = ?,
                            priority_score = ?,
                            status = ?, suppressed = ?, last_seen = ?, updated_at = ?,
                            event_count = ?, source_count = ?, summary = ?, recommended_action = ?,
                            coverage_summary = ?, scope_summary = ?, why_this_fired = ?, evidence_preview = ?,
                            telemetry_sources_json = ?, entities_json = ?, mitre_json = ?,
                            compliance_json = ?, recommendations_json = ?, evidence_json = ?
                        WHERE dedup_key = ?
                        """,
                        (
                            alert["rule_id"],
                            alert["title"],
                            alert.get("description", ""),
                            alert["severity"],
                            alert.get("confidence", 75),
                            alert.get("priority_score", 0),
                            status,
                            suppressed,
                            alert["last_seen"],
                            now,
                            alert.get("event_count", 0),
                            alert.get("source_count", 0),
                            alert.get("summary", ""),
                            alert.get("recommended_action", ""),
                            alert.get("coverage_summary", ""),
                            alert.get("scope_summary", ""),
                            alert.get("why_this_fired", ""),
                            alert.get("evidence_preview", ""),
                            json_dumps(alert.get("telemetry_sources", [])),
                            json_dumps(alert.get("entities", {})),
                            json_dumps(alert.get("mitre", [])),
                            json_dumps(alert.get("compliance", [])),
                            json_dumps(alert.get("recommendations", [])),
                            json_dumps(alert.get("evidence", [])),
                            alert["dedup_key"],
                        ),
                    )
                else:
                    status = "suppressed" if suppressed else "new"
                    conn.execute(
                        """
                        INSERT INTO alerts (
                            alert_id, dedup_key, rule_id, title, description, severity, confidence,
                            priority_score,
                            status, owner, disposition, notes, suppressed, first_seen, last_seen,
                            created_at, updated_at, event_count, source_count, summary,
                            recommended_action, coverage_summary, scope_summary, why_this_fired, evidence_preview,
                            telemetry_sources_json, entities_json, mitre_json, compliance_json,
                            recommendations_json, evidence_json
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            alert["alert_id"],
                            alert["dedup_key"],
                            alert["rule_id"],
                            alert["title"],
                            alert.get("description", ""),
                            alert["severity"],
                            alert.get("confidence", 75),
                            alert.get("priority_score", 0),
                            status,
                            "",
                            "",
                            "",
                            suppressed,
                            alert["first_seen"],
                            alert["last_seen"],
                            now,
                            now,
                            alert.get("event_count", 0),
                            alert.get("source_count", 0),
                            alert.get("summary", ""),
                            alert.get("recommended_action", ""),
                            alert.get("coverage_summary", ""),
                            alert.get("scope_summary", ""),
                            alert.get("why_this_fired", ""),
                            alert.get("evidence_preview", ""),
                            json_dumps(alert.get("telemetry_sources", [])),
                            json_dumps(alert.get("entities", {})),
                            json_dumps(alert.get("mitre", [])),
                            json_dumps(alert.get("compliance", [])),
                            json_dumps(alert.get("recommendations", [])),
                            json_dumps(alert.get("evidence", [])),
                        ),
                    )
            if active_keys:
                placeholders = ",".join("?" for _ in active_keys)
                conn.execute(
                    f"""
                    UPDATE alerts
                    SET status = CASE
                        WHEN status IN ('new', 'investigating', 'escalated') THEN 'resolved'
                        ELSE status
                    END,
                        updated_at = ?
                    WHERE dedup_key NOT IN ({placeholders})
                    """,
                    (now, *active_keys),
                )
            else:
                conn.execute(
                    """
                    UPDATE alerts
                    SET status = CASE
                        WHEN status IN ('new', 'investigating', 'escalated') THEN 'resolved'
                        ELSE status
                    END,
                        updated_at = ?
                    """,
                    (now,),
                )
        return self.list_alerts(include_suppressed=False)

    def list_alerts(self, include_suppressed: bool = False) -> List[Dict[str, Any]]:
        query = "SELECT * FROM alerts"
        params: List[Any] = []
        if not include_suppressed:
            query += " WHERE suppressed = 0"
        query += " ORDER BY priority_score DESC, last_seen DESC"
        with self.connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row_to_alert(row) for row in rows]

    def get_alert(self, alert_id: str) -> Optional[Dict[str, Any]]:
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM alerts WHERE alert_id = ?", (alert_id,)).fetchone()
        return self._row_to_alert(row) if row else None

    def update_alert(self, alert_id: str, changes: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        allowed = {"status", "owner", "disposition", "notes"}
        updates = {key: value for key, value in changes.items() if key in allowed}
        if not updates:
            return self.get_alert(alert_id)
        parts = [f"{field} = ?" for field in updates]
        values = list(updates.values())
        parts.append("updated_at = ?")
        values.append(utc_now())
        values.append(alert_id)
        with self.connect() as conn:
            conn.execute(
                f"UPDATE alerts SET {', '.join(parts)} WHERE alert_id = ?",
                values,
            )
        return self.get_alert(alert_id)

    def add_suppression(
        self,
        *,
        rule_id: Optional[str],
        dedup_key: Optional[str],
        host_name: Optional[str],
        source_ip: Optional[str],
        user_name: Optional[str],
        reason: str,
        expires_at: Optional[str],
    ) -> Dict[str, Any]:
        created_at = utc_now()
        with self.connect() as conn:
            cursor = conn.execute(
                """
                INSERT INTO suppressions (
                    rule_id, dedup_key, host_name, source_ip, user_name, reason,
                    created_at, expires_at, active
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)
                """,
                (rule_id, dedup_key, host_name, source_ip, user_name, reason, created_at, expires_at),
            )
            suppression_id = cursor.lastrowid
            conn.execute(
                """
                UPDATE alerts
                SET suppressed = 1,
                    status = CASE
                        WHEN status IN ('new', 'investigating', 'escalated') THEN 'suppressed'
                        ELSE status
                    END,
                    updated_at = ?
                WHERE (? IS NULL OR rule_id = ?)
                  AND (? IS NULL OR dedup_key = ?)
                  AND (? IS NULL OR entities_json LIKE ?)
                  AND (? IS NULL OR entities_json LIKE ?)
                  AND (? IS NULL OR entities_json LIKE ?)
                """,
                (
                    utc_now(),
                    rule_id, rule_id,
                    dedup_key, dedup_key,
                    host_name, f'%"{host_name}"%',
                    source_ip, f'%"{source_ip}"%',
                    user_name, f'%"{user_name}"%',
                ),
            )
            row = conn.execute("SELECT * FROM suppressions WHERE id = ?", (suppression_id,)).fetchone()
        assert row is not None
        return self._row_to_suppression(row)

    def delete_suppression(self, suppression_id: int) -> None:
        with self.connect() as conn:
            conn.execute("UPDATE suppressions SET active = 0 WHERE id = ?", (suppression_id,))
        self.refresh_suppression_state()

    def refresh_suppression_state(self) -> None:
        alerts = self.list_alerts(include_suppressed=True)
        now = utc_now()
        with self.connect() as conn:
            for alert in alerts:
                suppressed = 1 if self.suppression_matches(alert) else 0
                status = alert["status"]
                if suppressed:
                    status = "suppressed"
                elif status == "suppressed":
                    status = "new"
                conn.execute(
                    """
                    UPDATE alerts
                    SET suppressed = ?, status = ?, updated_at = ?
                    WHERE alert_id = ?
                    """,
                    (suppressed, status, now, alert["alert_id"]),
                )

    def summary(self, alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
        open_alerts = [alert for alert in alerts if alert.get("status") in OPEN_STATUSES]
        return {
            "generated_at": utc_now(),
            "total_alerts": len(open_alerts),
            "critical_alerts": sum(1 for alert in open_alerts if alert.get("severity") == "critical"),
            "high_alerts": sum(1 for alert in open_alerts if alert.get("severity") == "high"),
            "correlated_alerts": sum(1 for alert in open_alerts if (alert.get("source_count") or 0) > 1),
            "external_ip_alerts": sum(1 for alert in open_alerts if (alert.get("entities", {}).get("source_ips") or [])),
            "suppressed_alerts": sum(1 for alert in self.list_alerts(include_suppressed=True) if alert.get("suppressed")),
        }

    def list_cases(self) -> List[Dict[str, Any]]:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM cases ORDER BY updated_at DESC, created_at DESC"
            ).fetchall()
        return [self._row_to_case(row) for row in rows]

    def get_case(self, case_id: str) -> Optional[Dict[str, Any]]:
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM cases WHERE case_id = ?", (case_id,)).fetchone()
        if not row:
            return None
        case = self._row_to_case(row)
        case["comments"] = self.list_case_comments(case_id)
        case["linked_alert_details"] = [self.get_alert(alert_id) for alert_id in case["linked_alerts"]]
        return case

    def create_case(
        self,
        *,
        title: str,
        summary: str,
        owner: str,
        severity: str,
        alert_ids: List[str],
    ) -> Dict[str, Any]:
        created_at = utc_now()
        case_id = f"CASE-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{abs(hash((title, created_at))) % 100000:05d}"
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO cases (case_id, title, status, severity, owner, summary, created_at, updated_at)
                VALUES (?, ?, 'open', ?, ?, ?, ?, ?)
                """,
                (case_id, title, severity, owner, summary, created_at, created_at),
            )
            for alert_id in alert_ids:
                conn.execute(
                    "INSERT OR IGNORE INTO case_alerts (case_id, alert_id, linked_at) VALUES (?, ?, ?)",
                    (case_id, alert_id, created_at),
                )
        return self.get_case(case_id)

    def update_case(self, case_id: str, changes: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        allowed = {"title", "status", "severity", "owner", "summary"}
        updates = {key: value for key, value in changes.items() if key in allowed}
        if not updates:
            return self.get_case(case_id)
        parts = [f"{field} = ?" for field in updates]
        values = list(updates.values())
        parts.append("updated_at = ?")
        values.append(utc_now())
        values.append(case_id)
        with self.connect() as conn:
            conn.execute(f"UPDATE cases SET {', '.join(parts)} WHERE case_id = ?", values)
        return self.get_case(case_id)

    def list_case_alerts(self, case_id: str) -> List[str]:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT alert_id FROM case_alerts WHERE case_id = ? ORDER BY linked_at ASC",
                (case_id,),
            ).fetchall()
        return [row["alert_id"] for row in rows]

    def add_alerts_to_case(self, case_id: str, alert_ids: List[str]) -> Optional[Dict[str, Any]]:
        linked_at = utc_now()
        with self.connect() as conn:
            for alert_id in alert_ids:
                conn.execute(
                    "INSERT OR IGNORE INTO case_alerts (case_id, alert_id, linked_at) VALUES (?, ?, ?)",
                    (case_id, alert_id, linked_at),
                )
            conn.execute("UPDATE cases SET updated_at = ? WHERE case_id = ?", (linked_at, case_id))
        return self.get_case(case_id)

    def remove_alert_from_case(self, case_id: str, alert_id: str) -> Optional[Dict[str, Any]]:
        with self.connect() as conn:
            conn.execute("DELETE FROM case_alerts WHERE case_id = ? AND alert_id = ?", (case_id, alert_id))
            conn.execute("UPDATE cases SET updated_at = ? WHERE case_id = ?", (utc_now(), case_id))
        return self.get_case(case_id)

    def delete_case(self, case_id: str) -> None:
        with self.connect() as conn:
            conn.execute("DELETE FROM case_comments WHERE case_id = ?", (case_id,))
            conn.execute("DELETE FROM case_alerts WHERE case_id = ?", (case_id,))
            conn.execute("DELETE FROM cases WHERE case_id = ?", (case_id,))

    def add_case_comment(self, case_id: str, author: str, comment: str) -> Optional[Dict[str, Any]]:
        created_at = utc_now()
        with self.connect() as conn:
            conn.execute(
                "INSERT INTO case_comments (case_id, author, comment, created_at) VALUES (?, ?, ?, ?)",
                (case_id, author, comment, created_at),
            )
            conn.execute("UPDATE cases SET updated_at = ? WHERE case_id = ?", (created_at, case_id))
        return self.get_case(case_id)

    def list_case_comments(self, case_id: str) -> List[Dict[str, Any]]:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT author, comment, created_at FROM case_comments WHERE case_id = ? ORDER BY created_at ASC",
                (case_id,),
            ).fetchall()
        return [
            {"author": row["author"], "comment": row["comment"], "created_at": row["created_at"]}
            for row in rows
        ]
