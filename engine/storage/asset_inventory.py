#!/usr/bin/env python3
"""
SQLite-backed asset inventory and vulnerability store for AstroSIEM.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


ENGINE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = ENGINE_DIR / "storage" / "asset-inventory.sqlite"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def json_loads(value: Optional[str], default: Any) -> Any:
    if not value:
        return default
    try:
        return json.loads(value)
    except Exception:
        return default


class AssetInventoryStore:
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

    def _init_db(self):
        with self.connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS assets (
                    host_name TEXT PRIMARY KEY,
                    os_name TEXT,
                    os_version TEXT,
                    kernel_version TEXT,
                    architecture TEXT,
                    primary_ip TEXT,
                    ips_json TEXT NOT NULL DEFAULT '[]',
                    environment TEXT NOT NULL DEFAULT 'unknown',
                    business_criticality TEXT NOT NULL DEFAULT 'medium',
                    owner TEXT NOT NULL DEFAULT '',
                    internet_facing INTEGER NOT NULL DEFAULT 0,
                    inventory_digest TEXT,
                    last_inventory_at TEXT,
                    last_vuln_scan_at TEXT,
                    updated_at TEXT NOT NULL
                )
                """
            )
            self._ensure_columns(
                conn,
                "assets",
                {
                    "inventory_digest": "TEXT",
                    "last_vuln_scan_at": "TEXT",
                },
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS packages (
                    host_name TEXT NOT NULL,
                    package_name TEXT NOT NULL,
                    package_version TEXT NOT NULL,
                    package_manager TEXT,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY (host_name, package_name)
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS vulnerabilities (
                    host_name TEXT NOT NULL,
                    cve_id TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    score REAL,
                    package_name TEXT,
                    package_version TEXT,
                    title TEXT,
                    summary TEXT,
                    fix_version TEXT,
                    published_at TEXT,
                    scanner TEXT,
                    status TEXT NOT NULL DEFAULT 'open',
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY (host_name, cve_id)
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS services (
                    host_name TEXT NOT NULL,
                    service_name TEXT NOT NULL,
                    enabled_state TEXT,
                    active_state TEXT,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY (host_name, service_name)
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS config_checks (
                    host_name TEXT NOT NULL,
                    config_key TEXT NOT NULL,
                    config_value TEXT,
                    source TEXT,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY (host_name, config_key)
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS cve_feeds (
                    source TEXT PRIMARY KEY,
                    last_refreshed TEXT,
                    cve_count INTEGER NOT NULL DEFAULT 0,
                    feed_version TEXT,
                    source_url TEXT,
                    metadata_json TEXT NOT NULL DEFAULT '{}'
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS vuln_correlation (
                    host_name TEXT NOT NULL,
                    cve_id TEXT NOT NULL,
                    package_name TEXT NOT NULL DEFAULT '',
                    package_version TEXT,
                    status TEXT NOT NULL DEFAULT 'open',
                    assigned_to TEXT NOT NULL DEFAULT '',
                    ticket_id TEXT NOT NULL DEFAULT '',
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    resolved_at TEXT,
                    status_reason TEXT,
                    evidence_json TEXT NOT NULL DEFAULT '[]',
                    source TEXT,
                    last_scan_at TEXT,
                    last_inventory_digest TEXT,
                    PRIMARY KEY (host_name, cve_id, package_name)
                )
                """
            )

    def _ensure_columns(
        self, conn: sqlite3.Connection, table: str, columns: Dict[str, str]
    ) -> None:
        existing = {
            row["name"]
            for row in conn.execute(f"PRAGMA table_info({table})").fetchall()
        }
        for name, ddl in columns.items():
            if name not in existing:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {ddl}")

    def replace_asset_snapshot(
        self,
        host_name: str,
        inventory: Dict[str, Any],
        vulnerabilities: Iterable[Dict[str, Any]],
        scan_metadata: Optional[Dict[str, Any]] = None,
    ):
        host_name = host_name or inventory.get("hostname") or "unknown"
        updated_at = utc_now()
        packages = list(inventory.get("packages") or [])
        ips = list(inventory.get("ips") or [])
        services = list(inventory.get("services") or [])
        config_checks = list(inventory.get("config_checks") or [])
        scan_metadata = scan_metadata or {}
        inventory_digest = (
            inventory.get("inventory_digest")
            or scan_metadata.get("inventory_digest")
            or ""
        )
        last_inventory_at = inventory.get("generated_at", updated_at)
        normalized_vulns = [
            self._normalize_vulnerability(item, scan_metadata)
            for item in vulnerabilities
        ]
        last_vuln_scan_at = (
            scan_metadata.get("generated_at")
            or scan_metadata.get("scan_completed_at")
            or scan_metadata.get("timestamp")
            or (updated_at if normalized_vulns else None)
        )
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO assets (
                    host_name, os_name, os_version, kernel_version, architecture, primary_ip,
                    ips_json, environment, business_criticality, owner, internet_facing,
                    inventory_digest, last_inventory_at, last_vuln_scan_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(host_name) DO UPDATE SET
                    os_name = excluded.os_name,
                    os_version = excluded.os_version,
                    kernel_version = excluded.kernel_version,
                    architecture = excluded.architecture,
                    primary_ip = excluded.primary_ip,
                    ips_json = excluded.ips_json,
                    environment = excluded.environment,
                    business_criticality = excluded.business_criticality,
                    owner = excluded.owner,
                    internet_facing = excluded.internet_facing,
                    inventory_digest = excluded.inventory_digest,
                    last_inventory_at = excluded.last_inventory_at,
                    last_vuln_scan_at = excluded.last_vuln_scan_at,
                    updated_at = excluded.updated_at
                """,
                (
                    host_name,
                    inventory.get("os_name", ""),
                    inventory.get("os_version", ""),
                    inventory.get("kernel_version", ""),
                    inventory.get("architecture", ""),
                    inventory.get("primary_ip", ""),
                    json.dumps(ips),
                    inventory.get("environment", "unknown"),
                    inventory.get("business_criticality", "medium"),
                    inventory.get("owner", ""),
                    1 if inventory.get("internet_facing") else 0,
                    inventory_digest,
                    last_inventory_at,
                    last_vuln_scan_at,
                    updated_at,
                ),
            )
            conn.execute("DELETE FROM packages WHERE host_name = ?", (host_name,))
            for package in packages:
                conn.execute(
                    """
                    INSERT INTO packages (host_name, package_name, package_version, package_manager, updated_at)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        host_name,
                        package.get("name", ""),
                        package.get("version", ""),
                        package.get("manager", ""),
                        updated_at,
                    ),
                )

            conn.execute(
                "DELETE FROM vulnerabilities WHERE host_name = ?", (host_name,)
            )
            for vuln in normalized_vulns:
                conn.execute(
                    """
                    INSERT INTO vulnerabilities (
                        host_name, cve_id, severity, score, package_name, package_version,
                        title, summary, fix_version, published_at, scanner, status, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        host_name,
                        vuln.get("cve_id", ""),
                        vuln.get("severity", "unknown"),
                        vuln.get("score"),
                        vuln.get("package_name", ""),
                        vuln.get("package_version", ""),
                        vuln.get("title", ""),
                        vuln.get("summary", ""),
                        vuln.get("fix_version", ""),
                        vuln.get("published_at", ""),
                        vuln.get("scanner", ""),
                        vuln.get("status", "open"),
                        updated_at,
                    ),
                )

            self._sync_vuln_correlation(
                conn,
                host_name,
                normalized_vulns,
                inventory_digest=inventory_digest,
                scan_timestamp=last_vuln_scan_at,
            )

            conn.execute("DELETE FROM services WHERE host_name = ?", (host_name,))
            for service in services:
                conn.execute(
                    """
                    INSERT INTO services (host_name, service_name, enabled_state, active_state, updated_at)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        host_name,
                        service.get("name", ""),
                        service.get("enabled_state", ""),
                        service.get("active_state", ""),
                        updated_at,
                    ),
                )

            conn.execute("DELETE FROM config_checks WHERE host_name = ?", (host_name,))
            for config in config_checks:
                conn.execute(
                    """
                    INSERT INTO config_checks (host_name, config_key, config_value, source, updated_at)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        host_name,
                        config.get("key", ""),
                        str(config.get("value", "")),
                        config.get("source", ""),
                        updated_at,
                    ),
                )

    def _normalize_vulnerability(
        self, vuln: Dict[str, Any], scan_metadata: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        scan_metadata = scan_metadata or {}
        payload = dict(vuln or {})
        payload["cve_id"] = str(
            payload.get("cve_id") or payload.get("id") or payload.get("cve") or ""
        ).strip()
        payload["severity"] = str(payload.get("severity") or "unknown").lower()
        payload["package_name"] = (
            payload.get("package_name") or payload.get("package") or ""
        )
        payload["package_version"] = (
            payload.get("package_version") or payload.get("installed_version") or ""
        )
        payload["scanner"] = (
            payload.get("scanner") or scan_metadata.get("scanner") or "agent_report"
        )
        payload["status"] = str(payload.get("status") or "open").lower()
        return payload

    def _sync_vuln_correlation(
        self,
        conn: sqlite3.Connection,
        host_name: str,
        vulnerabilities: List[Dict[str, Any]],
        inventory_digest: str,
        scan_timestamp: str,
    ) -> None:
        current_keys = set()
        for vuln in vulnerabilities:
            cve_id = str(vuln.get("cve_id") or "").strip()
            package_name = str(vuln.get("package_name") or "")
            if not cve_id:
                continue
            key = (host_name, cve_id, package_name)
            current_keys.add(key)
            existing = conn.execute(
                """
                SELECT first_seen, assigned_to, ticket_id, status
                FROM vuln_correlation
                WHERE host_name = ? AND cve_id = ? AND package_name = ?
                """,
                key,
            ).fetchone()
            first_seen = existing["first_seen"] if existing else scan_timestamp
            assigned_to = existing["assigned_to"] if existing else ""
            ticket_id = existing["ticket_id"] if existing else ""
            preserved_status = (
                existing["status"]
                if existing and existing["status"] in {"in_progress", "false_positive"}
                else "open"
            )
            conn.execute(
                """
                INSERT INTO vuln_correlation (
                    host_name, cve_id, package_name, package_version, status, assigned_to, ticket_id,
                    first_seen, last_seen, resolved_at, status_reason, evidence_json, source,
                    last_scan_at, last_inventory_digest
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(host_name, cve_id, package_name) DO UPDATE SET
                    package_version = excluded.package_version,
                    status = excluded.status,
                    assigned_to = excluded.assigned_to,
                    ticket_id = excluded.ticket_id,
                    last_seen = excluded.last_seen,
                    resolved_at = excluded.resolved_at,
                    status_reason = excluded.status_reason,
                    evidence_json = excluded.evidence_json,
                    source = excluded.source,
                    last_scan_at = excluded.last_scan_at,
                    last_inventory_digest = excluded.last_inventory_digest
                """,
                (
                    host_name,
                    cve_id,
                    package_name,
                    vuln.get("package_version", ""),
                    preserved_status,
                    assigned_to,
                    ticket_id,
                    first_seen,
                    scan_timestamp,
                    None,
                    vuln.get(
                        "status_reason",
                        "Detected in latest vulnerability correlation run.",
                    ),
                    json.dumps(
                        [
                            {
                                "package_name": package_name,
                                "package_version": vuln.get("package_version", ""),
                                "scanner": vuln.get("scanner", ""),
                                "summary": vuln.get("summary", ""),
                            }
                        ]
                    ),
                    vuln.get("scanner", "agent_report"),
                    scan_timestamp,
                    inventory_digest,
                ),
            )

        existing_rows = conn.execute(
            "SELECT host_name, cve_id, package_name, status FROM vuln_correlation WHERE host_name = ?",
            (host_name,),
        ).fetchall()
        for row in existing_rows:
            key = (row["host_name"], row["cve_id"], row["package_name"])
            if key in current_keys:
                continue
            if row["status"] == "false_positive":
                continue
            conn.execute(
                """
                UPDATE vuln_correlation
                SET status = 'fixed',
                    resolved_at = ?,
                    status_reason = ?,
                    last_scan_at = ?,
                    last_inventory_digest = ?
                WHERE host_name = ? AND cve_id = ? AND package_name = ?
                """,
                (
                    scan_timestamp,
                    "Not observed in latest vulnerability correlation run.",
                    scan_timestamp,
                    inventory_digest,
                    row["host_name"],
                    row["cve_id"],
                    row["package_name"],
                ),
            )

    def upsert_cve_feed(
        self,
        source: str,
        *,
        last_refreshed: Optional[str] = None,
        cve_count: int = 0,
        feed_version: str = "",
        source_url: str = "",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO cve_feeds (source, last_refreshed, cve_count, feed_version, source_url, metadata_json)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(source) DO UPDATE SET
                    last_refreshed = excluded.last_refreshed,
                    cve_count = excluded.cve_count,
                    feed_version = excluded.feed_version,
                    source_url = excluded.source_url,
                    metadata_json = excluded.metadata_json
                """,
                (
                    source,
                    last_refreshed or utc_now(),
                    int(cve_count or 0),
                    feed_version,
                    source_url,
                    json.dumps(metadata or {}, sort_keys=True),
                ),
            )

    def list_cve_feeds(self) -> List[Dict[str, Any]]:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT source, last_refreshed, cve_count, feed_version, source_url, metadata_json FROM cve_feeds ORDER BY source ASC"
            ).fetchall()
        return [
            {
                "source": row["source"],
                "last_refreshed": row["last_refreshed"],
                "cve_count": row["cve_count"],
                "feed_version": row["feed_version"],
                "source_url": row["source_url"],
                "metadata": json_loads(row["metadata_json"], {}),
            }
            for row in rows
        ]

    def get_vuln_correlation(self, host_name: str) -> List[Dict[str, Any]]:
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT host_name, cve_id, package_name, package_version, status, assigned_to, ticket_id,
                       first_seen, last_seen, resolved_at, status_reason, evidence_json, source,
                       last_scan_at, last_inventory_digest
                FROM vuln_correlation
                WHERE host_name = ?
                ORDER BY CASE status WHEN 'open' THEN 4 WHEN 'in_progress' THEN 3 WHEN 'fixed' THEN 2 ELSE 1 END DESC,
                         cve_id ASC, package_name ASC
                """,
                (host_name,),
            ).fetchall()
        return [
            {
                "host_name": row["host_name"],
                "cve_id": row["cve_id"],
                "package_name": row["package_name"],
                "package_version": row["package_version"],
                "status": row["status"],
                "assigned_to": row["assigned_to"],
                "ticket_id": row["ticket_id"],
                "first_seen": row["first_seen"],
                "last_seen": row["last_seen"],
                "resolved_at": row["resolved_at"],
                "status_reason": row["status_reason"],
                "evidence": json_loads(row["evidence_json"], []),
                "source": row["source"],
                "last_scan_at": row["last_scan_at"],
                "last_inventory_digest": row["last_inventory_digest"],
            }
            for row in rows
        ]

    def vulnerability_intelligence_summary(self) -> Dict[str, Any]:
        feeds = self.list_cve_feeds()
        with self.connect() as conn:
            counts = conn.execute(
                """
                SELECT status, COUNT(*) AS count
                FROM vuln_correlation
                GROUP BY status
                """
            ).fetchall()
        by_status = {row["status"]: row["count"] for row in counts}

        now = datetime.now(timezone.utc)
        feed_freshness = []
        for feed in feeds:
            last_refreshed = feed.get("last_refreshed")
            freshness_info = {
                "source": feed.get("source"),
                "last_refreshed": last_refreshed,
                "hours_ago": None,
                "status": "unknown",
            }
            if last_refreshed:
                try:
                    refresh_dt = datetime.fromisoformat(
                        last_refreshed.replace("Z", "+00:00")
                    )
                    if refresh_dt.tzinfo is None:
                        refresh_dt = refresh_dt.replace(tzinfo=timezone.utc)
                    hours_ago = (now - refresh_dt).total_seconds() / 3600
                    freshness_info["hours_ago"] = round(hours_ago, 1)
                    if hours_ago < 24:
                        freshness_info["status"] = "fresh"
                    elif hours_ago < 72:
                        freshness_info["status"] = "stale"
                    else:
                        freshness_info["status"] = "outdated"
                except (ValueError, TypeError):
                    pass
            feed_freshness.append(freshness_info)

        return {
            "feeds": feeds,
            "feed_count": len(feeds),
            "feed_freshness": feed_freshness,
            "correlation_status": {
                "open": by_status.get("open", 0),
                "in_progress": by_status.get("in_progress", 0),
                "fixed": by_status.get("fixed", 0),
                "false_positive": by_status.get("false_positive", 0),
            },
        }

    def vulnerability_intel_summary(self) -> Dict[str, Any]:
        return self.vulnerability_intelligence_summary()

    def _posture_status(
        self, vulnerability_summary: Dict[str, int], internet_facing: bool
    ) -> str:
        if vulnerability_summary.get("critical", 0) > 0:
            return "critical"
        if vulnerability_summary.get("high", 0) > 0 and internet_facing:
            return "elevated"
        if (
            vulnerability_summary.get("high", 0) > 0
            or vulnerability_summary.get("medium", 0) > 10
        ):
            return "warning"
        return "normal"

    def _build_asset_summary(self, asset: Dict[str, Any]) -> Dict[str, Any]:
        vulnerabilities = list(asset.get("vulnerabilities") or [])
        vulnerability_summary = {
            "critical": sum(
                1
                for item in vulnerabilities
                if str(item.get("severity", "")).lower() == "critical"
            ),
            "high": sum(
                1
                for item in vulnerabilities
                if str(item.get("severity", "")).lower() == "high"
            ),
            "medium": sum(
                1
                for item in vulnerabilities
                if str(item.get("severity", "")).lower() == "medium"
            ),
            "low": sum(
                1
                for item in vulnerabilities
                if str(item.get("severity", "")).lower() == "low"
            ),
            "open_total": sum(
                1
                for item in vulnerabilities
                if str(item.get("status", "open")).lower() != "fixed"
            ),
        }
        return {
            "package_count": len(asset.get("packages") or []),
            "service_count": len(asset.get("services") or []),
            "config_check_count": len(asset.get("config_checks") or []),
            "vulnerability_summary": vulnerability_summary,
            "posture_status": self._posture_status(
                vulnerability_summary, bool(asset.get("internet_facing"))
            ),
        }

    def list_assets(self) -> List[Dict[str, Any]]:
        with self.connect() as conn:
            assets = conn.execute(
                "SELECT * FROM assets ORDER BY host_name ASC"
            ).fetchall()
        return [self.get_asset(row["host_name"]) for row in assets]

    def list_asset_summaries(self) -> List[Dict[str, Any]]:
        assets = []
        for asset in self.list_assets():
            assets.append(
                {
                    "host_name": asset.get("host_name"),
                    "primary_ip": asset.get("primary_ip"),
                    "os_name": asset.get("os_name"),
                    "os_version": asset.get("os_version"),
                    "kernel_version": asset.get("kernel_version"),
                    "environment": asset.get("environment"),
                    "business_criticality": asset.get("business_criticality"),
                    "owner": asset.get("owner"),
                    "internet_facing": bool(asset.get("internet_facing")),
                    "inventory_digest": asset.get("inventory_digest"),
                    "last_inventory_at": asset.get("last_inventory_at"),
                    "last_vuln_scan_at": asset.get("last_vuln_scan_at"),
                    "updated_at": asset.get("updated_at"),
                    **self._build_asset_summary(asset),
                }
            )
        return assets

    def get_asset(self, host_name: str) -> Dict[str, Any]:
        with self.connect() as conn:
            asset = conn.execute(
                "SELECT * FROM assets WHERE host_name = ?", (host_name,)
            ).fetchone()
            packages = conn.execute(
                "SELECT package_name, package_version, package_manager FROM packages WHERE host_name = ? ORDER BY package_name ASC",
                (host_name,),
            ).fetchall()
            vulnerabilities = conn.execute(
                "SELECT * FROM vulnerabilities WHERE host_name = ? ORDER BY CASE severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 ELSE 1 END DESC, cve_id ASC",
                (host_name,),
            ).fetchall()
            services = conn.execute(
                "SELECT service_name, enabled_state, active_state FROM services WHERE host_name = ? ORDER BY service_name ASC",
                (host_name,),
            ).fetchall()
            config_checks = conn.execute(
                "SELECT config_key, config_value, source FROM config_checks WHERE host_name = ? ORDER BY config_key ASC",
                (host_name,),
            ).fetchall()
        if not asset:
            return {}
        payload = {
            "host_name": asset["host_name"],
            "os_name": asset["os_name"],
            "os_version": asset["os_version"],
            "kernel_version": asset["kernel_version"],
            "architecture": asset["architecture"],
            "primary_ip": asset["primary_ip"],
            "ips": json.loads(asset["ips_json"] or "[]"),
            "environment": asset["environment"],
            "business_criticality": asset["business_criticality"],
            "owner": asset["owner"],
            "internet_facing": bool(asset["internet_facing"]),
            "inventory_digest": asset["inventory_digest"],
            "last_inventory_at": asset["last_inventory_at"],
            "last_vuln_scan_at": asset["last_vuln_scan_at"],
            "updated_at": asset["updated_at"],
            "packages": [
                {
                    "name": row["package_name"],
                    "version": row["package_version"],
                    "manager": row["package_manager"],
                }
                for row in packages
            ],
            "services": [
                {
                    "name": row["service_name"],
                    "enabled_state": row["enabled_state"],
                    "active_state": row["active_state"],
                }
                for row in services
            ],
            "config_checks": [
                {
                    "key": row["config_key"],
                    "value": row["config_value"],
                    "source": row["source"],
                }
                for row in config_checks
            ],
            "vulnerabilities": [dict(row) for row in vulnerabilities],
            "vuln_correlation": self.get_vuln_correlation(host_name),
            "vulnerability_intelligence": self.vulnerability_intelligence_summary(),
        }
        payload.update(self._build_asset_summary(payload))
        return payload

    def summarize(self) -> Dict[str, Any]:
        assets = self.list_asset_summaries()
        vuln_count = sum(
            (asset.get("vulnerability_summary") or {}).get("open_total", 0)
            for asset in assets
        )
        critical_hosts = sum(
            1
            for asset in assets
            if (asset.get("vulnerability_summary") or {}).get("critical", 0) > 0
        )
        return {
            "total_assets": len(assets),
            "internet_facing_assets": sum(
                1 for asset in assets if asset.get("internet_facing")
            ),
            "critical_hosts": critical_hosts,
            "total_vulnerabilities": vuln_count,
            "high_risk_assets": sum(
                1
                for asset in assets
                if asset.get("posture_status") in {"critical", "elevated"}
            ),
            "vulnerability_intelligence": self.vulnerability_intelligence_summary(),
        }

    VALID_VULN_STATUSES = {"open", "in_progress", "fixed", "false_positive"}

    def update_vuln_status(
        self,
        host_name: str,
        cve_id: str,
        status: str,
        reason: str = "",
        package_name: str = "",
    ) -> bool:
        if status not in self.VALID_VULN_STATUSES:
            return False
        updated_at = utc_now()
        resolved_at = updated_at if status == "fixed" else None
        with self.connect() as conn:
            conn.execute(
                """
                UPDATE vuln_correlation
                SET status = ?, status_reason = ?, resolved_at = ?, last_seen = ?
                WHERE host_name = ? AND cve_id = ? AND (package_name = ? OR package_name = '')
                """,
                (
                    status,
                    reason,
                    resolved_at,
                    updated_at,
                    host_name,
                    cve_id,
                    package_name,
                ),
            )
        return True

    def update_vuln_assignment(
        self,
        host_name: str,
        cve_id: str,
        assigned_to: str = "",
        ticket_id: str = "",
        package_name: str = "",
    ) -> bool:
        updated_at = utc_now()
        with self.connect() as conn:
            conn.execute(
                """
                UPDATE vuln_correlation
                SET assigned_to = ?, ticket_id = ?, last_seen = ?
                WHERE host_name = ? AND cve_id = ? AND (package_name = ? OR package_name = '')
                """,
                (assigned_to, ticket_id, updated_at, host_name, cve_id, package_name),
            )
        return True

    def get_all_vulnerabilities(
        self,
        status_filter: str = "",
        host_filter: str = "",
        limit: int = 500,
    ) -> List[Dict[str, Any]]:
        query = """
            SELECT vc.*, v.severity, v.score
            FROM vuln_correlation vc
            LEFT JOIN vulnerabilities v ON vc.host_name = v.host_name AND vc.cve_id = v.cve_id
            WHERE 1=1
        """
        params: List[Any] = []
        if status_filter:
            query += " AND vc.status = ?"
            params.append(status_filter)
        if host_filter:
            query += " AND vc.host_name = ?"
            params.append(host_filter)
        query += " ORDER BY CASE vc.status WHEN 'open' THEN 4 WHEN 'in_progress' THEN 3 WHEN 'fixed' THEN 2 ELSE 1 END DESC, v.score DESC, vc.cve_id ASC LIMIT ?"
        params.append(limit)
        with self.connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [
            {
                "host_name": row["host_name"],
                "cve_id": row["cve_id"],
                "package_name": row["package_name"],
                "package_version": row["package_version"],
                "severity": row["severity"] or "unknown",
                "score": row["score"],
                "status": row["status"],
                "assigned_to": row["assigned_to"],
                "ticket_id": row["ticket_id"],
                "first_seen": row["first_seen"],
                "last_seen": row["last_seen"],
                "resolved_at": row["resolved_at"],
                "status_reason": row["status_reason"],
            }
            for row in rows
        ]

    def bulk_update_vuln_status(
        self,
        host_cve_pairs: List[Dict[str, str]],
        status: str,
        reason: str = "",
    ) -> int:
        if status not in self.VALID_VULN_STATUSES:
            return 0
        updated_at = utc_now()
        resolved_at = updated_at if status == "fixed" else None
        count = 0
        with self.connect() as conn:
            for item in host_cve_pairs:
                host = item.get("host_name", "")
                cve = item.get("cve_id", "")
                pkg = item.get("package_name", "")
                if not host or not cve:
                    continue
                conn.execute(
                    """
                    UPDATE vuln_correlation
                    SET status = ?, status_reason = ?, resolved_at = ?, last_seen = ?
                    WHERE host_name = ? AND cve_id = ? AND (package_name = ? OR package_name = '')
                    """,
                    (status, reason, resolved_at, updated_at, host, cve, pkg),
                )
                count += 1
        return count
