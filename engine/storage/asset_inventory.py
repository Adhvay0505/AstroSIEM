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
from typing import Any, Dict, Iterable, List


ENGINE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = ENGINE_DIR / "storage" / "asset-inventory.sqlite"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


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
                    last_inventory_at TEXT,
                    updated_at TEXT NOT NULL
                )
                """
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

    def replace_asset_snapshot(self, host_name: str, inventory: Dict[str, Any], vulnerabilities: Iterable[Dict[str, Any]]):
        host_name = host_name or inventory.get("hostname") or "unknown"
        updated_at = utc_now()
        packages = list(inventory.get("packages") or [])
        ips = list(inventory.get("ips") or [])
        services = list(inventory.get("services") or [])
        config_checks = list(inventory.get("config_checks") or [])
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO assets (
                    host_name, os_name, os_version, kernel_version, architecture, primary_ip,
                    ips_json, environment, business_criticality, owner, internet_facing,
                    last_inventory_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                    last_inventory_at = excluded.last_inventory_at,
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
                    inventory.get("generated_at", updated_at),
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

            conn.execute("DELETE FROM vulnerabilities WHERE host_name = ?", (host_name,))
            for vuln in vulnerabilities:
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

    def _posture_status(self, vulnerability_summary: Dict[str, int], internet_facing: bool) -> str:
        if vulnerability_summary.get("critical", 0) > 0:
            return "critical"
        if vulnerability_summary.get("high", 0) > 0 and internet_facing:
            return "elevated"
        if vulnerability_summary.get("high", 0) > 0 or vulnerability_summary.get("medium", 0) > 10:
            return "warning"
        return "normal"

    def _build_asset_summary(self, asset: Dict[str, Any]) -> Dict[str, Any]:
        vulnerabilities = list(asset.get("vulnerabilities") or [])
        vulnerability_summary = {
            "critical": sum(1 for item in vulnerabilities if str(item.get("severity", "")).lower() == "critical"),
            "high": sum(1 for item in vulnerabilities if str(item.get("severity", "")).lower() == "high"),
            "medium": sum(1 for item in vulnerabilities if str(item.get("severity", "")).lower() == "medium"),
            "low": sum(1 for item in vulnerabilities if str(item.get("severity", "")).lower() == "low"),
            "open_total": sum(1 for item in vulnerabilities if str(item.get("status", "open")).lower() != "fixed"),
        }
        return {
            "package_count": len(asset.get("packages") or []),
            "service_count": len(asset.get("services") or []),
            "config_check_count": len(asset.get("config_checks") or []),
            "vulnerability_summary": vulnerability_summary,
            "posture_status": self._posture_status(vulnerability_summary, bool(asset.get("internet_facing"))),
        }

    def list_assets(self) -> List[Dict[str, Any]]:
        with self.connect() as conn:
            assets = conn.execute("SELECT * FROM assets ORDER BY host_name ASC").fetchall()
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
                    "last_inventory_at": asset.get("last_inventory_at"),
                    "updated_at": asset.get("updated_at"),
                    **self._build_asset_summary(asset),
                }
            )
        return assets

    def get_asset(self, host_name: str) -> Dict[str, Any]:
        with self.connect() as conn:
            asset = conn.execute("SELECT * FROM assets WHERE host_name = ?", (host_name,)).fetchone()
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
            "last_inventory_at": asset["last_inventory_at"],
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
            "vulnerabilities": [
                dict(row)
                for row in vulnerabilities
            ],
        }
        payload.update(self._build_asset_summary(payload))
        return payload

    def summarize(self) -> Dict[str, Any]:
        assets = self.list_asset_summaries()
        vuln_count = sum((asset.get("vulnerability_summary") or {}).get("open_total", 0) for asset in assets)
        critical_hosts = sum(1 for asset in assets if (asset.get("vulnerability_summary") or {}).get("critical", 0) > 0)
        return {
            "total_assets": len(assets),
            "internet_facing_assets": sum(1 for asset in assets if asset.get("internet_facing")),
            "critical_hosts": critical_hosts,
            "total_vulnerabilities": vuln_count,
            "high_risk_assets": sum(1 for asset in assets if asset.get("posture_status") in {"critical", "elevated"}),
        }
