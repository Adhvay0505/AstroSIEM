#!/usr/bin/env python3
"""
AstroSIEM dashboard server with alert workflow API.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timedelta, timezone
from functools import partial
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import yaml


ENGINE_DIR = Path(__file__).resolve().parent.parent
PROCESSED_DIR = ENGINE_DIR / "processed-data"
CONFIG_DIR = ENGINE_DIR / "config"
if str(ENGINE_DIR) not in sys.path:
    sys.path.insert(0, str(ENGINE_DIR))

from typing import Any, Dict, List, Optional

from policy.baselines import evaluate_asset_baseline, load_agent_baselines
from storage.alert_state import AlertStateStore
from storage.asset_inventory import AssetInventoryStore
from storage.posture_state import PostureStateStore


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def parse_timestamp(value):
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def load_json(path: Path, default):
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text())
    except Exception:
        return default


def load_processed_events() -> List[Dict[str, Any]]:
    sources = [
        ("security", PROCESSED_DIR / "events-security-processed.json"),
        ("fim", PROCESSED_DIR / "events-fim-processed.json"),
        ("network", PROCESSED_DIR / "events-network-processed.json"),
        ("apache", PROCESSED_DIR / "events-apache-processed.json"),
        ("nginx", PROCESSED_DIR / "events-nginx-processed.json"),
        ("docker", PROCESSED_DIR / "events-docker-processed.json"),
        ("kubernetes", PROCESSED_DIR / "events-kubernetes-processed.json"),
    ]
    events: List[Dict[str, Any]] = []
    for source_name, path in sources:
        payload = load_json(path, [])
        items = payload.get("events", []) if isinstance(payload, dict) else payload
        if not isinstance(items, list):
            continue
        for item in items:
            if not isinstance(item, dict):
                continue
            event = dict(item)
            event["_source"] = source_name
            events.append(event)
    return events


def investigation_event_matches(event: Dict[str, Any], scope: str, value: str) -> bool:
    needle = str(value or "").lower()
    if not needle:
        return False
    if scope == "host":
        return str(event.get("hostname") or "").lower() == needle
    if scope == "source_ip":
        return (
            str(
                event.get("source_ip") or event.get("source", {}).get("ip") or ""
            ).lower()
            == needle
        )
    if scope == "user":
        candidates = [
            event.get("user"),
            event.get("username"),
            event.get("user_name"),
            event.get("message"),
            event.get("description"),
            event.get("raw_log"),
        ]
        haystack = " ".join(str(item or "") for item in candidates).lower()
        return needle in haystack
    return False


def investigation_alert_matches(alert: Dict[str, Any], scope: str, value: str) -> bool:
    needle = str(value or "").lower()
    entities = alert.get("entities") or {}
    if scope == "host":
        return needle in [str(item).lower() for item in entities.get("hosts", [])]
    if scope == "source_ip":
        return needle in [str(item).lower() for item in entities.get("source_ips", [])]
    if scope == "user":
        return needle in [str(item).lower() for item in entities.get("users", [])]
    return False


def investigation_posture_matches(
    finding: Dict[str, Any], scope: str, value: str
) -> bool:
    needle = str(value or "").lower()
    if scope == "host":
        return str(finding.get("host_name") or "").lower() == needle
    if scope == "source_ip":
        return False
    if scope == "user":
        haystack = " ".join(
            [
                str(finding.get("summary") or ""),
                str(finding.get("rationale") or ""),
                json.dumps(finding.get("evidence") or []),
            ]
        ).lower()
        return needle in haystack
    return False


def investigation_case_matches(
    case: Dict[str, Any], related_alert_ids: List[str], scope: str, value: str
) -> bool:
    if any(
        alert_id in set(case.get("linked_alerts") or [])
        for alert_id in related_alert_ids
    ):
        return True
    needle = str(value or "").lower()
    haystack = " ".join(
        [
            str(case.get("title") or ""),
            str(case.get("summary") or ""),
            str(case.get("owner") or ""),
        ]
    ).lower()
    return scope == "user" and needle in haystack


def build_investigation(
    scope: str, value: str, handler: "AstroRequestHandler"
) -> Dict[str, Any]:
    scope = (scope or "host").strip()
    value = (value or "").strip()
    alerts = [
        handler._enrich_alert(alert)
        for alert in handler.store.list_alerts(include_suppressed=True)
    ]
    posture_findings = handler.posture_store.list_findings(include_resolved=True)
    assets = handler._list_assets()
    cases = [handler._enrich_case(case) for case in handler.store.list_cases()]
    events = load_processed_events()

    matched_alerts = [
        alert for alert in alerts if investigation_alert_matches(alert, scope, value)
    ]
    matched_posture = [
        finding
        for finding in posture_findings
        if investigation_posture_matches(finding, scope, value)
    ]
    matched_events = [
        event for event in events if investigation_event_matches(event, scope, value)
    ]
    matched_events.sort(
        key=lambda item: parse_timestamp(item.get("timestamp_utc")) or utc_now(),
        reverse=True,
    )

    if scope == "host":
        matched_asset = next(
            (
                asset
                for asset in assets
                if str(asset.get("host_name")).lower() == value.lower()
            ),
            None,
        )
    else:
        matched_asset = None

    related_alert_ids = [
        alert.get("alert_id") for alert in matched_alerts if alert.get("alert_id")
    ]
    matched_cases = [
        case
        for case in cases
        if investigation_case_matches(case, related_alert_ids, scope, value)
    ]

    recommendations = []
    if matched_alerts:
        recommendations.append(
            f"Start with the top {min(len(matched_alerts), 3)} alert(s) because they already contain correlated evidence."
        )
    if matched_posture:
        recommendations.append(
            "Check posture findings for host health or policy drift before escalating suspicious activity."
        )
    if (
        matched_asset
        and (matched_asset.get("policy_drift") or {}).get("summary", {}).get("total", 0)
        > 0
    ):
        recommendations.append(
            "Review policy drift items to determine whether the activity is tied to recent configuration changes."
        )
    if scope == "source_ip" and matched_events:
        recommendations.append(
            "Pivot on the source IP across web, network, and authentication telemetry to confirm campaign breadth."
        )
    if scope == "user":
        recommendations.append(
            "Verify whether the user appears in alerts, raw events, and cases before treating the activity as malicious."
        )
    if not recommendations:
        recommendations.append(
            "No high-confidence related objects were found. Confirm the investigation key and expand the time scope if needed."
        )

    timeline = []
    for event in matched_events[:50]:
        timeline.append(
            {
                "timestamp_utc": event.get("timestamp_utc"),
                "source": event.get("_source", "-"),
                "host": event.get("hostname"),
                "severity": event.get("severity") or event.get("change") or "-",
                "message": event.get("message")
                or event.get("description")
                or event.get("raw_log")
                or event.get("path")
                or "-",
            }
        )

    return {
        "scope": scope,
        "value": value,
        "summary": {
            "alerts": len(matched_alerts),
            "posture_findings": len(matched_posture),
            "cases": len(matched_cases),
            "events": len(matched_events),
            "has_asset_context": bool(matched_asset),
        },
        "recommendations": recommendations,
        "alerts": matched_alerts[:10],
        "posture_findings": matched_posture[:10],
        "cases": matched_cases[:10],
        "asset": matched_asset,
        "timeline": timeline,
    }


def load_configured_agents() -> Dict[str, Dict[str, Any]]:
    return load_agent_baselines(CONFIG_DIR)


def build_coverage_snapshot(asset_store: Optional[AssetInventoryStore] = None):
    expected_sources = [
        "security",
        "fim",
        "network",
        "apache",
        "nginx",
        "docker",
        "kubernetes",
    ]
    source_files = {
        "security": PROCESSED_DIR / "events-security-processed.json",
        "fim": PROCESSED_DIR / "events-fim-processed.json",
        "network": PROCESSED_DIR / "events-network-processed.json",
        "apache": PROCESSED_DIR / "events-apache-processed.json",
        "nginx": PROCESSED_DIR / "events-nginx-processed.json",
        "docker": PROCESSED_DIR / "events-docker-processed.json",
        "kubernetes": PROCESSED_DIR / "events-kubernetes-processed.json",
    }

    configured_agents = load_configured_agents()
    config_hosts = sorted(configured_agents.keys())

    asset_summaries = {
        item["host_name"]: item
        for item in (asset_store.list_asset_summaries() if asset_store else [])
        if item.get("host_name") in configured_agents
    }

    hosts = {
        name: {"host": name, "sources": set(), "last_seen": None}
        for name in config_hosts
    }
    global_latest = None

    for source, path in source_files.items():
        payload = load_json(path, [])
        events = payload.get("events", []) if isinstance(payload, dict) else payload
        for event in events:
            host_name = event.get("hostname") or "unknown"
            if host_name not in configured_agents:
                continue
            host = hosts.setdefault(
                host_name, {"host": host_name, "sources": set(), "last_seen": None}
            )
            host["sources"].add(source)
            ts = parse_timestamp(event.get("timestamp_utc"))
            if ts and (host["last_seen"] is None or ts > host["last_seen"]):
                host["last_seen"] = ts
            if ts and (global_latest is None or ts > global_latest):
                global_latest = ts

    if global_latest is None:
        global_latest = utc_now()

    host_rows = []
    for host in sorted(hosts.values(), key=lambda item: item["host"]):
        last_seen = host["last_seen"]
        freshness_hours = None
        if last_seen:
            freshness_hours = (global_latest - last_seen).total_seconds() / 3600.0
        if freshness_hours is None:
            status = "offline"
        elif freshness_hours <= 1:
            status = "healthy"
        elif freshness_hours <= 24:
            status = "degraded"
        else:
            status = "stale"
        source_list = sorted(host["sources"])
        coverage_score = (
            int((len(source_list) / len(expected_sources)) * 100)
            if expected_sources
            else 0
        )
        asset = asset_summaries.get(host["host"], {})
        host_rows.append(
            {
                "host": host["host"],
                "status": status,
                "last_seen": last_seen.isoformat() if last_seen else None,
                "coverage_score": coverage_score,
                "sources_present": source_list,
                "missing_sources": [
                    source
                    for source in expected_sources
                    if source not in host["sources"]
                ],
                "environment": asset.get("environment", "unknown"),
                "business_criticality": asset.get("business_criticality", "medium"),
                "internet_facing": bool(asset.get("internet_facing")),
                "owner": asset.get("owner")
                or configured_agents.get(host["host"], {}).get("description", ""),
                "package_count": asset.get("package_count", 0),
                "vulnerability_summary": asset.get("vulnerability_summary", {}),
                "posture_status": asset.get("posture_status", "normal"),
            }
        )

    return {
        "summary": {
            "total_hosts": len(host_rows),
            "healthy_hosts": sum(1 for row in host_rows if row["status"] == "healthy"),
            "degraded_hosts": sum(
                1 for row in host_rows if row["status"] == "degraded"
            ),
            "stale_hosts": sum(1 for row in host_rows if row["status"] == "stale"),
            "offline_hosts": sum(1 for row in host_rows if row["status"] == "offline"),
            "average_coverage": int(
                sum(row["coverage_score"] for row in host_rows) / len(host_rows)
            )
            if host_rows
            else 0,
            "reference_timestamp": global_latest.isoformat() if global_latest else None,
            "hosts_with_inventory": sum(
                1 for row in host_rows if row.get("package_count", 0) > 0
            ),
            "critical_vulnerability_hosts": sum(
                1
                for row in host_rows
                if (row.get("vulnerability_summary") or {}).get("critical", 0) > 0
            ),
        },
        "hosts": host_rows,
    }


def build_asset_risk_summary(asset: dict) -> str:
    vuln_summary = asset.get("vulnerability_summary") or {}
    parts = [
        f"{asset.get('business_criticality', 'medium')} criticality",
        asset.get("environment", "unknown"),
    ]
    if asset.get("internet_facing"):
        parts.append("internet-facing")
    if vuln_summary.get("critical", 0):
        parts.append(f"{vuln_summary['critical']} critical CVE(s)")
    elif vuln_summary.get("high", 0):
        parts.append(f"{vuln_summary['high']} high CVE(s)")
    return ", ".join(parts)


class AstroRequestHandler(SimpleHTTPRequestHandler):
    server_version = "AstroSIEMServer/1.0"

    def __init__(self, *args, directory=None, **kwargs):
        self.store = AlertStateStore()
        self.asset_store = AssetInventoryStore()
        self.posture_store = PostureStateStore()
        super().__init__(*args, directory=directory, **kwargs)

    def end_headers(self):
        self.send_header("Cache-Control", "no-store")
        super().end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/api/alerts":
            self._handle_get_alerts(parsed)
            return
        if parsed.path == "/api/investigate":
            params = parse_qs(parsed.query)
            scope = params.get("scope", ["host"])[0]
            value = params.get("value", [""])[0]
            if not value:
                self._send_json(
                    {"error": "missing_investigation_value"},
                    status=HTTPStatus.BAD_REQUEST,
                )
                return
            self._send_json(build_investigation(scope, value, self))
            return
        if parsed.path == "/api/assets":
            self._send_json(
                {"summary": self._assets_summary(), "assets": self._list_assets()}
            )
            return
        if parsed.path == "/api/posture":
            findings = self.posture_store.list_findings(include_resolved=True)
            self._send_json(
                {"summary": self.posture_store.summary(findings), "findings": findings}
            )
            return
        if parsed.path.startswith("/api/assets/"):
            host_name = parsed.path.rsplit("/", 1)[-1]
            asset = self.asset_store.get_asset(host_name) or self._fallback_asset(
                host_name
            )
            if not asset:
                self._send_json(
                    {"error": "asset_not_found"}, status=HTTPStatus.NOT_FOUND
                )
                return
            asset = dict(asset)
            asset.update(
                evaluate_asset_baseline(host_name, asset, load_configured_agents())
            )
            self._send_json({"asset": asset})
            return
        if parsed.path == "/api/cases":
            self._send_json(
                {"cases": [self._enrich_case(case) for case in self.store.list_cases()]}
            )
            return
        if parsed.path.startswith("/api/cases/"):
            case_id = parsed.path.rsplit("/", 1)[-1]
            case = self.store.get_case(case_id)
            if not case:
                self._send_json(
                    {"error": "case_not_found"}, status=HTTPStatus.NOT_FOUND
                )
                return
            self._send_json({"case": self._enrich_case(case)})
            return
        if parsed.path == "/api/suppressions":
            self._handle_get_suppressions()
            return
        if parsed.path == "/api/coverage":
            self._send_json(build_coverage_snapshot(self.asset_store))
            return
        if parsed.path == "/api/vulnerabilities":
            params = parse_qs(parsed.query)
            status_filter = params.get("status", [""])[0]
            host_filter = params.get("host", [""])[0]
            vulns = self.asset_store.get_all_vulnerabilities(
                status_filter=status_filter,
                host_filter=host_filter,
            )
            vuln_intel = self.asset_store.vulnerability_intelligence_summary()
            self._send_json(
                {
                    "vulnerabilities": vulns,
                    "summary": vuln_intel,
                }
            )
            return
        if parsed.path == "/api/feeds":
            feeds = self.asset_store.list_cve_feeds()
            self._send_json({"feeds": feeds})
            return
        super().do_GET()

    def do_PATCH(self):
        parsed = urlparse(self.path)
        if parsed.path.startswith("/api/alerts/"):
            alert_id = parsed.path.rsplit("/", 1)[-1]
            body = self._read_json_body()
            updated = self.store.update_alert(alert_id, body)
            if not updated:
                self._send_json(
                    {"error": "alert_not_found"}, status=HTTPStatus.NOT_FOUND
                )
                return
            self._send_json({"alert": self._enrich_alert(updated)})
            return
        if parsed.path.startswith("/api/cases/"):
            case_id = parsed.path.rsplit("/", 1)[-1]
            body = self._read_json_body()
            updated = self.store.update_case(case_id, body)
            if not updated:
                self._send_json(
                    {"error": "case_not_found"}, status=HTTPStatus.NOT_FOUND
                )
                return
            self._send_json({"case": self._enrich_case(updated)})
            return
        self._send_json({"error": "not_found"}, status=HTTPStatus.NOT_FOUND)

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path == "/api/cases":
            body = self._read_json_body()
            case = self.store.create_case(
                title=(body.get("title") or "Untitled case").strip(),
                summary=(body.get("summary") or "").strip(),
                owner=(body.get("owner") or "").strip(),
                severity=(body.get("severity") or "medium").strip(),
                alert_ids=list(body.get("alert_ids") or []),
            )
            self._send_json(
                {"case": self._enrich_case(case)}, status=HTTPStatus.CREATED
            )
            return
        if parsed.path.startswith("/api/cases/") and parsed.path.endswith("/alerts"):
            case_id = parsed.path.split("/")[-2]
            body = self._read_json_body()
            case = self.store.add_alerts_to_case(
                case_id, list(body.get("alert_ids") or [])
            )
            if not case:
                self._send_json(
                    {"error": "case_not_found"}, status=HTTPStatus.NOT_FOUND
                )
                return
            self._send_json({"case": self._enrich_case(case)})
            return
        if parsed.path.startswith("/api/cases/") and parsed.path.endswith("/comments"):
            case_id = parsed.path.split("/")[-2]
            body = self._read_json_body()
            case = self.store.add_case_comment(
                case_id,
                (body.get("author") or "").strip(),
                (body.get("comment") or "").strip(),
            )
            if not case:
                self._send_json(
                    {"error": "case_not_found"}, status=HTTPStatus.NOT_FOUND
                )
                return
            self._send_json(
                {"case": self._enrich_case(case)}, status=HTTPStatus.CREATED
            )
            return
        if parsed.path == "/api/suppressions":
            body = self._read_json_body()
            duration_hours = int(body.get("duration_hours", 24))
            expires_at = (utc_now() + timedelta(hours=duration_hours)).isoformat()
            suppression = self.store.add_suppression(
                rule_id=body.get("rule_id") or None,
                dedup_key=body.get("dedup_key") or None,
                host_name=body.get("host_name") or None,
                source_ip=body.get("source_ip") or None,
                user_name=body.get("user_name") or None,
                reason=(body.get("reason") or "Suppressed via dashboard").strip(),
                expires_at=expires_at,
            )
            self._send_json({"suppression": suppression}, status=HTTPStatus.CREATED)
            return
        if parsed.path == "/api/vulnerabilities/assign":
            body = self._read_json_body()
            pairs = body.get("vulnerabilities", [])
            assigned_to = (body.get("assigned_to") or "").strip()
            ticket_id = (body.get("ticket_id") or "").strip()
            if not pairs or not assigned_to:
                self._send_json(
                    {"error": "missing_required_fields"}, status=HTTPStatus.BAD_REQUEST
                )
                return
            count = 0
            for item in pairs:
                host = item.get("host_name", "")
                cve = item.get("cve_id", "")
                pkg = item.get("package_name", "")
                if host and cve:
                    self.asset_store.update_vuln_assignment(
                        host, cve, assigned_to, ticket_id, pkg
                    )
                    count += 1
            self._send_json({"updated": count})
            return
        if parsed.path == "/api/vulnerabilities/status":
            body = self._read_json_body()
            pairs = body.get("vulnerabilities", [])
            status = (body.get("status") or "").strip()
            reason = (body.get("reason") or "").strip()
            if not pairs or status not in {
                "open",
                "in_progress",
                "fixed",
                "false_positive",
            }:
                self._send_json(
                    {"error": "invalid_status_or_missing_vulnerabilities"},
                    status=HTTPStatus.BAD_REQUEST,
                )
                return
            count = 0
            for item in pairs:
                host = item.get("host_name", "")
                cve = item.get("cve_id", "")
                pkg = item.get("package_name", "")
                if host and cve:
                    self.asset_store.update_vuln_status(host, cve, status, reason, pkg)
                    count += 1
            self._send_json({"updated": count})
            return
        if parsed.path == "/api/vulnerabilities/bulk-status":
            body = self._read_json_body()
            host_cve_pairs = body.get("vulnerabilities", [])
            status = (body.get("status") or "").strip()
            reason = (body.get("reason") or "").strip()
            if not host_cve_pairs or status not in {
                "open",
                "in_progress",
                "fixed",
                "false_positive",
            }:
                self._send_json(
                    {"error": "invalid_status_or_missing_vulnerabilities"},
                    status=HTTPStatus.BAD_REQUEST,
                )
                return
            count = self.asset_store.bulk_update_vuln_status(
                host_cve_pairs, status, reason
            )
            self._send_json({"updated": count})
            return
        self._send_json({"error": "not_found"}, status=HTTPStatus.NOT_FOUND)

    def do_DELETE(self):
        parsed = urlparse(self.path)
        if parsed.path.startswith("/api/cases/") and "/alerts/" not in parsed.path:
            case_id = parsed.path.rsplit("/", 1)[-1]
            self.store.delete_case(case_id)
            self._send_json({"deleted": case_id})
            return
        if parsed.path.startswith("/api/cases/") and "/alerts/" in parsed.path:
            parts = parsed.path.split("/")
            case_id = parts[-3]
            alert_id = parts[-1]
            case = self.store.remove_alert_from_case(case_id, alert_id)
            if not case:
                self._send_json(
                    {"error": "case_not_found"}, status=HTTPStatus.NOT_FOUND
                )
                return
            self._send_json({"case": self._enrich_case(case)})
            return
        if parsed.path.startswith("/api/suppressions/"):
            suppression_id = int(parsed.path.rsplit("/", 1)[-1])
            self.store.delete_suppression(suppression_id)
            self._send_json({"deleted": suppression_id})
            return
        self._send_json({"error": "not_found"}, status=HTTPStatus.NOT_FOUND)

    def _handle_get_alerts(self, parsed) -> None:
        params = parse_qs(parsed.query)
        include_suppressed = params.get("include_suppressed", ["0"])[0] == "1"
        alerts = self.store.list_alerts(include_suppressed=include_suppressed)
        self._send_json(
            {
                "summary": self.store.summary(alerts),
                "alerts": [self._enrich_alert(alert) for alert in alerts],
            }
        )

    def _handle_get_suppressions(self) -> None:
        self._send_json({"suppressions": self.store.list_active_suppressions()})

    def _fallback_asset(self, host_name):
        agents = load_configured_agents()
        for host in build_coverage_snapshot(self.asset_store).get("hosts", []):
            if host.get("host") != host_name:
                continue
            payload = {
                "host_name": host_name,
                "os_name": "Unknown",
                "os_version": "",
                "kernel_version": "",
                "architecture": "",
                "primary_ip": "",
                "ips": [],
                "environment": host.get("environment", "unknown"),
                "business_criticality": host.get("business_criticality", "medium"),
                "owner": host.get("owner", ""),
                "internet_facing": bool(host.get("internet_facing")),
                "inventory_digest": None,
                "last_inventory_at": None,
                "last_vuln_scan_at": None,
                "updated_at": None,
                "packages": [],
                "services": [],
                "config_checks": [],
                "vulnerabilities": [],
                "vuln_correlation": [],
                "package_count": 0,
                "service_count": 0,
                "config_check_count": 0,
                "vulnerability_summary": host.get(
                    "vulnerability_summary",
                    {"critical": 0, "high": 0, "medium": 0, "low": 0, "open_total": 0},
                ),
                "posture_status": host.get("posture_status", "normal"),
                "vulnerability_intelligence": self.asset_store.vulnerability_intelligence_summary(),
            }
            payload.update(evaluate_asset_baseline(host_name, payload, agents))
            return payload
        return {}

    def _list_assets(self):
        configured_agents = load_configured_agents()
        host_names = set(configured_agents)
        for host in build_coverage_snapshot(self.asset_store).get("hosts", []):
            host_names.add(host.get("host"))
        assets = []
        for host_name in host_names:
            full_asset = self.asset_store.get_asset(host_name)
            if full_asset:
                payload = dict(full_asset)
                payload.update(
                    evaluate_asset_baseline(host_name, payload, configured_agents)
                )
                assets.append(payload)
            else:
                fallback = self._fallback_asset(host_name)
                if fallback:
                    assets.append(fallback)
        return sorted(assets, key=lambda item: item.get("host_name", ""))

    def _assets_summary(self):
        assets = self._list_assets()
        vuln_intel = self.asset_store.vulnerability_intelligence_summary()
        return {
            "total_assets": len(assets),
            "internet_facing_assets": sum(
                1 for item in assets if item.get("internet_facing")
            ),
            "critical_hosts": sum(
                1
                for item in assets
                if (item.get("vulnerability_summary") or {}).get("critical", 0) > 0
            ),
            "total_vulnerabilities": sum(
                (item.get("vulnerability_summary") or {}).get("open_total", 0)
                for item in assets
            ),
            "high_risk_assets": sum(
                1
                for item in assets
                if item.get("posture_status") in {"critical", "elevated"}
            ),
            "drifted_assets": sum(
                1
                for item in assets
                if (
                    (item.get("policy_drift") or {}).get("summary", {}).get("total", 0)
                    > 0
                )
            ),
            "vulnerability_intelligence": vuln_intel,
        }

    def _alert_asset_contexts(self, alert):
        contexts = []
        for host_name in (alert.get("entities", {}) or {}).get("hosts", []):
            asset = self.asset_store.get_asset(host_name) or self._fallback_asset(
                host_name
            )
            if not asset:
                continue
            contexts.append(
                {
                    "host_name": asset.get("host_name"),
                    "primary_ip": asset.get("primary_ip"),
                    "environment": asset.get("environment"),
                    "business_criticality": asset.get("business_criticality"),
                    "owner": asset.get("owner"),
                    "internet_facing": asset.get("internet_facing"),
                    "package_count": asset.get("package_count", 0),
                    "posture_status": asset.get("posture_status", "normal"),
                    "vulnerability_summary": asset.get("vulnerability_summary", {}),
                    "risk_summary": build_asset_risk_summary(asset),
                }
            )
        return contexts

    def _enrich_alert(self, alert):
        enriched = dict(alert)
        asset_contexts = self._alert_asset_contexts(alert)
        enriched["asset_contexts"] = asset_contexts
        enriched["primary_asset_context"] = (
            asset_contexts[0] if asset_contexts else None
        )
        enriched["asset_risk_summary"] = (
            asset_contexts[0]["risk_summary"] if asset_contexts else ""
        )
        return enriched

    def _enrich_case(self, case):
        enriched = dict(case)
        linked_alert_details = [
            self._enrich_alert(alert)
            for alert in (case.get("linked_alert_details") or [])
            if alert
        ]
        if linked_alert_details:
            enriched["linked_alert_details"] = linked_alert_details
        enriched["asset_scope"] = sorted(
            {
                ctx.get("host_name")
                for alert in linked_alert_details
                for ctx in (alert.get("asset_contexts") or [])
                if ctx.get("host_name")
            }
        )
        return enriched

    def _read_json_body(self):
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0:
            return {}
        raw = self.rfile.read(length)
        if not raw:
            return {}
        return json.loads(raw.decode("utf-8"))

    def _send_json(self, payload, status=HTTPStatus.OK):
        data = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def main():
    parser = argparse.ArgumentParser(description="AstroSIEM dashboard server")
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--root", default=str(ENGINE_DIR))
    args = parser.parse_args()

    root = Path(args.root).resolve()
    handler = partial(AstroRequestHandler, directory=str(root))
    with ThreadingHTTPServer((args.bind, args.port), handler) as httpd:
        print(
            f"Serving AstroSIEM on http://{args.bind}:{args.port}/dashboard/login.html"
        )
        httpd.serve_forever()


if __name__ == "__main__":
    main()
