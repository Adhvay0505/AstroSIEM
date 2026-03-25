#!/usr/bin/env python3
"""
Risk engine for AstroSIEM.

Calculates and manages entity risk scores based on alerts, vulnerabilities,
and asset context.
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

SCRIPT_DIR = Path(__file__).resolve().parent
ENGINE_DIR = SCRIPT_DIR.parent
if str(ENGINE_DIR) not in sys.path:
    sys.path.insert(0, str(ENGINE_DIR))

from storage.risk_scores import RiskScoreStore
from storage.asset_inventory import AssetInventoryStore


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


SEVERITY_RISK_BOOST = {
    "critical": 20,
    "high": 12,
    "medium": 6,
    "low": 3,
    "info": 1,
}

VULNERABILITY_RISK_BOOST = {
    "critical": 15,
    "high": 8,
    "medium": 3,
    "low": 1,
}

CRITICALITY_MULTIPLIER = {
    "critical": 1.5,
    "high": 1.2,
    "medium": 1.0,
    "low": 0.8,
}


class RiskEngine:
    def __init__(self):
        self.risk_store = RiskScoreStore()
        self.asset_store = AssetInventoryStore()

    def calculate_host_risk_from_alert(
        self,
        host_name: str,
        alert_severity: str,
        alert_rule_id: str,
        alert_id: str = "",
    ) -> Dict[str, Any]:
        asset = self.asset_store.get_asset(host_name)

        base_risk = SEVERITY_RISK_BOOST.get(alert_severity.lower(), 5)

        criticality = asset.get("business_criticality", "medium") if asset else "medium"
        multiplier = CRITICALITY_MULTIPLIER.get(criticality, 1.0)

        if asset and asset.get("internet_facing"):
            multiplier *= 1.3

        risk_delta = round(base_risk * multiplier, 1)

        factors = []
        factors.append(f"Alert: {alert_rule_id} ({alert_severity})")

        if asset:
            if asset.get("internet_facing"):
                factors.append("Internet-facing asset")
            factors.append(f"Business criticality: {criticality}")

            vuln_summary = asset.get("vulnerability_summary") or {}
            critical_vulns = vuln_summary.get("critical", 0)
            high_vulns = vuln_summary.get("high", 0)
            if critical_vulns:
                factors.append(f"{critical_vulns} critical CVE(s)")
                risk_delta += critical_vulns * 2
            if high_vulns:
                factors.append(f"{high_vulns} high CVE(s)")
                risk_delta += high_vulns

        risk_delta = min(50, risk_delta)

        result = self.risk_store.add_risk(
            entity_type="host",
            entity_id=host_name,
            risk_delta=risk_delta,
            factor_type="alert",
            factor_detail=f"{alert_rule_id} ({alert_severity})",
            alert_id=alert_id,
        )

        return result

    def calculate_host_risk_from_vulnerability(
        self,
        host_name: str,
        cve_id: str,
        severity: str,
        cvss_score: float = 0,
    ) -> Dict[str, Any]:
        asset = self.asset_store.get_asset(host_name)

        base_risk = VULNERABILITY_RISK_BOOST.get(severity.lower(), 3)

        if cvss_score >= 9.0:
            base_risk = 25
        elif cvss_score >= 7.0:
            base_risk = 15

        criticality = asset.get("business_criticality", "medium") if asset else "medium"
        multiplier = CRITICALITY_MULTIPLIER.get(criticality, 1.0)

        if asset and asset.get("internet_facing"):
            multiplier *= 1.3

        risk_delta = round(base_risk * multiplier, 1)

        result = self.risk_store.add_risk(
            entity_type="host",
            entity_id=host_name,
            risk_delta=risk_delta,
            factor_type="vulnerability",
            factor_detail=f"{cve_id} ({severity}, CVSS {cvss_score})",
        )

        return result

    def calculate_user_risk(
        self,
        user_name: str,
        alert_severity: str,
        alert_rule_id: str,
        alert_id: str = "",
    ) -> Dict[str, Any]:
        base_risk = SEVERITY_RISK_BOOST.get(alert_severity.lower(), 5)

        risk_delta = base_risk

        result = self.risk_store.add_risk(
            entity_type="user",
            entity_id=user_name,
            risk_delta=risk_delta,
            factor_type="alert",
            factor_detail=f"{alert_rule_id} ({alert_severity})",
            alert_id=alert_id,
        )

        return result

    def calculate_ip_risk(
        self,
        ip_address: str,
        alert_severity: str,
        alert_rule_id: str,
        alert_id: str = "",
    ) -> Dict[str, Any]:
        from ipaddress import ip_address as ip_check

        try:
            is_private = ip_check(ip_address).is_private
        except ValueError:
            is_private = False

        base_risk = SEVERITY_RISK_BOOST.get(alert_severity.lower(), 5)

        if not is_private:
            base_risk *= 1.5

        risk_delta = round(base_risk, 1)

        result = self.risk_store.add_risk(
            entity_type="ip",
            entity_id=ip_address,
            risk_delta=risk_delta,
            factor_type="alert",
            factor_detail=f"{alert_rule_id} ({alert_severity}, {'external' if not is_private else 'internal'})",
            alert_id=alert_id,
        )

        return result

    def recalculate_all_host_risks(self) -> Dict[str, Any]:
        assets = self.asset_store.list_assets()

        results = {
            "hosts_processed": 0,
            "risks_updated": 0,
            "errors": [],
        }

        for asset in assets:
            host_name = asset.get("host_name")
            if not host_name:
                continue

            results["hosts_processed"] += 1

            try:
                current_risk = self.risk_store.get_entity_risk("host", host_name)
                current_score = current_risk["risk_score"] if current_risk else 0

                new_score = 0
                factors = []

                criticality = asset.get("business_criticality", "medium")
                if criticality == "critical":
                    new_score += 12
                    factors.append("Critical business criticality")
                elif criticality == "high":
                    new_score += 8
                    factors.append("High business criticality")

                if asset.get("internet_facing"):
                    new_score += 10
                    factors.append("Internet-facing")

                vuln_summary = asset.get("vulnerability_summary") or {}
                critical_vulns = vuln_summary.get("critical", 0)
                high_vulns = vuln_summary.get("high", 0)
                medium_vulns = vuln_summary.get("medium", 0)

                if critical_vulns:
                    new_score += critical_vulns * 15
                    factors.append(f"{critical_vulns} critical CVE(s)")
                if high_vulns:
                    new_score += high_vulns * 8
                    factors.append(f"{high_vulns} high CVE(s)")
                if medium_vulns:
                    new_score += medium_vulns * 3
                    factors.append(f"{medium_vulns} medium CVE(s)")

                new_score = min(100, new_score)

                if new_score != current_score or new_score > 0:
                    self.risk_store.set_risk(
                        entity_type="host",
                        entity_id=host_name,
                        risk_score=new_score,
                        risk_factors=[
                            {"type": "recalculation", "detail": f} for f in factors
                        ],
                    )
                    results["risks_updated"] += 1

            except Exception as e:
                results["errors"].append(f"{host_name}: {str(e)}")

        return results

    def get_host_risk_summary(self, host_name: str) -> Dict[str, Any]:
        risk = self.risk_store.get_entity_risk("host", host_name)
        asset = self.asset_store.get_asset(host_name)

        if not risk:
            return {
                "host_name": host_name,
                "risk_score": 0,
                "risk_level": "low",
                "risk_factors": [],
                "vulnerability_context": {},
                "asset_context": {},
            }

        score = risk["risk_score"]
        if score >= 70:
            level = "critical"
        elif score >= 50:
            level = "high"
        elif score >= 30:
            level = "medium"
        else:
            level = "low"

        return {
            "host_name": host_name,
            "risk_score": score,
            "risk_level": level,
            "risk_factors": risk.get("risk_factors", []),
            "alert_count": risk.get("alert_count", 0),
            "last_updated": risk.get("last_updated"),
            "vulnerability_context": asset.get("vulnerability_summary", {})
            if asset
            else {},
            "asset_context": {
                "business_criticality": asset.get("business_criticality", "medium")
                if asset
                else "medium",
                "internet_facing": asset.get("internet_facing", False)
                if asset
                else False,
                "environment": asset.get("environment", "unknown")
                if asset
                else "unknown",
            },
        }

    def auto_escalate_critical_vulnerabilities(self) -> Dict[str, Any]:
        assets = self.asset_store.list_assets()

        escalated = []

        for asset in assets:
            host_name = asset.get("host_name")
            vuln_summary = asset.get("vulnerability_summary", {})
            critical_count = vuln_summary.get("critical", 0)
            high_count = vuln_summary.get("high", 0)

            if critical_count > 0:
                risk = self.calculate_host_risk_from_vulnerability(
                    host_name=host_name,
                    cve_id="CRITICAL_VULN_BATCH",
                    severity="critical",
                    cvss_score=10.0,
                )
                escalated.append(
                    {
                        "host": host_name,
                        "severity": "critical",
                        "count": critical_count,
                        "new_risk_score": risk.get("risk_score", 0),
                    }
                )

        return {
            "total_escalated": len(escalated),
            "escalations": escalated,
        }


def main():
    import json

    engine = RiskEngine()

    action = sys.argv[1] if len(sys.argv) > 1 else "recalculate"

    if action == "recalculate":
        result = engine.recalculate_all_host_risks()
        print(json.dumps(result, indent=2))
    elif action == "escalate":
        result = engine.auto_escalate_critical_vulnerabilities()
        print(json.dumps(result, indent=2))
    elif action == "summary":
        store = RiskScoreStore()
        print(json.dumps(store.summarize(), indent=2))
    else:
        print(f"Unknown action: {action}")
        print("Usage: risk_engine.py [recalculate|escalate|summary]")


if __name__ == "__main__":
    main()
