#!/usr/bin/env python3
"""
Run host posture and policy checks similar to Wazuh's SCA and health monitoring.
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List


SCRIPT_DIR = Path(__file__).resolve().parent
ENGINE_DIR = SCRIPT_DIR.parent
if str(ENGINE_DIR) not in sys.path:
    sys.path.insert(0, str(ENGINE_DIR))

from dashboard.server import build_coverage_snapshot
from policy.baselines import evaluate_asset_baseline, load_agent_baselines
from posture.active_response import execute_responses
from storage.asset_inventory import AssetInventoryStore
from storage.posture_state import PostureStateStore


PROCESSED_DIR = ENGINE_DIR / "processed-data"
FIM_FILE = PROCESSED_DIR / "events-fim-processed.json"


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def make_finding(
    host_name: str,
    check_id: str,
    title: str,
    severity: str,
    summary: str,
    recommendation: str,
    rationale: str,
    evidence: List[Dict[str, Any]],
) -> Dict[str, Any]:
    dedup_key = f"{host_name}:{check_id}"
    timestamp = now_iso()
    return {
        "finding_id": f"POSTURE-{abs(hash(dedup_key)) % 100000000:08d}",
        "dedup_key": dedup_key,
        "host_name": host_name,
        "check_id": check_id,
        "title": title,
        "severity": severity,
        "summary": summary,
        "recommendation": recommendation,
        "rationale": rationale,
        "evidence": evidence,
        "first_seen": timestamp,
        "last_seen": timestamp,
    }


def assess_host(host: Dict[str, Any], asset_lookup: Dict[str, Dict[str, Any]], agent_baselines: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
    host_name = host.get("host") or "unknown"
    asset = asset_lookup.get(host_name, {})
    findings: List[Dict[str, Any]] = []
    missing_sources = host.get("missing_sources") or []
    posture_status = asset.get("posture_status") or host.get("posture_status") or "normal"
    vuln_summary = asset.get("vulnerability_summary") or host.get("vulnerability_summary") or {}
    package_names = {pkg.get("name", "").lower() for pkg in (asset.get("packages") or [])}
    service_map = {svc.get("name", ""): svc for svc in (asset.get("services") or [])}
    config_map = {cfg.get("key", ""): str(cfg.get("value", "")) for cfg in (asset.get("config_checks") or [])}

    if host.get("status") == "offline":
        findings.append(
            make_finding(
                host_name,
                "ASTRO-POSTURE-1001",
                "Host offline or missing telemetry",
                "critical",
                f"{host_name} has no recent telemetry in AstroSIEM.",
                "Validate the agent service, network path, and Apache export endpoint. Restore telemetry before trusting this host's security posture.",
                "No recent log sources were observed for this host in the current telemetry window.",
                [{"status": host.get("status"), "coverage_score": host.get("coverage_score", 0)}],
            )
        )
    elif host.get("status") == "stale":
        findings.append(
            make_finding(
                host_name,
                "ASTRO-POSTURE-1002",
                "Host telemetry is stale",
                "high",
                f"{host_name} has not reported fresh telemetry within the expected analysis window.",
                "Investigate delayed collection, stalled cron/systemd jobs, or agent-side failures before triaging this host as healthy.",
                "The host is present but its last seen timestamp has aged beyond the healthy threshold.",
                [{"status": host.get("status"), "last_seen": host.get("last_seen")}],
            )
        )

    critical_sources = {"security", "fim", "network"}
    missing_critical = sorted(critical_sources.intersection(missing_sources))
    if missing_critical:
        severity = "high" if len(missing_critical) >= 2 else "medium"
        findings.append(
            make_finding(
                host_name,
                "ASTRO-POSTURE-1003",
                "Critical telemetry coverage gap",
                severity,
                f"{host_name} is missing required telemetry sources: {', '.join(missing_critical)}.",
                "Enable the missing modules on the agent and verify exports are arriving in the collector pipeline.",
                "Detection confidence drops when security, FIM, or network telemetry is absent.",
                [{"missing_sources": missing_critical, "sources_present": host.get("sources_present", [])}],
            )
        )

    if asset and asset.get("business_criticality") in {"high", "critical"} and asset.get("package_count", 0) == 0:
        findings.append(
            make_finding(
                host_name,
                "ASTRO-POSTURE-1004",
                "Critical asset lacks inventory data",
                "high",
                f"{host_name} is marked as {asset.get('business_criticality')} criticality but has no package inventory in SQLite.",
                "Export host inventory from the agent so analysts can correlate vulnerabilities, installed software, and posture drift.",
                "Critical assets should always have current package and host metadata available for investigations.",
                [{"business_criticality": asset.get("business_criticality"), "package_count": asset.get("package_count", 0)}],
            )
        )

    if posture_status in {"critical", "elevated"}:
        severity = "critical" if posture_status == "critical" else "high"
        summary = f"{host_name} has {vuln_summary.get('critical', 0)} critical and {vuln_summary.get('high', 0)} high open vulnerabilities."
        findings.append(
            make_finding(
                host_name,
                "ASTRO-POSTURE-1005",
                "Host vulnerability posture is elevated",
                severity,
                summary,
                "Patch or isolate the host, then rerun the vulnerability export so alerts and cases reflect the updated posture.",
                "The asset inventory marks this host as elevated due to vulnerability severity and exposure.",
                [{"posture_status": posture_status, "vulnerability_summary": vuln_summary}],
            )
        )

    docker_present = "docker.service" in service_map or "docker" in package_names
    if docker_present and "docker" in missing_sources:
        findings.append(
            make_finding(
                host_name,
                "ASTRO-POSTURE-1006",
                "Docker installed without Docker telemetry",
                "medium",
                f"{host_name} appears to run Docker but AstroSIEM is not receiving Docker telemetry.",
                "Enable the Docker log collector on the agent and validate that container events are exported.",
                "Container runtime visibility is expected when Docker packages are installed.",
                [{"missing_sources": missing_sources}],
            )
        )

    kube_present = "kubelet.service" in service_map or any(name.startswith(("kube", "kubectl")) for name in package_names)
    if kube_present and "kubernetes" in missing_sources:
        findings.append(
            make_finding(
                host_name,
                "ASTRO-POSTURE-1007",
                "Kubernetes packages installed without Kubernetes telemetry",
                "medium",
                f"{host_name} has Kubernetes components installed but no Kubernetes telemetry is reaching AstroSIEM.",
                "Enable Kubernetes audit or pod log export so analyst visibility matches the host runtime footprint.",
                "Kubernetes-capable hosts should contribute Kubernetes telemetry to maintain detection coverage.",
                [{"missing_sources": missing_sources}],
            )
        )

    ssh_present = any(name in service_map for name in {"sshd.service", "ssh.service"}) or any(
        name.startswith("openssh") or name == "ssh" for name in package_names
    )
    if ssh_present and "security" in missing_sources:
        findings.append(
            make_finding(
                host_name,
                "ASTRO-POSTURE-1008",
                "SSH-capable host lacks security telemetry",
                "high",
                f"{host_name} has SSH packages installed but AstroSIEM is missing security/auth telemetry.",
                "Restore auth and security log export so login activity and privilege escalation are visible.",
                "SSH exposure without auth telemetry materially reduces detection coverage.",
                [{"missing_sources": missing_sources, "package_sample": sorted(list(package_names))[:10]}],
            )
        )

    apache_present = any(name in service_map for name in {"apache2.service", "httpd.service"}) or any(
        name.startswith("apache") or name.startswith("httpd") for name in package_names
    )
    if apache_present and "apache" in missing_sources:
        findings.append(
            make_finding(
                host_name,
                "ASTRO-POSTURE-1009",
                "Apache installed without Apache telemetry",
                "medium",
                f"{host_name} appears to run Apache/httpd but Apache logs are not reaching AstroSIEM.",
                "Enable Apache log export to preserve visibility into web exploitation and authentication activity.",
                "Web-facing services should contribute their service logs for detection and investigations.",
                [{"missing_sources": missing_sources}],
            )
        )

    nginx_present = "nginx.service" in service_map or "nginx" in package_names
    if nginx_present and "nginx" in missing_sources:
        findings.append(
            make_finding(
                host_name,
                "ASTRO-POSTURE-1010",
                "Nginx installed without Nginx telemetry",
                "medium",
                f"{host_name} appears to run Nginx but Nginx logs are not reaching AstroSIEM.",
                "Enable Nginx log export to preserve visibility into web requests, attacks, and configuration drift.",
                "Web telemetry coverage is incomplete while Nginx is installed but not reporting.",
                [{"missing_sources": missing_sources}],
            )
        )

    firewall_status = config_map.get("firewall_status", "").lower()
    if firewall_status in {"inactive", "not running", "stopped", "dead"}:
        findings.append(
            make_finding(
                host_name,
                "ASTRO-POSTURE-1011",
                "Host firewall appears disabled",
                "high",
                f"{host_name} reports firewall status '{config_map.get('firewall_status')}'.",
                "Enable and verify host firewall policy so the endpoint enforces a baseline network control layer.",
                "A disabled host firewall weakens baseline hardening and increases exposure to lateral movement and opportunistic attacks.",
                [{"firewall_status": config_map.get("firewall_status"), "source": "config_checks"}],
            )
        )

    if config_map.get("ssh_permit_root_login", "").lower() in {"yes", "prohibit-password"}:
        findings.append(
            make_finding(
                host_name,
                "ASTRO-POSTURE-1012",
                "SSH root login appears enabled",
                "high",
                f"{host_name} reports PermitRootLogin={config_map.get('ssh_permit_root_login')}.",
                "Disable direct root SSH access and require named accounts with privilege escalation.",
                "Allowing direct root SSH access weakens accountability and increases brute-force risk.",
                [{"ssh_permit_root_login": config_map.get("ssh_permit_root_login")}],
            )
        )

    if config_map.get("ssh_password_authentication", "").lower() == "yes":
        findings.append(
            make_finding(
                host_name,
                "ASTRO-POSTURE-1013",
                "SSH password authentication enabled",
                "medium",
                f"{host_name} reports PasswordAuthentication={config_map.get('ssh_password_authentication')}.",
                "Prefer key-based SSH authentication and disable password auth where operationally possible.",
                "Password-based SSH increases the brute-force and credential stuffing attack surface.",
                [{"ssh_password_authentication": config_map.get("ssh_password_authentication")}],
            )
        )

    if config_map.get("docker_socket_present", "").lower() == "true" and "docker" in missing_sources:
        findings.append(
            make_finding(
                host_name,
                "ASTRO-POSTURE-1014",
                "Docker socket present without runtime visibility",
                "high",
                f"{host_name} exposes the Docker socket but AstroSIEM is not receiving Docker telemetry.",
                "Enable Docker telemetry and review access to the Docker socket to reduce blind spots and privilege abuse risk.",
                "The Docker socket is a high-impact control surface and should not be unmanaged.",
                [{"docker_socket_present": True, "missing_sources": missing_sources}],
            )
        )

    policy_eval = evaluate_asset_baseline(host_name, asset or {"host_name": host_name}, agent_baselines)
    for drift in policy_eval.get("policy_drift", {}).get("items", []):
        if drift.get("type") == "service":
            expected = drift.get("expected") or {}
            actual = drift.get("actual") or {}
            findings.append(
                make_finding(
                    host_name,
                    f"ASTRO-POSTURE-POLICY-SVC-{str(drift.get('key')).replace('.', '_').replace('-', '_').upper()}",
                    "Agent service baseline drift",
                    "high" if drift.get("key") in {"sshd.service", "ssh.service", "firewalld.service", "ufw.service"} else "medium",
                    f"{host_name} service {drift.get('key')} does not match the configured policy baseline.",
                    "Reconcile the service state with the agent policy baseline or update the baseline if the change is intentional.",
                    "AstroSIEM compares actual service states against centrally configured expectations for managed agents.",
                    [
                        {
                            "service": drift.get("key"),
                            "expected": expected,
                            "actual": actual,
                            "reason": drift.get("reason"),
                        }
                    ],
                )
            )
        elif drift.get("type") == "config":
            findings.append(
                make_finding(
                    host_name,
                    f"ASTRO-POSTURE-POLICY-CFG-{str(drift.get('key')).replace('.', '_').replace('-', '_').upper()}",
                    "Agent configuration baseline drift",
                    "high" if drift.get("key") in {"ssh_permit_root_login", "firewall_status"} else "medium",
                    f"{host_name} config {drift.get('key')} does not match the configured policy baseline.",
                    "Restore the expected configuration value or update the baseline if this configuration is now intentional.",
                    "AstroSIEM compares collected endpoint configuration checks against centrally managed expected values.",
                    [
                        {
                            "config_key": drift.get("key"),
                            "expected": drift.get("expected"),
                            "actual": drift.get("actual"),
                            "reason": drift.get("reason"),
                        }
                    ],
                )
            )

    return findings


def load_fim_events() -> List[Dict[str, Any]]:
    if not FIM_FILE.exists():
        return []
    try:
        import json

        data = json.loads(FIM_FILE.read_text())
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            return data.get("events", [])
    except Exception:
        return []
    return []


def assess_fim_hardening(fim_events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    sensitive_paths = {
        "/etc/passwd": ("critical", "Account database file changed"),
        "/etc/shadow": ("critical", "Shadow password file changed"),
        "/etc/sudoers": ("high", "Sudo policy file changed"),
        "/etc/ssh/sshd_config": ("high", "SSH daemon configuration changed"),
    }

    for event in fim_events:
        path = event.get("path") or ""
        host_name = event.get("hostname") or "unknown"
        if path in sensitive_paths:
            severity, title = sensitive_paths[path]
            findings.append(
                make_finding(
                    host_name,
                    f"ASTRO-POSTURE-FIM-{path.split('/')[-1].upper()}",
                    title,
                    severity,
                    f"{path} was {event.get('change', 'modified')} on {host_name}.",
                    "Validate whether this change was expected, review the actor and deployment context, and revert or contain if unauthorized.",
                    "Sensitive identity and remote access files changing is a high-signal hardening event.",
                    [{"path": path, "change": event.get("change"), "new": event.get("new"), "old": event.get("old")}],
                )
            )

        new_meta = event.get("new") or {}
        mode = str(new_meta.get("mode") or "")
        if path in {"/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/ssh/sshd_config"} and mode in {"0o666", "0o664", "0o777", "0o776", "0o775", "0o644"}:
            findings.append(
                make_finding(
                    host_name,
                    f"ASTRO-POSTURE-PERM-{path.split('/')[-1].upper()}",
                    "Sensitive file permissions appear too permissive",
                    "critical" if path in {"/etc/shadow", "/etc/sudoers"} else "high",
                    f"{path} on {host_name} now reports mode {mode}.",
                    "Lock down the file permissions immediately and confirm whether the change was malicious or accidental.",
                    "Weak permissions on sensitive system files materially weaken host hardening.",
                    [{"path": path, "mode": mode, "change": event.get("change")}],
                )
            )

    return findings


def main():
    asset_store = AssetInventoryStore()
    posture_store = PostureStateStore()
    coverage = build_coverage_snapshot(asset_store)
    asset_lookup = {asset["host_name"]: asset for asset in asset_store.list_assets() if asset.get("host_name")}
    agent_baselines = load_agent_baselines()
    fim_events = load_fim_events()

    findings: List[Dict[str, Any]] = []
    for host in coverage.get("hosts", []):
        findings.extend(assess_host(host, asset_lookup, agent_baselines))
    findings.extend(assess_fim_hardening(fim_events))

    stored_findings = posture_store.sync_findings(findings)
    executed = execute_responses(stored_findings, posture_store)
    print(
        f"Generated {len(findings)} posture finding(s) across {len(coverage.get('hosts', []))} host(s). "
        f"Executed {len(executed)} active response(s)."
    )


if __name__ == "__main__":
    main()
