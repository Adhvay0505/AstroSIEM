#!/usr/bin/env python3
"""
AstroSIEM Kubernetes Log Parser
Parses Kubernetes audit, pod, and component logs, maps to MITRE techniques and compliance frameworks
"""

import os
import re
import json
import yaml
from datetime import datetime
from pathlib import Path
from collections import defaultdict

SCRIPT_DIR = Path(__file__).parent.resolve()
ENGINE_DIR = SCRIPT_DIR.parent

LOG_DIR = ENGINE_DIR / "incoming-logs"
OUTPUT_FILE = ENGINE_DIR / "processed-data" / "events-kubernetes-processed.json"
MAPPING_FILE = ENGINE_DIR / "config" / "kubernetes-mapping.yaml"

LOG_DIR = str(LOG_DIR)
OUTPUT_FILE = str(OUTPUT_FILE)
MAPPING_FILE = str(MAPPING_FILE)


def load_mapping():
    """Load Kubernetes log patterns and compliance mappings"""
    try:
        with open(MAPPING_FILE, "r") as f:
            return yaml.safe_load(f)
    except Exception as e:
        print(f"Warning: Could not load Kubernetes mapping: {e}")
        return {
            "audit_patterns": [],
            "component_patterns": [],
            "pod_patterns": [],
            "compliance_mapping": {},
        }


def extract_namespace(line):
    """Extract Kubernetes namespace from log"""
    match = re.search(r"namespace[=]([^\s]+)", line)
    if match:
        return match.group(1)
    return "default"


def extract_pod_name(line):
    """Extract pod name from log"""
    match = re.search(r"pod[=]([^\s]+)", line)
    if match:
        return match.group(1)
    return "unknown"


def parse_audit_log(line, hostname, mapping):
    """Parse Kubernetes audit log line"""
    namespace = extract_namespace(line)
    pod = extract_pod_name(line)

    for pattern_def in mapping.get("audit_patterns", []):
        pattern = pattern_def.get("pattern", "")
        try:
            if re.search(pattern, line, re.IGNORECASE):
                mitre_id = pattern_def.get("mitre", "")
                compliance = []
                for framework, techniques in mapping.get(
                    "compliance_mapping", {}
                ).items():
                    if mitre_id in techniques:
                        compliance.append(framework.upper())

                return {
                    "timestamp_utc": datetime.now().isoformat(),
                    "hostname": hostname,
                    "log_type": "k8s_audit",
                    "namespace": namespace,
                    "pod_name": pod,
                    "description": pattern_def.get("description", "K8s audit event"),
                    "mitre": [{"technique_id": mitre_id, "technique_name": mitre_id}]
                    if mitre_id
                    else [],
                    "severity": pattern_def.get("severity", "medium"),
                    "compliance": compliance,
                    "raw_log": line.strip()[:500],
                }
        except re.error:
            pass

    return None


def parse_component_log(line, hostname, mapping):
    """Parse Kubernetes component log line"""
    for pattern_def in mapping.get("component_patterns", []):
        pattern = pattern_def.get("pattern", "")
        try:
            if re.search(pattern, line, re.IGNORECASE):
                mitre_id = pattern_def.get("mitre", "")
                compliance = []
                for framework, techniques in mapping.get(
                    "compliance_mapping", {}
                ).items():
                    if mitre_id in techniques:
                        compliance.append(framework.upper())

                return {
                    "timestamp_utc": datetime.now().isoformat(),
                    "hostname": hostname,
                    "log_type": "k8s_component",
                    "description": pattern_def.get(
                        "description", "K8s component event"
                    ),
                    "mitre": [{"technique_id": mitre_id, "technique_name": mitre_id}]
                    if mitre_id
                    else [],
                    "severity": pattern_def.get("severity", "medium"),
                    "compliance": compliance,
                    "raw_log": line.strip()[:500],
                }
        except re.error:
            pass

    return None


def parse_pod_log(line, hostname, mapping):
    """Parse Kubernetes pod log line"""
    namespace = extract_namespace(line)
    pod = extract_pod_name(line)

    for pattern_def in mapping.get("pod_patterns", []):
        pattern = pattern_def.get("pattern", "")
        try:
            if re.search(pattern, line, re.IGNORECASE):
                mitre_id = pattern_def.get("mitre", "")
                compliance = []
                for framework, techniques in mapping.get(
                    "compliance_mapping", {}
                ).items():
                    if mitre_id in techniques:
                        compliance.append(framework.upper())

                return {
                    "timestamp_utc": datetime.now().isoformat(),
                    "hostname": hostname,
                    "log_type": "k8s_pod",
                    "namespace": namespace,
                    "pod_name": pod,
                    "description": pattern_def.get("description", "K8s pod event"),
                    "mitre": [{"technique_id": mitre_id, "technique_name": mitre_id}]
                    if mitre_id
                    else [],
                    "severity": pattern_def.get("severity", "medium"),
                    "compliance": compliance,
                    "raw_log": line.strip()[:500],
                }
        except re.error:
            pass

    return None


def parse_kubernetes_logs():
    """Main function to parse Kubernetes logs"""
    mapping = load_mapping()
    parsed_entries = []

    for filename in os.listdir(LOG_DIR):
        if (
            "kubernetes" in filename.lower()
            or "k8s" in filename.lower()
            and filename.endswith(".log")
        ):
            full_path = os.path.join(LOG_DIR, filename)
            stem = Path(filename).stem
            hostname = stem.split("_")[0] if "_" in stem else stem

            with open(full_path, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue

                    entry = None

                    if "[K8S_AUDIT]" in line:
                        entry = parse_audit_log(
                            line.replace("[K8S_AUDIT]", "").strip(), hostname, mapping
                        )
                    elif "[K8S_COMPONENT]" in line:
                        entry = parse_component_log(
                            line.replace("[K8S_COMPONENT]", "").strip(),
                            hostname,
                            mapping,
                        )
                    elif "[K8S_POD]" in line:
                        entry = parse_pod_log(
                            line.replace("[K8S_POD]", "").strip(), hostname, mapping
                        )
                    elif "[K8S_EVENT]" in line:
                        entry = parse_audit_log(
                            line.replace("[K8S_EVENT]", "").strip(), hostname, mapping
                        )
                    elif "[K8S_LOG]" in line:
                        entry = parse_pod_log(
                            line.replace("[K8S_LOG]", "").strip(), hostname, mapping
                        )
                    elif "kubernetes" in line.lower() or "kubelet" in line.lower():
                        if "audit" in line.lower():
                            entry = parse_audit_log(line, hostname, mapping)
                        else:
                            entry = parse_pod_log(line, hostname, mapping)

                    if entry:
                        parsed_entries.append(entry)

    parsed_entries.sort(key=lambda x: x["timestamp_utc"], reverse=True)

    stats = {
        "total_events": len(parsed_entries),
        "by_type": defaultdict(int),
        "by_severity": defaultdict(int),
        "by_compliance": defaultdict(int),
        "top_namespaces": defaultdict(int),
    }

    for entry in parsed_entries:
        stats["by_type"][entry.get("log_type", "unknown")] += 1
        stats["by_severity"][entry.get("severity", "unknown")] += 1

        if entry.get("namespace"):
            stats["top_namespaces"][entry["namespace"]] += 1

        for c in entry.get("compliance", []):
            stats["by_compliance"][c] += 1

    stats = {k: dict(v) if isinstance(v, defaultdict) else v for k, v in stats.items()}

    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)

    output = {"events": parsed_entries, "statistics": stats}

    with open(OUTPUT_FILE, "w") as f:
        json.dump(output, f, indent=2)

    print(f"Parsed {len(parsed_entries)} Kubernetes events.")
    if parsed_entries:
        print(f"  - Audit: {stats['by_type'].get('k8s_audit', 0)}")
        print(f"  - Pod: {stats['by_type'].get('k8s_pod', 0)}")
        print(f"  - Component: {stats['by_type'].get('k8s_component', 0)}")
        print(f"  - Critical: {stats['by_severity'].get('critical', 0)}")
        print(f"  - High: {stats['by_severity'].get('high', 0)}")


if __name__ == "__main__":
    parse_kubernetes_logs()
