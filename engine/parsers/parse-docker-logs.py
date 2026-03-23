#!/usr/bin/env python3
"""
AstroSIEM Docker Log Parser
Parses Docker daemon and container logs, maps to MITRE techniques and compliance frameworks
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
OUTPUT_FILE = ENGINE_DIR / "processed-data" / "events-docker-processed.json"
MAPPING_FILE = ENGINE_DIR / "config" / "docker-mapping.yaml"

LOG_DIR = str(LOG_DIR)
OUTPUT_FILE = str(OUTPUT_FILE)
MAPPING_FILE = str(MAPPING_FILE)


def load_mapping():
    """Load Docker log patterns and compliance mappings"""
    try:
        with open(MAPPING_FILE, "r") as f:
            return yaml.safe_load(f)
    except Exception as e:
        print(f"Warning: Could not load Docker mapping: {e}")
        return {
            "container_patterns": [],
            "daemon_patterns": [],
            "compliance_mapping": {},
        }


def extract_container_name(line):
    """Extract container name from log line"""
    match = re.search(r"container[=]([^\s]+)", line)
    if match:
        return match.group(1)
    return "unknown"


def extract_image_name(line):
    """Extract image name from log line"""
    match = re.search(r"image[=]([^\s]+)", line)
    if match:
        return match.group(1)
    return "unknown"


def parse_container_log(line, hostname, mapping):
    """Parse Docker container log line"""
    container_name = extract_container_name(line)
    image_name = extract_image_name(line)

    for pattern_def in mapping.get("container_patterns", []):
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
                    "log_type": "docker_container",
                    "container_name": container_name,
                    "image_name": image_name,
                    "description": pattern_def.get(
                        "description", "Docker container event"
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


def parse_daemon_log(line, hostname, mapping):
    """Parse Docker daemon log line"""
    for pattern_def in mapping.get("daemon_patterns", []):
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
                    "log_type": "docker_daemon",
                    "description": pattern_def.get(
                        "description", "Docker daemon event"
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


def parse_docker_logs():
    """Main function to parse Docker logs"""
    mapping = load_mapping()
    parsed_entries = []

    for filename in os.listdir(LOG_DIR):
        if "docker" in filename.lower() and filename.endswith(".log"):
            full_path = os.path.join(LOG_DIR, filename)
            stem = Path(filename).stem
            hostname = stem.split("_")[0] if "_" in stem else stem

            with open(full_path, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue

                    entry = None

                    if "[DOCKER_CONTAINER]" in line:
                        entry = parse_container_log(
                            line.replace("[DOCKER_CONTAINER]", "").strip(),
                            hostname,
                            mapping,
                        )
                    elif "[DOCKER_DAEMON]" in line:
                        entry = parse_daemon_log(
                            line.replace("[DOCKER_DAEMON]", "").strip(),
                            hostname,
                            mapping,
                        )
                    elif "docker" in line.lower():
                        if "container" in line.lower():
                            entry = parse_container_log(line, hostname, mapping)
                        else:
                            entry = parse_daemon_log(line, hostname, mapping)

                    if entry:
                        parsed_entries.append(entry)

    parsed_entries.sort(key=lambda x: x["timestamp_utc"], reverse=True)

    stats = {
        "total_events": len(parsed_entries),
        "by_type": defaultdict(int),
        "by_severity": defaultdict(int),
        "by_compliance": defaultdict(int),
        "top_containers": defaultdict(int),
    }

    for entry in parsed_entries:
        stats["by_type"][entry.get("log_type", "unknown")] += 1
        stats["by_severity"][entry.get("severity", "unknown")] += 1

        if entry.get("container_name"):
            stats["top_containers"][entry["container_name"]] += 1

        for c in entry.get("compliance", []):
            stats["by_compliance"][c] += 1

    stats = {k: dict(v) if isinstance(v, defaultdict) else v for k, v in stats.items()}

    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)

    output = {"events": parsed_entries, "statistics": stats}

    with open(OUTPUT_FILE, "w") as f:
        json.dump(output, f, indent=2)

    print(f"Parsed {len(parsed_entries)} Docker events.")
    if parsed_entries:
        print(f"  - Container: {stats['by_type'].get('docker_container', 0)}")
        print(f"  - Daemon: {stats['by_type'].get('docker_daemon', 0)}")
        print(f"  - Critical: {stats['by_severity'].get('critical', 0)}")
        print(f"  - High: {stats['by_severity'].get('high', 0)}")


if __name__ == "__main__":
    parse_docker_logs()
