#!/usr/bin/env python3
"""
AstroSIEM Nginx Log Parser
Parses Nginx access and error logs, maps to MITRE techniques and compliance frameworks
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
OUTPUT_FILE = ENGINE_DIR / "processed-data" / "events-nginx-processed.json"
MAPPING_FILE = ENGINE_DIR / "config" / "nginx-mapping.yaml"

LOG_DIR = str(LOG_DIR)
OUTPUT_FILE = str(OUTPUT_FILE)
MAPPING_FILE = str(MAPPING_FILE)


def load_mapping():
    """Load Nginx log patterns and compliance mappings"""
    try:
        with open(MAPPING_FILE, "r") as f:
            return yaml.safe_load(f)
    except Exception as e:
        print(f"Warning: Could not load Nginx mapping: {e}")
        return {"access_patterns": [], "error_patterns": [], "compliance_mapping": {}}


def extract_ip_from_log(line):
    """Extract client IP from log line"""
    match = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
    if match:
        return match.group(1)
    return None


def extract_url_from_log(line):
    """Extract requested URL from access log"""
    match = re.search(r'"(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+([^\s]+)', line)
    if match:
        return match.group(2)
    return None


def extract_status_code(line):
    """Extract HTTP status code"""
    match = re.search(r"\s(\d{3})\s", line)
    if match:
        return int(match.group(1))
    return None


def parse_access_log(line, hostname, mapping):
    """Parse Nginx access log line"""
    for pattern_def in mapping.get("access_patterns", []):
        pattern = pattern_def.get("pattern", "")
        try:
            if re.search(pattern, line, re.IGNORECASE):
                src_ip = extract_ip_from_log(line)
                url = extract_url_from_log(line)
                status = extract_status_code(line)

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
                    "log_type": "nginx_access",
                    "source_ip": src_ip,
                    "request_url": url,
                    "http_status": status,
                    "description": pattern_def.get("description", "Nginx access event"),
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


def parse_error_log(line, hostname, mapping):
    """Parse Nginx error log line"""
    for pattern_def in mapping.get("error_patterns", []):
        pattern = pattern_def.get("pattern", "")
        try:
            if re.search(pattern, line, re.IGNORECASE):
                src_ip = extract_ip_from_log(line)

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
                    "log_type": "nginx_error",
                    "source_ip": src_ip,
                    "description": pattern_def.get("description", "Nginx error event"),
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


def parse_nginx_logs():
    """Main function to parse Nginx logs"""
    mapping = load_mapping()
    parsed_entries = []

    for filename in os.listdir(LOG_DIR):
        if "nginx" in filename.lower() and filename.endswith(".log"):
            full_path = os.path.join(LOG_DIR, filename)
            stem = Path(filename).stem
            hostname = stem.split("_")[0] if "_" in stem else stem

            with open(full_path, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue

                    entry = None

                    if "[NGINX_ACCESS]" in line:
                        entry = parse_access_log(
                            line.replace("[NGINX_ACCESS]", "").strip(),
                            hostname,
                            mapping,
                        )
                    elif "[NGINX_ERROR]" in line:
                        entry = parse_error_log(
                            line.replace("[NGINX_ERROR]", "").strip(), hostname, mapping
                        )
                    elif "nginx" in line.lower():
                        if any(
                            x in line.lower()
                            for x in ["get ", "post ", " 200 ", " 404 "]
                        ):
                            entry = parse_access_log(line, hostname, mapping)
                        else:
                            entry = parse_error_log(line, hostname, mapping)

                    if entry:
                        parsed_entries.append(entry)

    parsed_entries.sort(key=lambda x: x["timestamp_utc"], reverse=True)

    stats = {
        "total_events": len(parsed_entries),
        "by_type": defaultdict(int),
        "by_severity": defaultdict(int),
        "by_compliance": defaultdict(int),
        "top_attackers": defaultdict(int),
        "top_urls": defaultdict(int),
    }

    for entry in parsed_entries:
        stats["by_type"][entry.get("log_type", "unknown")] += 1
        stats["by_severity"][entry.get("severity", "unknown")] += 1

        if entry.get("source_ip"):
            stats["top_attackers"][entry["source_ip"]] += 1

        if entry.get("request_url"):
            stats["top_urls"][entry["request_url"]] += 1

        for c in entry.get("compliance", []):
            stats["by_compliance"][c] += 1

    stats = {k: dict(v) if isinstance(v, defaultdict) else v for k, v in stats.items()}

    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)

    output = {"events": parsed_entries, "statistics": stats}

    with open(OUTPUT_FILE, "w") as f:
        json.dump(output, f, indent=2)

    print(f"Parsed {len(parsed_entries)} Nginx events.")
    if parsed_entries:
        print(f"  - Access: {stats['by_type'].get('nginx_access', 0)}")
        print(f"  - Error: {stats['by_type'].get('nginx_error', 0)}")
        print(f"  - Critical: {stats['by_severity'].get('critical', 0)}")
        print(f"  - High: {stats['by_severity'].get('high', 0)}")


if __name__ == "__main__":
    parse_nginx_logs()
