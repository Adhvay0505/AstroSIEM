#!/usr/bin/env python3
"""
AstroSIEM Network Log Parser
Parses firewall and IDS logs, maps to MITRE techniques and compliance frameworks
"""

import os
import re
import json
import yaml
from datetime import datetime
from pathlib import Path
from collections import defaultdict

# Get the directory where this script is located
SCRIPT_DIR = Path(__file__).parent.resolve()
ENGINE_DIR = SCRIPT_DIR.parent

# Define absolute paths
LOG_DIR = ENGINE_DIR / "incoming-logs"
OUTPUT_FILE = ENGINE_DIR / "processed-data" / "events-network-processed.json"
NETWORK_MAPPING_FILE = ENGINE_DIR / "config" / "network-mapping.yaml"

# Convert to strings
LOG_DIR = str(LOG_DIR)
OUTPUT_FILE = str(OUTPUT_FILE)
NETWORK_MAPPING_FILE = str(NETWORK_MAPPING_FILE)


def load_network_mapping():
    """Load network log patterns and compliance mappings"""
    try:
        with open(NETWORK_MAPPING_FILE, "r") as f:
            return yaml.safe_load(f)
    except Exception as e:
        print(f"Warning: Could not load network mapping: {e}")
        return {"firewall_patterns": [], "ids_patterns": [], "compliance_mapping": {}}


def extract_ip_from_log(line):
    """Extract source and destination IPs from log line"""
    src_ip = None
    dst_ip = None

    # Common patterns for IP extraction
    ip_pattern = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")

    # Try to find SRC= and DST= patterns first (firewall format)
    src_match = re.search(r"SRC=([0-9.]+)", line)
    dst_match = re.search(r"DST=([0-9.]+)", line)

    if src_match:
        src_ip = src_match.group(1)
    if dst_match:
        dst_ip = dst_match.group(1)

    # If not found, try general IP extraction
    if not src_ip or not dst_ip:
        ips = ip_pattern.findall(line)
        if len(ips) >= 2:
            src_ip = ips[0]
            dst_ip = ips[1]
        elif len(ips) == 1:
            src_ip = ips[0]

    return src_ip, dst_ip


def extract_port_from_log(line):
    """Extract source and destination ports from log line"""
    src_port = None
    dst_port = None

    # Try DPT (destination port) and SPT (source port)
    dpt_match = re.search(r"DPT=([0-9]+)", line)
    spt_match = re.search(r"SPT=([0-9]+)", line)

    if dpt_match:
        dst_port = int(dpt_match.group(1))
    if spt_match:
        src_port = int(spt_match.group(1))

    return src_port, dst_port


def parse_firewall_log(line, hostname, mapping):
    """Parse a firewall log line"""
    # Check against firewall patterns
    for pattern_def in mapping.get("firewall_patterns", []):
        pattern = pattern_def.get("pattern", "")

        # Handle regex patterns (check for regex chars like |, (, ), *, +)
        try:
            if any(c in pattern for c in "|()*+?{"):
                if re.search(pattern, line, re.IGNORECASE):
                    pattern_matched = True
                else:
                    pattern_matched = False
            else:
                pattern_matched = pattern.lower() in line.lower()
        except re.error:
            pattern_matched = pattern.lower() in line.lower()

        if pattern_matched:
            # Extract IPs and ports
            src_ip, dst_ip = extract_ip_from_log(line)
            src_port, dst_port = extract_port_from_log(line)

            # Get compliance frameworks
            mitre_id = pattern_def.get("mitre", "")
            compliance = []
            for framework, techniques in mapping.get("compliance_mapping", {}).items():
                if mitre_id in techniques:
                    compliance.append(framework.upper())

            return {
                "timestamp_utc": datetime.now().isoformat(),
                "hostname": hostname,
                "log_type": "firewall",
                "source_ip": src_ip,
                "destination_ip": dst_ip,
                "source_port": src_port,
                "destination_port": dst_port,
                "action": "block",
                "description": pattern_def.get("description", "Firewall event"),
                "mitre": [
                    {
                        "technique_id": mitre_id,
                        "technique_name": pattern_def.get("mitre", "Unknown"),
                    }
                ]
                if mitre_id
                else [],
                "severity": pattern_def.get("severity", "medium"),
                "compliance": compliance,
                "raw_log": line.strip()[:500],
            }

    return None


def parse_ids_log(line, hostname, mapping):
    """Parse an IDS alert log line"""
    # Check against IDS patterns
    for pattern_def in mapping.get("ids_patterns", []):
        pattern = pattern_def.get("pattern", "")

        # Handle regex patterns
        try:
            if any(c in pattern for c in "|()*+?{"):
                if re.search(pattern, line, re.IGNORECASE):
                    pattern_matched = True
                else:
                    pattern_matched = False
            else:
                pattern_matched = pattern.lower() in line.lower()
        except re.error:
            pattern_matched = pattern.lower() in line.lower()

        if pattern_matched:
            # Extract IPs
            src_ip, dst_ip = extract_ip_from_log(line)
            src_port, dst_port = extract_port_from_log(line)

            # Get compliance frameworks
            mitre_id = pattern_def.get("mitre", "")
            compliance = []
            for framework, techniques in mapping.get("compliance_mapping", {}).items():
                if mitre_id in techniques:
                    compliance.append(framework.upper())

            return {
                "timestamp_utc": datetime.now().isoformat(),
                "hostname": hostname,
                "log_type": "ids",
                "source_ip": src_ip,
                "destination_ip": dst_ip,
                "source_port": src_port,
                "destination_port": dst_port,
                "action": "alert",
                "description": pattern_def.get("description", "IDS Alert"),
                "mitre": [
                    {
                        "technique_id": mitre_id,
                        "technique_name": pattern_def.get("mitre", "Unknown"),
                    }
                ]
                if mitre_id
                else [],
                "severity": pattern_def.get("severity", "high"),
                "compliance": compliance,
                "raw_log": line.strip()[:500],
            }

    return None


def parse_network_logs():
    """Main function to parse network logs"""
    mapping = load_network_mapping()
    parsed_entries = []

    # Find all network log files
    for filename in os.listdir(LOG_DIR):
        if "network" in filename.lower() and (
            filename.endswith(".log") or filename.endswith(".txt")
        ):
            full_path = os.path.join(LOG_DIR, filename)

            # Extract hostname from filename
            stem = Path(filename).stem
            hostname = stem.split("_")[0] if "_" in stem else stem

            with open(full_path, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue

                    entry = None

                    # Determine log type and parse
                    if "[FIREWALL]" in line:
                        entry = parse_firewall_log(
                            line.replace("[FIREWALL]", ""), hostname, mapping
                        )
                    elif "[IDS]" in line:
                        entry = parse_ids_log(
                            line.replace("[IDS]", ""), hostname, mapping
                        )
                    elif any(
                        pattern in line.lower()
                        for pattern in ["block", "drop", "reject", "ufw"]
                    ):
                        entry = parse_firewall_log(line, hostname, mapping)
                    elif any(
                        pattern in line.lower()
                        for pattern in ["alert", "scan", "attack", "exploit", "ids"]
                    ):
                        entry = parse_ids_log(line, hostname, mapping)

                    if entry:
                        parsed_entries.append(entry)

    # Sort by timestamp (newest first)
    parsed_entries.sort(key=lambda x: x["timestamp_utc"], reverse=True)

    # Statistics
    stats = {
        "total_events": len(parsed_entries),
        "by_type": defaultdict(int),
        "by_severity": defaultdict(int),
        "by_compliance": defaultdict(int),
        "top_attackers": defaultdict(int),
        "top_ports": defaultdict(int),
    }

    for entry in parsed_entries:
        stats["by_type"][entry.get("log_type", "unknown")] += 1
        stats["by_severity"][entry.get("severity", "unknown")] += 1

        if entry.get("source_ip"):
            stats["top_attackers"][entry["source_ip"]] += 1

        if entry.get("destination_port"):
            stats["top_ports"][entry["destination_port"]] += 1

        for c in entry.get("compliance", []):
            stats["by_compliance"][c] += 1

    # Convert defaultdicts to regular dicts
    stats = {k: dict(v) if isinstance(v, defaultdict) else v for k, v in stats.items()}

    # Save output
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)

    output = {"events": parsed_entries, "statistics": stats}

    with open(OUTPUT_FILE, "w") as f:
        json.dump(output, f, indent=2)

    print(f"Parsed {len(parsed_entries)} network events.")
    if parsed_entries:
        print(f"  - Firewall: {stats['by_type'].get('firewall', 0)}")
        print(f"  - IDS: {stats['by_type'].get('ids', 0)}")
        print(f"  - Critical: {stats['by_severity'].get('critical', 0)}")
        print(f"  - High: {stats['by_severity'].get('high', 0)}")


if __name__ == "__main__":
    parse_network_logs()
