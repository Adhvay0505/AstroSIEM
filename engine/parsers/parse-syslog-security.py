import os
import json
import yaml
from datetime import datetime
from pathlib import Path

# Get the directory where this script is located
SCRIPT_DIR = Path(__file__).parent.resolve()
ENGINE_DIR = SCRIPT_DIR.parent

# Define absolute paths
LOG_DIR = ENGINE_DIR / "incoming-logs"
OUTPUT_FILE = ENGINE_DIR / "processed-data" / "events-security-processed.json"
MITRE_FILE = ENGINE_DIR / "processed-data" / "detection-rules-mitre-auth.json"
COMPLIANCE_FILE = ENGINE_DIR / "config" / "compliance-mapping.yaml"

# Convert to strings for compatibility
LOG_DIR = str(LOG_DIR)
OUTPUT_FILE = str(OUTPUT_FILE)
MITRE_FILE = str(MITRE_FILE)
COMPLIANCE_FILE = str(COMPLIANCE_FILE)


def load_mitre_rules():
    with open(MITRE_FILE, "r") as f:
        return json.load(f)


def load_compliance_mapping():
    """Load compliance mapping from YAML config"""
    try:
        with open(COMPLIANCE_FILE, "r") as f:
            return yaml.safe_load(f)
    except Exception as e:
        print(f"Warning: Could not load compliance mapping: {e}")
        return {}


def get_compliance_violations(mitre_hits, compliance_mapping):
    """Map MITRE techniques to compliance frameworks"""
    violations = set()

    for mitre_hit in mitre_hits:
        technique_id = mitre_hit.get("technique_id", "")

        # Check each compliance framework
        for framework, techniques in compliance_mapping.items():
            if technique_id in techniques:
                violations.add(framework.upper())

    return sorted(list(violations))


def match_mitre_rules(message, rules):
    matched = []
    msg_lower = message.lower()
    for rule in rules:
        for keyword in rule["keywords"]:
            if keyword.lower() in msg_lower:
                matched.append(
                    {
                        "technique_id": rule["technique_id"],
                        "technique_name": rule["technique_name"],
                        "tactic": rule["tactic"],
                        "description": rule["description"],
                    }
                )
                break
    return matched


def parse_log_line(line, hostname, mitre_rules, compliance_mapping):
    try:
        # ISO 8601 format check (Fedora secure.log)
        if line[:4].isdigit() and "T" in line:
            ts_str, rest = line.split(" ", 1)
            timestamp = datetime.fromisoformat(ts_str)
        else:
            # Normalize syslog timestamp with single-digit day
            ts_str = line[:15]
            ts_str = " ".join(ts_str.split())  # Collapse multiple spaces
            timestamp = datetime.strptime(ts_str, "%b %d %H:%M:%S")
            timestamp = timestamp.replace(year=datetime.now().year)
            rest = line[16:]

        parts = rest.split(": ", 1)
        meta = parts[0]
        message = parts[1] if len(parts) > 1 else ""

        if "[" in meta and "]" in meta:
            process, pid = meta.split("[", 1)
            pid = pid.strip("]")
        else:
            process = meta.strip()
            pid = ""

        mitre_hits = match_mitre_rules(message, mitre_rules)
        compliance_violations = get_compliance_violations(
            mitre_hits, compliance_mapping
        )

        return {
            "timestamp_utc": timestamp.isoformat(),
            "hostname": hostname,
            "process": process,
            "pid": pid,
            "message": message.strip(),
            "mitre": mitre_hits,
            "compliance": compliance_violations,
        }
    except Exception:
        return None


def main():
    parsed_logs = []
    mitre_rules = load_mitre_rules()
    compliance_mapping = load_compliance_mapping()

    for filename in os.listdir(LOG_DIR):
        if filename.endswith(".log") or filename.endswith(".json"):
            full_path = os.path.join(LOG_DIR, filename)
            # Extract agent name from filename (everything before first underscore)
            # e.g., "debian-vm_auth.log" -> "debian-vm"
            stem = Path(filename).stem
            hostname = stem.split("_")[0] if "_" in stem else stem
            with open(full_path, "r") as f:
                for line in f:
                    entry = parse_log_line(
                        line, hostname, mitre_rules, compliance_mapping
                    )
                    if entry:
                        parsed_logs.append(entry)

    parsed_logs.sort(key=lambda x: x["timestamp_utc"], reverse=True)

    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    with open(OUTPUT_FILE, "w") as f:
        json.dump(parsed_logs, f, indent=2)

    print(f"Parsed {len(parsed_logs)} lines from logs.")


if __name__ == "__main__":
    main()
