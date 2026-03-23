#!/usr/bin/env python3
"""
AstroSIEM Agent FIM (File Integrity Monitoring)
Lightweight FIM for endpoint agents
Monitors critical system files and detects changes
"""

import os
import json
import hashlib
import sys
from pathlib import Path
from datetime import datetime, timezone

STATE_DIR = "/var/lib/astro-siem"
FIM_BASELINE = f"{STATE_DIR}/fim-baseline.json"
FIM_LOG = f"{STATE_DIR}/fim-changes.log"

WATCH_DIRS = ["/etc", "/var/www", "/home", "/root"]


def compute_hash(filepath):
    try:
        with open(filepath, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except Exception:
        return None


def get_metadata(path):
    try:
        stat = os.stat(path)
        return {
            "hash": compute_hash(path),
            "size": stat.st_size,
            "mtime": datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat(),
            "mode": oct(stat.st_mode & 0o777),
        }
    except Exception:
        return None


def scan_files():
    file_info = {}
    for root_dir in WATCH_DIRS:
        if not os.path.exists(root_dir):
            continue
        try:
            for root, _, files in os.walk(root_dir):
                for file in files:
                    full_path = os.path.join(root, file)
                    meta = get_metadata(full_path)
                    if meta:
                        file_info[full_path] = meta
        except PermissionError:
            continue
    return file_info


def load_baseline():
    if os.path.exists(FIM_BASELINE):
        try:
            with open(FIM_BASELINE, "r") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


def save_baseline(baseline):
    os.makedirs(STATE_DIR, exist_ok=True)
    with open(FIM_BASELINE, "w") as f:
        json.dump(baseline, f)


def write_log(change_type, path, old_data, new_data):
    entry = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "hostname": os.uname().nodename,
        "path": path,
        "change": change_type,
        "old": old_data,
        "new": new_data,
    }
    os.makedirs(STATE_DIR, exist_ok=True)
    with open(FIM_LOG, "a") as f:
        f.write(json.dumps(entry) + "\n")


def main():
    old_state = load_baseline()
    new_state = scan_files()

    old_paths = set(old_state.keys())
    new_paths = set(new_state.keys())

    changes_found = 0

    for path in old_paths - new_paths:
        write_log("deleted", path, old_state[path], None)
        changes_found += 1

    for path in new_paths - old_paths:
        write_log("created", path, None, new_state[path])
        changes_found += 1

    for path in old_paths & new_paths:
        if old_state[path] != new_state[path]:
            write_log("modified", path, old_state[path], new_state[path])
            changes_found += 1

    save_baseline(new_state)

    if changes_found > 0:
        print(f"FIM: Found {changes_found} changes")
    else:
        print("FIM: No changes detected")


if __name__ == "__main__":
    main()
