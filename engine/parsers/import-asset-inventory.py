#!/usr/bin/env python3
"""
Import host inventory and vulnerability exports into AstroSIEM's SQLite asset store.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).parent.resolve()
ENGINE_DIR = SCRIPT_DIR.parent
INCOMING_DIR = ENGINE_DIR / "incoming-logs"
if str(ENGINE_DIR) not in sys.path:
    sys.path.insert(0, str(ENGINE_DIR))

from storage.asset_inventory import AssetInventoryStore


def load_json(path: Path):
    try:
        return json.loads(path.read_text())
    except Exception:
        return None


def discover_payloads():
    inventory_payloads = {}
    vuln_payloads = {}
    vuln_status_payloads = {}
    if not INCOMING_DIR.exists():
        return inventory_payloads, vuln_payloads, vuln_status_payloads
    for path in INCOMING_DIR.iterdir():
        if path.name.endswith("_inventory.json"):
            host = path.name[: -len("_inventory.json")]
            inventory_payloads[host] = load_json(path)
        elif path.name.endswith("_vuln-results.json"):
            host = path.name[: -len("_vuln-results.json")]
            vuln_payloads[host] = load_json(path)
        elif path.name.endswith("_vuln-status.json"):
            host = path.name[: -len("_vuln-status.json")]
            vuln_status_payloads[host] = load_json(path)
    return inventory_payloads, vuln_payloads, vuln_status_payloads


def normalize_vulns(payload):
    if not payload:
        return []
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        return payload.get("vulnerabilities", [])
    return []


def extract_scan_metadata(vuln_payload, status_payload):
    metadata = {}
    if isinstance(vuln_payload, dict):
        metadata.update(vuln_payload.get("metadata") or {})
        if vuln_payload.get("generated_at"):
            metadata["generated_at"] = vuln_payload.get("generated_at")
    if isinstance(status_payload, dict):
        metadata.setdefault("status", status_payload.get("state"))
        metadata.setdefault("status_message", status_payload.get("message"))
        metadata.setdefault("scan_completed_at", status_payload.get("timestamp"))
        if status_payload.get("scanner") and not metadata.get("scanner"):
            metadata["scanner"] = status_payload.get("scanner")
    return metadata


def main():
    inventory_payloads, vuln_payloads, vuln_status_payloads = discover_payloads()
    store = AssetInventoryStore()

    imported = 0
    all_hosts = sorted(set(inventory_payloads) | set(vuln_payloads) | set(vuln_status_payloads))
    for host in all_hosts:
        inventory = inventory_payloads.get(host) or {"hostname": host, "generated_at": None, "packages": []}
        if not isinstance(inventory, dict):
            continue
        vuln_payload = vuln_payloads.get(host)
        vulnerabilities = normalize_vulns(vuln_payload)
        scan_metadata = extract_scan_metadata(vuln_payload, vuln_status_payloads.get(host))
        store.replace_asset_snapshot(host, inventory, vulnerabilities, scan_metadata=scan_metadata)
        imported += 1

    print(f"Imported asset inventory for {imported} host(s).")


if __name__ == "__main__":
    main()
