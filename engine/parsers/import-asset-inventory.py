#!/usr/bin/env python3
"""
Import host inventory and vulnerability exports into AstroSIEM's SQLite asset store.
"""

from __future__ import annotations

import json
from pathlib import Path

from storage.asset_inventory import AssetInventoryStore


SCRIPT_DIR = Path(__file__).parent.resolve()
ENGINE_DIR = SCRIPT_DIR.parent
INCOMING_DIR = ENGINE_DIR / "incoming-logs"


def load_json(path: Path):
    try:
        return json.loads(path.read_text())
    except Exception:
        return None


def discover_payloads():
    inventory_payloads = {}
    vuln_payloads = {}
    if not INCOMING_DIR.exists():
        return inventory_payloads, vuln_payloads
    for path in INCOMING_DIR.iterdir():
        if path.name.endswith("_inventory.json"):
            host = path.name[: -len("_inventory.json")]
            inventory_payloads[host] = load_json(path)
        elif path.name.endswith("_vuln-results.json"):
            host = path.name[: -len("_vuln-results.json")]
            vuln_payloads[host] = load_json(path)
    return inventory_payloads, vuln_payloads


def normalize_vulns(payload):
    if not payload:
        return []
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        return payload.get("vulnerabilities", [])
    return []


def main():
    inventory_payloads, vuln_payloads = discover_payloads()
    store = AssetInventoryStore()

    imported = 0
    all_hosts = sorted(set(inventory_payloads) | set(vuln_payloads))
    for host in all_hosts:
        inventory = inventory_payloads.get(host) or {"hostname": host, "generated_at": None, "packages": []}
        if not isinstance(inventory, dict):
            continue
        vulnerabilities = normalize_vulns(vuln_payloads.get(host))
        store.replace_asset_snapshot(host, inventory, vulnerabilities)
        imported += 1

    print(f"Imported asset inventory for {imported} host(s).")


if __name__ == "__main__":
    main()
