#!/usr/bin/env python3
"""
Agent policy baseline loading and drift evaluation.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

import yaml


ENGINE_DIR = Path(__file__).resolve().parent.parent
CONFIG_DIR = ENGINE_DIR / "config"


def load_agent_baselines(config_dir: Path = CONFIG_DIR) -> Dict[str, Dict[str, Any]]:
    path = config_dir / "agents.yaml"
    if not path.exists():
        return {}
    try:
        data = yaml.safe_load(path.read_text()) or {}
    except Exception:
        return {}
    agents = data.get("agents") or {}
    return agents if isinstance(agents, dict) else {}


def normalize_expected_services(agent_cfg: Dict[str, Any]) -> List[Dict[str, str]]:
    baseline = (agent_cfg or {}).get("policy_baseline") or {}
    services = baseline.get("expected_services") or []
    normalized = []
    for item in services:
        if not isinstance(item, dict) or not item.get("name"):
            continue
        normalized.append(
            {
                "name": str(item.get("name")),
                "enabled_state": str(item.get("enabled_state", "")),
                "active_state": str(item.get("active_state", "")),
            }
        )
    return normalized


def normalize_expected_configs(agent_cfg: Dict[str, Any]) -> List[Dict[str, Any]]:
    baseline = (agent_cfg or {}).get("policy_baseline") or {}
    configs = baseline.get("expected_configs") or {}
    normalized = []
    if isinstance(configs, dict):
        for key, value in configs.items():
            expected = value if isinstance(value, list) else [value]
            normalized.append({"key": str(key), "expected_values": [str(item) for item in expected]})
    elif isinstance(configs, list):
        for item in configs:
            if not isinstance(item, dict) or not item.get("key"):
                continue
            value = item.get("expected_values", item.get("value", []))
            expected = value if isinstance(value, list) else [value]
            normalized.append({"key": str(item.get("key")), "expected_values": [str(v) for v in expected]})
    return normalized


def evaluate_asset_baseline(host_name: str, asset: Dict[str, Any], agents: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    agent_cfg = agents.get(host_name, {})
    expected_services = normalize_expected_services(agent_cfg)
    expected_configs = normalize_expected_configs(agent_cfg)
    service_map = {svc.get("name"): svc for svc in (asset.get("services") or [])}
    config_map = {cfg.get("key"): str(cfg.get("value", "")) for cfg in (asset.get("config_checks") or [])}

    drifts: List[Dict[str, Any]] = []
    for expected in expected_services:
        actual = service_map.get(expected["name"])
        if not actual:
            drifts.append(
                {
                    "type": "service",
                    "key": expected["name"],
                    "expected": expected,
                    "actual": None,
                    "reason": "missing_service_inventory",
                }
            )
            continue
        if expected.get("enabled_state") and actual.get("enabled_state") != expected["enabled_state"]:
            drifts.append(
                {
                    "type": "service",
                    "key": expected["name"],
                    "expected": expected,
                    "actual": actual,
                    "reason": "enabled_state_mismatch",
                }
            )
        if expected.get("active_state") and actual.get("active_state") != expected["active_state"]:
            drifts.append(
                {
                    "type": "service",
                    "key": expected["name"],
                    "expected": expected,
                    "actual": actual,
                    "reason": "active_state_mismatch",
                }
            )

    for expected in expected_configs:
        actual_value = config_map.get(expected["key"])
        if actual_value is None:
            drifts.append(
                {
                    "type": "config",
                    "key": expected["key"],
                    "expected": expected["expected_values"],
                    "actual": None,
                    "reason": "missing_config_inventory",
                }
            )
            continue
        if actual_value not in expected["expected_values"]:
            drifts.append(
                {
                    "type": "config",
                    "key": expected["key"],
                    "expected": expected["expected_values"],
                    "actual": actual_value,
                    "reason": "config_value_mismatch",
                }
            )

    return {
        "policy_baseline": {
            "expected_services": expected_services,
            "expected_configs": expected_configs,
        },
        "policy_drift": {
            "items": drifts,
            "summary": {
                "total": len(drifts),
                "service": sum(1 for item in drifts if item.get("type") == "service"),
                "config": sum(1 for item in drifts if item.get("type") == "config"),
            },
        },
    }
