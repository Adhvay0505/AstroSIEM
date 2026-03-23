#!/usr/bin/env python3
"""
Active response hooks for posture findings.
"""

from __future__ import annotations

import json
import subprocess
import urllib.request
from pathlib import Path
from typing import Any, Dict, Iterable, List

import yaml

from storage.posture_state import PostureStateStore


ENGINE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_CONFIG = {
    "responses": [
        {
            "name": "critical-posture-log",
            "type": "log",
            "min_severity": "critical",
            "output_file": "processed-data/active-response.log",
        }
    ]
}
SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def severity_value(severity: str) -> int:
    return SEVERITY_ORDER.get(str(severity or "").lower(), 0)


def load_config(config_path: Path | None = None) -> Dict[str, Any]:
    path = config_path or (ENGINE_DIR / "config" / "active-response.yaml")
    if not path.exists():
        return DEFAULT_CONFIG
    try:
        data = yaml.safe_load(path.read_text()) or {}
    except Exception:
        return DEFAULT_CONFIG
    responses = data.get("responses")
    if not isinstance(responses, list):
        return DEFAULT_CONFIG
    return data


def action_matches(action: Dict[str, Any], finding: Dict[str, Any]) -> bool:
    if severity_value(finding.get("severity", "")) < severity_value(action.get("min_severity", "critical")):
        return False
    check_ids = action.get("check_ids") or []
    if check_ids and finding.get("check_id") not in check_ids:
        return False
    return True


def execute_action(action: Dict[str, Any], finding: Dict[str, Any]) -> tuple[str, str]:
    action_type = action.get("type", "log")
    payload = json.dumps(finding, sort_keys=True)
    if action_type == "log":
        output_path = Path(action.get("output_file") or ENGINE_DIR / "processed-data" / "active-response.log")
        if not output_path.is_absolute():
            output_path = ENGINE_DIR / output_path
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with output_path.open("a") as handle:
            handle.write(payload + "\n")
        return "success", f"Logged finding to {output_path}"
    if action_type == "script":
        script = action.get("script")
        if not script:
            return "error", "Missing script path"
        script_path = Path(script)
        if not script_path.is_absolute():
            script_path = ENGINE_DIR / script_path
        result = subprocess.run(
            [str(script_path)],
            input=payload,
            text=True,
            capture_output=True,
            timeout=15,
            check=False,
        )
        output = (result.stdout or result.stderr or "").strip()
        return ("success" if result.returncode == 0 else "error"), output or f"exit={result.returncode}"
    if action_type == "webhook":
        url = action.get("url")
        if not url:
            return "error", "Missing webhook URL"
        request = urllib.request.Request(
            url,
            data=payload.encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method=action.get("method", "POST"),
        )
        with urllib.request.urlopen(request, timeout=10) as response:  # nosec B310
            return "success", f"HTTP {response.status}"
    return "error", f"Unsupported action type: {action_type}"


def execute_responses(findings: Iterable[Dict[str, Any]], store: PostureStateStore) -> List[Dict[str, Any]]:
    config = load_config()
    executed: List[Dict[str, Any]] = []
    for finding in findings:
        if finding.get("status") == "resolved":
            continue
        for action in config.get("responses", []):
            action_name = action.get("name") or "unnamed-action"
            if not action_matches(action, finding):
                continue
            if store.response_already_recorded(finding["finding_id"], action_name):
                continue
            status, output = execute_action(action, finding)
            store.record_response(
                finding_id=finding["finding_id"],
                action_name=action_name,
                action_type=action.get("type", "log"),
                status=status,
                output=output,
            )
            executed.append(
                {
                    "finding_id": finding["finding_id"],
                    "action_name": action_name,
                    "status": status,
                    "output": output,
                }
            )
    return executed

