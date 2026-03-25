#!/usr/bin/env python3
"""
Active response hooks for posture findings with stateful actions.
"""

from __future__ import annotations

import json
import subprocess
import urllib.request
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

import yaml

from storage.posture_state import PostureStateStore
from storage.active_response_state import ActiveResponseStore


ENGINE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_CONFIG = {
    "responses": [
        {
            "name": "critical-posture-log",
            "type": "log",
            "min_severity": "critical",
            "output_file": "processed-data/active-response.log",
        }
    ],
    "stateful_responses": [
        {
            "name": "block-ip-temp",
            "type": "iptables-block",
            "min_severity": "high",
            "duration_seconds": 3600,
            "repeated_offender": True,
            "entity_type": "ip",
        }
    ],
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
    if severity_value(finding.get("severity", "")) < severity_value(
        action.get("min_severity", "critical")
    ):
        return False
    check_ids = action.get("check_ids") or []
    if check_ids and finding.get("check_id") not in check_ids:
        return False
    return True


def execute_action(action: Dict[str, Any], finding: Dict[str, Any]) -> tuple[str, str]:
    action_type = action.get("type", "log")
    payload = json.dumps(finding, sort_keys=True)
    if action_type == "log":
        output_path = Path(
            action.get("output_file")
            or ENGINE_DIR / "processed-data" / "active-response.log"
        )
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
        return (
            "success" if result.returncode == 0 else "error"
        ), output or f"exit={result.returncode}"
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


def execute_responses(
    findings: Iterable[Dict[str, Any]], store: PostureStateStore
) -> List[Dict[str, Any]]:
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


def load_stateful_config(config_path: Any = None) -> Dict[str, Any]:
    path = (
        config_path if config_path else (ENGINE_DIR / "config" / "active-response.yaml")
    )
    if not path.exists():
        return DEFAULT_CONFIG
    try:
        data = yaml.safe_load(path.read_text()) or {}
    except Exception:
        return DEFAULT_CONFIG
    return data


def execute_stateful_action(
    action: Dict[str, Any],
    entity_value: str,
    triggered_by_finding_id: str = "",
    triggered_by_alert_id: str = "",
) -> tuple[str, str, Any]:
    action_type = action.get("type", "log")
    duration = action.get("duration_seconds", 0)
    action_name = action.get("name", "unnamed")

    if action_type == "iptables-block":
        return _execute_iptables_block(entity_value, duration, action_name)
    elif action_type == "ip-block":
        return _execute_iptables_block(entity_value, duration, action_name)
    elif action_type == "user-disable":
        return _execute_user_disable(entity_value, action_name)
    elif action_type == "process-kill":
        return _execute_process_kill(entity_value, action_name)
    elif action_type == "script":
        return _execute_stateful_script(action, entity_value, duration)

    return "error", f"Unsupported stateful action type: {action_type}", None


def _execute_iptables_block(
    ip: str, duration: int, action_name: str
) -> tuple[str, str, Any]:
    if not ip or ip in {"0.0.0.0", "127.0.0.1", "::1"}:
        return "error", "Invalid IP address", None

    try:
        result = subprocess.run(
            ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"],
            capture_output=True,
            timeout=10,
            check=False,
        )
        if result.returncode == 0:
            return "success", f"Blocked {ip} for {duration}s", duration
        else:
            return "error", f"iptables failed: {result.stderr.decode()}", None
    except FileNotFoundError:
        return "error", "iptables not found", None
    except Exception as e:
        return "error", str(e), None


def _execute_ip_block(ip: str, duration: int, action_name: str) -> tuple[str, str, Any]:
    return _execute_iptables_block(ip, duration, action_name)


def _execute_user_disable(username: str, action_name: str) -> tuple[str, str, Any]:
    if not username or username == "root":
        return "error", "Cannot disable root or empty user", None

    try:
        result = subprocess.run(
            ["usermod", "-L", "-e", "1", username],
            capture_output=True,
            timeout=10,
            check=False,
        )
        if result.returncode == 0:
            return "success", f"Disabled user {username}", 0
        else:
            return "error", f"usermod failed: {result.stderr.decode()}", None
    except FileNotFoundError:
        return "error", "usermod not found", None
    except Exception as e:
        return "error", str(e), None


def _execute_process_kill(
    process_pattern: str, action_name: str
) -> tuple[str, str, Any]:
    try:
        result = subprocess.run(
            ["pkill", "-f", process_pattern],
            capture_output=True,
            timeout=10,
            check=False,
        )
        if result.returncode == 0:
            killed = result.stdout.decode().strip() or "processes"
            return "success", f"Killed {killed}", 0
        elif result.returncode == 1:
            return "success", "No processes found to kill", 0
        else:
            return "error", f"pkill failed: {result.stderr.decode()}", None
    except FileNotFoundError:
        return "error", "pkill not found", None
    except Exception as e:
        return "error", str(e), None


def _execute_stateful_script(
    action: Dict[str, Any], entity_value: str, duration: int
) -> tuple[str, str, Any]:
    script = action.get("script")
    if not script:
        return "error", "Missing script path", None

    script_path = Path(script)
    if not script_path.is_absolute():
        script_path = ENGINE_DIR / script_path

    payload = json.dumps({"entity": entity_value, "duration": duration})

    try:
        result = subprocess.run(
            [str(script_path)],
            input=payload,
            text=True,
            capture_output=True,
            timeout=15,
            check=False,
        )
        output = (result.stdout or result.stderr or "").strip()
        status = "success" if result.returncode == 0 else "error"
        return (
            status,
            output or f"exit={result.returncode}",
            duration if result.returncode == 0 else None,
        )
    except Exception as e:
        return "error", str(e), None


def revert_stateful_action(
    action_type: str,
    entity_value: str,
    action_name: str = "",
) -> tuple[str, str]:
    if action_type in {"iptables-block", "ip-block"}:
        return _revert_iptables_block(entity_value)
    elif action_type == "user-disable":
        return _revert_user_disable(entity_value)
    elif action_type == "script":
        return "success", "Script actions must be reverted manually"

    return "error", f"Unknown action type: {action_type}"


def _revert_iptables_block(ip: str) -> tuple[str, str]:
    if not ip:
        return "error", "Invalid IP"

    try:
        result = subprocess.run(
            ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
            capture_output=True,
            timeout=10,
            check=False,
        )
        if result.returncode == 0:
            return "success", f"Unblocked {ip}"
        else:
            return "error", f"Failed to unblock: {result.stderr.decode()}"
    except FileNotFoundError:
        return "error", "iptables not found"
    except Exception as e:
        return "error", str(e)


def _revert_user_disable(username: str) -> tuple[str, str]:
    if not username:
        return "error", "Invalid username"

    try:
        result = subprocess.run(
            ["usermod", "-U", "-e", "", username],
            capture_output=True,
            timeout=10,
            check=False,
        )
        if result.returncode == 0:
            return "success", f"Re-enabled user {username}"
        else:
            return "error", f"Failed to re-enable: {result.stderr.decode()}"
    except FileNotFoundError:
        return "error", "usermod not found"
    except Exception as e:
        return "error", str(e)


def execute_stateful_responses(
    findings: Iterable[Dict[str, Any]] = [],
    alerts: Iterable[Dict[str, Any]] = [],
) -> List[Dict[str, Any]]:
    config = load_stateful_config()
    state_store = ActiveResponseStore()
    executed: List[Dict[str, Any]] = []

    expired = state_store.expire_responses()
    if expired > 0:
        print(f"Expired {expired} stateful responses")

    finding_dict = {f.get("finding_id"): f for f in findings}
    alert_dict = {a.get("alert_id"): a for a in alerts}

    all_events = list(findings) + list(alerts)

    for event in all_events:
        event_id = event.get("finding_id") or event.get("alert_id", "")
        event_type = "finding" if event.get("finding_id") else "alert"

        for action in config.get("stateful_responses", []):
            action_name = action.get("name") or "unnamed"
            if not action_matches(action, event):
                continue

            entity_type = action.get("entity_type", "ip")

            if entity_type == "ip":
                entity_value = event.get("source_ip") or event.get("source", {}).get(
                    "ip"
                )
            elif entity_type == "user":
                entity_value = event.get("user") or event.get("username")
            elif entity_type == "host":
                entity_value = event.get("host") or event.get("hostname")
            else:
                entity_value = None

            if not entity_value:
                continue

            existing = state_store.check_active_block(
                entity_type, entity_value, action_name
            )
            if existing:
                continue

            if action.get("repeated_offender"):
                offender = state_store.record_offense(entity_type, entity_value)
                offense_count = offender.get("offense_count", 1)
                if offense_count >= 2:
                    base_duration = action.get("duration_seconds", 3600)
                    duration = state_store.calculate_block_duration(
                        entity_type, entity_value, base_duration
                    )
                else:
                    duration = action.get("duration_seconds", 0)
            else:
                duration = action.get("duration_seconds", 0)

            triggered_by = event.get("finding_id") or event.get("alert_id", "")

            status, output, actual_duration = execute_stateful_action(
                action,
                entity_value,
                triggered_by_finding_id=event.get("finding_id", ""),
                triggered_by_alert_id=event.get("alert_id", ""),
            )

            response_id = f"{action_name}-{entity_type}-{entity_value}"

            if status == "success":
                state_store.start_response(
                    response_id=response_id,
                    entity_type=entity_type,
                    entity_value=entity_value,
                    action_type=action.get("type", "unknown"),
                    action_name=action_name,
                    triggered_by_finding_id=event.get("finding_id", ""),
                    triggered_by_alert_id=event.get("alert_id", ""),
                    duration_seconds=actual_duration or duration,
                    output=output,
                )

            executed.append(
                {
                    "response_id": response_id,
                    "entity_type": entity_type,
                    "entity_value": entity_value,
                    "action_name": action_name,
                    "status": status,
                    "output": output,
                    "duration": actual_duration or duration,
                    "triggered_by": triggered_by,
                }
            )

    return executed
