#!/usr/bin/env python3
"""
AstroSIEM detection engine.

Normalizes processed telemetry, evaluates YAML-driven detections, and emits
analyst-facing alerts with evidence and investigation guidance.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import sys
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

import yaml


SCRIPT_DIR = Path(__file__).parent.resolve()
ENGINE_DIR = SCRIPT_DIR.parent
if str(ENGINE_DIR) not in sys.path:
    sys.path.insert(0, str(ENGINE_DIR))

from storage.alert_state import AlertStateStore
from storage.asset_inventory import AssetInventoryStore
PROCESSED_DIR = ENGINE_DIR / "processed-data"
RULES_DIR = ENGINE_DIR / "rules"
OUTPUT_FILE = PROCESSED_DIR / "alerts-analyst.json"

SEVERITY_SCORES = {
    "low": 25,
    "info": 25,
    "medium": 55,
    "warning": 55,
    "high": 80,
    "error": 80,
    "critical": 100,
}


def load_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        with path.open("r") as handle:
            return json.load(handle)
    except Exception:
        return default


def load_rules() -> List[Dict[str, Any]]:
    rules: List[Dict[str, Any]] = []
    for path in sorted(RULES_DIR.glob("*.yaml")):
        with path.open("r") as handle:
            data = yaml.safe_load(handle) or {}
        for rule in data.get("rules", []):
            rule["rule_file"] = path.name
            rules.append(rule)
    return rules


def safe_parse_timestamp(value: Optional[str]) -> datetime:
    if not value:
        return datetime.now(timezone.utc)
    cleaned = value.replace("Z", "+00:00")
    try:
        ts = datetime.fromisoformat(cleaned)
    except ValueError:
        return datetime.now(timezone.utc)
    if ts.tzinfo is None:
        return ts.replace(tzinfo=timezone.utc)
    return ts.astimezone(timezone.utc)


def severity_score(value: Optional[str]) -> int:
    return SEVERITY_SCORES.get((value or "").lower(), 40)


def first_match(patterns: Iterable[str], message: str) -> Optional[str]:
    for pattern in patterns:
        match = re.search(pattern, message, re.IGNORECASE)
        if match:
            return match.group(1)
    return None


def is_private_ip(value: Optional[str]) -> bool:
    if not value:
        return False
    try:
        return ipaddress.ip_address(value).is_private
    except ValueError:
        return False


def normalize_value(value: Any) -> str:
    if value is None or value == "":
        return "-"
    if isinstance(value, (list, tuple, set)):
        filtered = [str(item) for item in value if item not in (None, "")]
        return ", ".join(filtered) if filtered else "-"
    return str(value)


def get_path(event: Dict[str, Any], dotted: str) -> Any:
    current: Any = event
    for part in dotted.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def event_matches(event: Dict[str, Any], conditions: Dict[str, Any]) -> bool:
    for field, expected in conditions.items():
        actual = get_path(event, field)
        if isinstance(expected, dict):
            for op, operand in expected.items():
                if op == "in" and actual not in operand:
                    return False
                if op == "contains" and operand.lower() not in str(actual or "").lower():
                    return False
                if op == "contains_any":
                    haystack = str(actual or "").lower()
                    if not any(term.lower() in haystack for term in operand):
                        return False
                if op == "regex":
                    if actual is None or not re.search(operand, str(actual)):
                        return False
                if op == "gte" and (actual is None or actual < operand):
                    return False
                if op == "lte" and (actual is None or actual > operand):
                    return False
                if op == "exists" and bool(actual not in (None, "")) != bool(operand):
                    return False
                if op == "not_private" and bool(operand):
                    if actual in (None, "") or is_private_ip(str(actual)):
                        return False
                if op == "private" and bool(operand):
                    if actual in (None, "") or not is_private_ip(str(actual)):
                        return False
        elif isinstance(expected, list):
            if actual not in expected:
                return False
        else:
            if actual != expected:
                return False
    return True


def extract_security_ip(message: str) -> Optional[str]:
    return first_match(
        [
            r"rhost=([0-9.]+)",
            r"from ([0-9.]+)",
            r"\b([0-9]{1,3}(?:\.[0-9]{1,3}){3})\b",
        ],
        message,
    )


def extract_security_user(message: str) -> Optional[str]:
    user = first_match(
        [
            r"invalid user ([A-Za-z0-9_.-]+)",
            r"for invalid user ([A-Za-z0-9_.-]+)",
            r"for user ([A-Za-z0-9_.-]+)",
            r"for ([A-Za-z0-9_.-]+) from",
            r'user "([^"]+)"',
            r"user=([A-Za-z0-9_.-]+)",
        ],
        message,
    )
    if user in {"this", "user"}:
        return None
    return user


def derive_security_action(process: str, message: str) -> Tuple[str, str, str]:
    msg = message.lower()
    proc = process.lower()
    category = "system"
    action = "log_observed"
    severity = "info"

    if "invalid user" in msg or "user unknown" in msg:
        category = "authentication"
        action = "invalid_user"
        severity = "high"
    elif any(term in msg for term in ["authentication failure", "failed password", "too many authentication failures"]):
        category = "authentication"
        action = "login_failed"
        severity = "critical" if "too many authentication failures" in msg else "high"
    elif "accepted password" in msg or "accepted publickey" in msg:
        category = "authentication"
        action = "login_success"
        severity = "medium"
    elif "session opened for user root" in msg and "sudo" in proc:
        category = "privilege"
        action = "sudo_session_opened"
        severity = "medium"
    elif "session closed for user root" in msg and "sudo" in proc:
        category = "privilege"
        action = "sudo_session_closed"
        severity = "low"
    elif "useradd" in proc or "new user" in msg:
        category = "identity"
        action = "user_created"
        severity = "high"
    elif "chpasswd" in proc or "password changed" in msg:
        category = "identity"
        action = "password_changed"
        severity = "high"

    return category, action, severity


def normalize_security_events(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    normalized = []
    for raw in events:
        message = raw.get("message", "")
        process = raw.get("process", "syslog")
        category, action, derived_severity = derive_security_action(process, message)
        if category == "system" and not raw.get("mitre") and not raw.get("compliance"):
            continue
        normalized.append(
            {
                "event_id": stable_event_id("security", raw),
                "timestamp": safe_parse_timestamp(raw.get("timestamp_utc")),
                "timestamp_utc": raw.get("timestamp_utc"),
                "telemetry": {"source": "security"},
                "event": {
                    "category": category,
                    "action": action,
                    "severity": derived_severity,
                    "severity_score": severity_score(derived_severity),
                },
                "host": {"name": raw.get("hostname", "unknown")},
                "source": {"ip": extract_security_ip(message)},
                "destination": {"ip": None},
                "user": {"name": extract_security_user(message)},
                "process": {"name": process, "pid": raw.get("pid")},
                "file": {"path": None},
                "container": {"name": None, "image": None},
                "kubernetes": {"namespace": None, "pod_name": None},
                "message": message,
                "description": message,
                "mitre": raw.get("mitre", []),
                "compliance": raw.get("compliance", []),
                "raw_event": raw,
            }
        )
    return normalized


def normalize_fim_events(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    action_map = {
        "created": "file_created",
        "modified": "file_modified",
        "deleted": "file_deleted",
    }
    normalized = []
    for raw in events:
        change = raw.get("change", "modified")
        normalized.append(
            {
                "event_id": stable_event_id("fim", raw),
                "timestamp": safe_parse_timestamp(raw.get("timestamp_utc")),
                "timestamp_utc": raw.get("timestamp_utc"),
                "telemetry": {"source": "fim"},
                "event": {
                    "category": "file",
                    "action": action_map.get(change, "file_modified"),
                    "severity": "high" if str(raw.get("path", "")).startswith(("/etc", "/root")) else "medium",
                    "severity_score": 78 if str(raw.get("path", "")).startswith(("/etc", "/root")) else 55,
                },
                "host": {"name": raw.get("hostname", "unknown")},
                "source": {"ip": None},
                "destination": {"ip": None},
                "user": {"name": None},
                "process": {"name": "fim", "pid": None},
                "file": {"path": raw.get("path")},
                "container": {"name": None, "image": None},
                "kubernetes": {"namespace": None, "pod_name": None},
                "message": f"{change} {raw.get('path', '')}".strip(),
                "description": f"File integrity change: {change}",
                "mitre": raw.get("mitre", []),
                "compliance": raw.get("compliance", []),
                "raw_event": raw,
            }
        )
    return normalized


def normalize_network_events(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    normalized = []
    for raw in events:
        normalized.append(
            {
                "event_id": stable_event_id("network", raw),
                "timestamp": safe_parse_timestamp(raw.get("timestamp_utc")),
                "timestamp_utc": raw.get("timestamp_utc"),
                "telemetry": {"source": "network"},
                "event": {
                    "category": "network",
                    "action": raw.get("log_type", "network_event"),
                    "severity": raw.get("severity", "medium"),
                    "severity_score": severity_score(raw.get("severity")),
                },
                "host": {"name": raw.get("hostname", "unknown")},
                "source": {"ip": raw.get("source_ip")},
                "destination": {"ip": raw.get("destination_ip"), "port": raw.get("destination_port")},
                "user": {"name": None},
                "process": {"name": raw.get("log_type", "network"), "pid": None},
                "file": {"path": None},
                "container": {"name": None, "image": None},
                "kubernetes": {"namespace": None, "pod_name": None},
                "message": raw.get("description") or raw.get("raw_log", ""),
                "description": raw.get("description") or "Network event",
                "mitre": raw.get("mitre", []),
                "compliance": raw.get("compliance", []),
                "raw_event": raw,
            }
        )
    return normalized


def classify_web_action(description: str) -> str:
    desc = (description or "").lower()
    if any(term in desc for term in ["code execution", "backdoor", "shell"]):
        return "web_rce_indicator"
    if any(term in desc for term in ["scanner", "missing php file", "access denied by configuration"]):
        return "scanner_activity"
    return "web_exploit_attempt"


def normalize_web_events(events: List[Dict[str, Any]], source_name: str) -> List[Dict[str, Any]]:
    normalized = []
    for raw in events:
        description = raw.get("description") or raw.get("raw_log", "")
        normalized.append(
            {
                "event_id": stable_event_id(source_name, raw),
                "timestamp": safe_parse_timestamp(raw.get("timestamp_utc")),
                "timestamp_utc": raw.get("timestamp_utc"),
                "telemetry": {"source": source_name},
                "event": {
                    "category": "web",
                    "action": classify_web_action(description),
                    "severity": raw.get("severity", "medium"),
                    "severity_score": severity_score(raw.get("severity")),
                },
                "host": {"name": raw.get("hostname", "unknown")},
                "source": {"ip": raw.get("source_ip")},
                "destination": {"ip": None, "port": raw.get("http_status")},
                "user": {"name": None},
                "process": {"name": raw.get("log_type", source_name), "pid": None},
                "file": {"path": None},
                "container": {"name": None, "image": None},
                "kubernetes": {"namespace": None, "pod_name": None},
                "message": description,
                "description": description,
                "url": raw.get("request_url"),
                "mitre": raw.get("mitre", []),
                "compliance": raw.get("compliance", []),
                "raw_event": raw,
            }
        )
    return normalized


def classify_docker_action(description: str) -> str:
    desc = (description or "").lower()
    if "docker socket access" in desc:
        return "docker_socket_access"
    if "host volume mounted" in desc:
        return "host_mount"
    if "sensitive file access" in desc:
        return "sensitive_file_access"
    return "container_runtime_anomaly"


def normalize_docker_events(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    normalized = []
    for raw in events:
        description = raw.get("description") or raw.get("raw_log", "")
        normalized.append(
            {
                "event_id": stable_event_id("docker", raw),
                "timestamp": safe_parse_timestamp(raw.get("timestamp_utc")),
                "timestamp_utc": raw.get("timestamp_utc"),
                "telemetry": {"source": "docker"},
                "event": {
                    "category": "container",
                    "action": classify_docker_action(description),
                    "severity": raw.get("severity", "medium"),
                    "severity_score": severity_score(raw.get("severity")),
                },
                "host": {"name": raw.get("hostname", "unknown")},
                "source": {"ip": None},
                "destination": {"ip": None},
                "user": {"name": None},
                "process": {"name": raw.get("log_type", "docker"), "pid": None},
                "file": {"path": None},
                "container": {"name": raw.get("container_name"), "image": raw.get("image_name")},
                "kubernetes": {"namespace": None, "pod_name": None},
                "message": description,
                "description": description,
                "mitre": raw.get("mitre", []),
                "compliance": raw.get("compliance", []),
                "raw_event": raw,
            }
        )
    return normalized


def classify_k8s_action(description: str) -> str:
    desc = (description or "").lower()
    if "impersonation" in desc:
        return "service_account_impersonation"
    if "interactive shell" in desc:
        return "interactive_shell"
    if "secret" in desc:
        return "secrets_access"
    return "unauthorized_k8s_access"


def normalize_k8s_events(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    normalized = []
    for raw in events:
        description = raw.get("description") or raw.get("raw_log", "")
        user = first_match([r"user=([A-Za-z0-9:_.-]+)"], raw.get("raw_log", "") or "")
        normalized.append(
            {
                "event_id": stable_event_id("kubernetes", raw),
                "timestamp": safe_parse_timestamp(raw.get("timestamp_utc")),
                "timestamp_utc": raw.get("timestamp_utc"),
                "telemetry": {"source": "kubernetes"},
                "event": {
                    "category": "kubernetes",
                    "action": classify_k8s_action(description),
                    "severity": raw.get("severity", "medium"),
                    "severity_score": severity_score(raw.get("severity")),
                },
                "host": {"name": raw.get("hostname", "unknown")},
                "source": {"ip": None},
                "destination": {"ip": None},
                "user": {"name": user},
                "process": {"name": raw.get("log_type", "kubernetes"), "pid": None},
                "file": {"path": None},
                "container": {"name": None, "image": None},
                "kubernetes": {"namespace": raw.get("namespace"), "pod_name": raw.get("pod_name")},
                "message": description,
                "description": description,
                "mitre": raw.get("mitre", []),
                "compliance": raw.get("compliance", []),
                "raw_event": raw,
            }
        )
    return normalized


def stable_event_id(prefix: str, raw: Dict[str, Any]) -> str:
    key_parts = [
        prefix,
        raw.get("timestamp_utc"),
        raw.get("hostname"),
        raw.get("process"),
        raw.get("message"),
        raw.get("description"),
        raw.get("raw_log"),
        raw.get("path"),
        raw.get("change"),
        raw.get("source_ip"),
        raw.get("destination_ip"),
        raw.get("container_name"),
        raw.get("pod_name"),
    ]
    payload = "|".join("" if part is None else str(part) for part in key_parts)
    return f"{prefix}-{hashlib.sha1(payload.encode()).hexdigest()[:14]}"


def load_all_normalized_events() -> List[Dict[str, Any]]:
    security = load_json(PROCESSED_DIR / "events-security-processed.json", [])
    fim = load_json(PROCESSED_DIR / "events-fim-processed.json", [])
    network = load_json(PROCESSED_DIR / "events-network-processed.json", {}).get("events", [])
    apache = load_json(PROCESSED_DIR / "events-apache-processed.json", {}).get("events", [])
    nginx = load_json(PROCESSED_DIR / "events-nginx-processed.json", {}).get("events", [])
    docker = load_json(PROCESSED_DIR / "events-docker-processed.json", {}).get("events", [])
    kubernetes = load_json(PROCESSED_DIR / "events-kubernetes-processed.json", {}).get("events", [])

    events = []
    events.extend(normalize_security_events(security if isinstance(security, list) else []))
    events.extend(normalize_fim_events(fim if isinstance(fim, list) else []))
    events.extend(normalize_network_events(network))
    events.extend(normalize_web_events(apache, "apache"))
    events.extend(normalize_web_events(nginx, "nginx"))
    events.extend(normalize_docker_events(docker))
    events.extend(normalize_k8s_events(kubernetes))
    events.sort(key=lambda item: item["timestamp"])
    return events


def group_signature(event: Dict[str, Any], fields: List[str]) -> Tuple[Any, ...]:
    return tuple(get_path(event, field) for field in fields)


def select_best_threshold_window(events: List[Dict[str, Any]], rule: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:
    if not events:
        return None
    window = timedelta(minutes=rule.get("window_minutes", 60))
    threshold = rule.get("threshold", 1)
    best_range: Optional[Tuple[int, int]] = None
    start = 0
    for end, current in enumerate(events):
        while current["timestamp"] - events[start]["timestamp"] > window:
            start += 1
        if best_range is None or (end - start) > (best_range[1] - best_range[0]):
            best_range = (start, end)
    if best_range is not None and (best_range[1] - best_range[0] + 1) >= threshold:
        return events[best_range[0] : best_range[1] + 1]
    return None


def select_best_distinct_window(events: List[Dict[str, Any]], rule: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:
    if not events:
        return None
    window = timedelta(minutes=rule.get("window_minutes", 60))
    threshold = rule.get("threshold", 1)
    distinct_field = rule.get("distinct_field")
    best_range: Optional[Tuple[int, int]] = None
    best_distinct = 0
    start = 0
    for end, current in enumerate(events):
        while current["timestamp"] - events[start]["timestamp"] > window:
            start += 1
        candidate = events[start : end + 1]
        distinct_values = {
            get_path(item, distinct_field)
            for item in candidate
            if get_path(item, distinct_field) not in (None, "")
        }
        if len(distinct_values) > best_distinct or (
            len(distinct_values) == best_distinct
            and (
                best_range is None
                or len(candidate) > (best_range[1] - best_range[0] + 1)
            )
        ):
            best_range = (start, end)
            best_distinct = len(distinct_values)
    if best_distinct >= threshold:
        assert best_range is not None
        return events[best_range[0] : best_range[1] + 1]
    return None


def summarize_entities(events: List[Dict[str, Any]]) -> Dict[str, List[str]]:
    entity_map = {
        "hosts": sorted({get_path(event, "host.name") for event in events if get_path(event, "host.name")}),
        "source_ips": sorted({get_path(event, "source.ip") for event in events if get_path(event, "source.ip")}),
        "destination_ips": sorted({get_path(event, "destination.ip") for event in events if get_path(event, "destination.ip")}),
        "users": sorted({get_path(event, "user.name") for event in events if get_path(event, "user.name")}),
        "containers": sorted({get_path(event, "container.name") for event in events if get_path(event, "container.name")}),
        "namespaces": sorted({get_path(event, "kubernetes.namespace") for event in events if get_path(event, "kubernetes.namespace")}),
        "files": sorted({get_path(event, "file.path") for event in events if get_path(event, "file.path")}),
        "telemetry_sources": sorted({get_path(event, "telemetry.source") for event in events if get_path(event, "telemetry.source")}),
    }
    return entity_map


def find_sequence_matches(group_events: List[Dict[str, Any]], rule: Dict[str, Any]) -> List[List[Dict[str, Any]]]:
    steps = rule.get("steps", [])
    if not steps:
        return []
    max_span = timedelta(minutes=rule.get("window_minutes", 60))
    matches: List[List[Dict[str, Any]]] = []
    cursor = 0

    while cursor < len(group_events):
        start_index = cursor
        current_index = cursor
        matched_events: List[Dict[str, Any]] = []
        anchor_time: Optional[datetime] = None
        complete = True

        for step in steps:
            step_match = step.get("match", {})
            min_count = int(step.get("min_count", 1))
            matched_for_step = 0

            while current_index < len(group_events):
                event = group_events[current_index]
                if anchor_time and event["timestamp"] - anchor_time > max_span:
                    complete = False
                    break
                if event_matches(event, step_match):
                    if anchor_time is None:
                        anchor_time = event["timestamp"]
                    matched_events.append(event)
                    matched_for_step += 1
                    current_index += 1
                    if matched_for_step >= min_count:
                        break
                    continue
                current_index += 1

            if not complete or matched_for_step < min_count:
                complete = False
                break

        if complete and matched_events:
            matches.append(matched_events)
            cursor = current_index
        else:
            cursor = start_index + 1

    return matches


def template_context(events: List[Dict[str, Any]], rule: Dict[str, Any]) -> Dict[str, str]:
    entities = summarize_entities(events)
    context = {
        "count": str(len(events)),
        "window_minutes": str(rule.get("window_minutes", 0)),
        "source.ip": normalize_value(entities["source_ips"][0] if entities["source_ips"] else None),
        "destination.ip": normalize_value(entities["destination_ips"][0] if entities["destination_ips"] else None),
        "host.name": normalize_value(entities["hosts"][0] if entities["hosts"] else None),
        "user.name": normalize_value(entities["users"][0] if entities["users"] else None),
        "container.name": normalize_value(entities["containers"][0] if entities["containers"] else None),
        "kubernetes.namespace": normalize_value(entities["namespaces"][0] if entities["namespaces"] else None),
        "file.path": normalize_value(entities["files"][0] if entities["files"] else None),
        "distinct_count": "0",
    }
    distinct_field = rule.get("distinct_field")
    if distinct_field:
        distinct_values = {
            get_path(event, distinct_field)
            for event in events
            if get_path(event, distinct_field) not in (None, "")
        }
        context["distinct_count"] = str(len(distinct_values))
    return context


def render_template(template: str, context: Dict[str, str]) -> str:
    rendered = template
    for key, value in context.items():
        rendered = rendered.replace("{" + key + "}", value)
    return rendered


def build_evidence(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    evidence = []
    for event in sorted(events, key=lambda item: item["timestamp"], reverse=True)[:5]:
        evidence.append(
            {
                "timestamp_utc": event["timestamp"].isoformat(),
                "telemetry_source": get_path(event, "telemetry.source"),
                "host": get_path(event, "host.name"),
                "source_ip": get_path(event, "source.ip"),
                "destination_ip": get_path(event, "destination.ip"),
                "user": get_path(event, "user.name"),
                "action": get_path(event, "event.action"),
                "severity": get_path(event, "event.severity"),
                "message": event.get("message") or event.get("description") or "",
            }
        )
    return evidence


def build_alert(rule: Dict[str, Any], matched_events: List[Dict[str, Any]]) -> Dict[str, Any]:
    matched_events = sorted(matched_events, key=lambda item: item["timestamp"])
    context = template_context(matched_events, rule)
    entities = summarize_entities(matched_events)
    first_seen = matched_events[0]["timestamp"].isoformat()
    last_seen = matched_events[-1]["timestamp"].isoformat()
    dedup_signature = "|".join(
        [
            rule["id"],
            ",".join(entities["hosts"]),
            ",".join(entities["source_ips"]),
            ",".join(entities["destination_ips"]),
            ",".join(entities["users"]),
            ",".join(entities["containers"]),
            ",".join(entities["namespaces"]),
            ",".join(entities["files"]),
        ]
    )
    dedup_key = hashlib.sha1(dedup_signature.encode()).hexdigest()
    alert_id = f"ALERT-{dedup_key[:12].upper()}"
    telemetry_sources = entities["telemetry_sources"]
    evidence = build_evidence(matched_events)
    summary = render_template(rule.get("summary_template", rule["description"]), context)
    priority_score = min(
        100,
        int(rule.get("confidence", 75))
        + min(len(matched_events), 20)
        + min((len(telemetry_sources) - 1) * 12, 24)
        + (10 if rule.get("severity") == "critical" else 0)
        + (5 if rule.get("severity") == "high" else 0),
    )
    why_this_fired = [
        f"Rule {rule['id']} matched {len(matched_events)} event(s).",
        f"Severity set to {rule.get('severity', 'medium')} with confidence {rule.get('confidence', 75)}.",
    ]
    if rule.get("type") == "threshold":
        why_this_fired.append(
            f"Threshold condition met: at least {rule.get('threshold', 1)} events within {rule.get('window_minutes', 0)} minutes."
        )
    if rule.get("type") == "distinct":
        why_this_fired.append(
            f"Distinct-entity condition met on {rule.get('distinct_field', 'entity')}."
        )
    if rule.get("type") == "sequence":
        step_names = [step.get("label", f"step {idx + 1}") for idx, step in enumerate(rule.get("steps", []))]
        why_this_fired.append(
            f"Ordered sequence observed within {rule.get('window_minutes', 0)} minutes: {' -> '.join(step_names)}."
        )
    if len(telemetry_sources) > 1:
        why_this_fired.append(
            f"Correlated across {len(telemetry_sources)} telemetry sources: {', '.join(telemetry_sources)}."
        )

    return {
        "alert_id": alert_id,
        "dedup_key": dedup_key,
        "rule_id": rule["id"],
        "title": rule["title"],
        "description": rule.get("description", ""),
        "severity": rule.get("severity", "medium"),
        "confidence": rule.get("confidence", 75),
        "priority_score": priority_score,
        "status": "new",
        "first_seen": first_seen,
        "last_seen": last_seen,
        "event_count": len(matched_events),
        "source_count": len(telemetry_sources),
        "summary": summary,
        "recommendations": rule.get("recommendations", []),
        "telemetry_sources": telemetry_sources,
        "entities": entities,
        "scope_summary": build_scope_summary(entities),
        "coverage_summary": ", ".join(telemetry_sources) if telemetry_sources else "-",
        "recommended_action": rule.get("recommendations", ["Investigate the correlated evidence."])[0],
        "why_this_fired": " ".join(why_this_fired),
        "evidence_preview": " | ".join(item["message"][:120] for item in evidence[:3]),
        "mitre": sorted(
            {
                hit.get("technique_id")
                for event in matched_events
                for hit in event.get("mitre", [])
                if hit.get("technique_id")
            }
        ),
        "compliance": sorted(
            {
                tag
                for event in matched_events
                for tag in event.get("compliance", [])
                if tag
            }
        ),
        "evidence": evidence,
    }


def build_scope_summary(entities: Dict[str, List[str]]) -> str:
    parts = []
    if entities["hosts"]:
        parts.append(f"host {'/'.join(entities['hosts'][:2])}")
    if entities["source_ips"]:
        parts.append(f"source {'/'.join(entities['source_ips'][:2])}")
    if entities["users"]:
        parts.append(f"user {'/'.join(entities['users'][:2])}")
    if entities["containers"]:
        parts.append(f"container {'/'.join(entities['containers'][:2])}")
    if entities["namespaces"]:
        parts.append(f"namespace {'/'.join(entities['namespaces'][:2])}")
    if entities["files"]:
        parts.append(f"file {'/'.join(entities['files'][:1])}")
    return ", ".join(parts) if parts else "broad telemetry scope"


def evaluate_rule(rule: Dict[str, Any], events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    if rule.get("type") == "sequence":
        steps = rule.get("steps", [])
        candidates = [
            event
            for event in events
            if rule_source_matches(rule.get("source"), event)
            and any(event_matches(event, step.get("match", {})) for step in steps)
        ]
    else:
        candidates = [
            event
            for event in events
            if rule_source_matches(rule.get("source"), event) and event_matches(event, rule.get("match", {}))
        ]
    if not candidates:
        return []

    grouped: Dict[Tuple[Any, ...], List[Dict[str, Any]]] = defaultdict(list)
    group_fields = rule.get("group_by", [])
    if group_fields:
        for event in candidates:
            signature = group_signature(event, group_fields)
            if rule.get("type") == "sequence" and any(value in (None, "") for value in signature):
                continue
            grouped[signature].append(event)
    else:
        grouped[tuple()] = candidates

    alerts = []
    for group_events in grouped.values():
        group_events.sort(key=lambda item: item["timestamp"])
        matched: Optional[List[Dict[str, Any]]] = None
        if rule["type"] == "threshold":
            matched = select_best_threshold_window(group_events, rule)
        elif rule["type"] == "distinct":
            matched = select_best_distinct_window(group_events, rule)
        elif rule["type"] == "sequence":
            for sequence_match in find_sequence_matches(group_events, rule):
                alerts.append(build_alert(rule, sequence_match))
            continue
        elif rule["type"] == "event_group":
            matched = group_events
        if matched:
            alerts.append(build_alert(rule, matched))
    return alerts


def rule_source_matches(rule_source: Optional[str], event: Dict[str, Any]) -> bool:
    if not rule_source or rule_source == "multi":
        return True
    telemetry = get_path(event, "telemetry.source")
    if rule_source == "web":
        return telemetry in {"apache", "nginx"}
    return telemetry == rule_source


def detect(events: List[Dict[str, Any]], rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    alerts = []
    for rule in rules:
        alerts.extend(evaluate_rule(rule, events))
    alerts.sort(
        key=lambda item: (
            severity_score(item["severity"]),
            safe_parse_timestamp(item["last_seen"]).timestamp(),
            item["event_count"],
        ),
        reverse=True,
    )
    return alerts


def build_summary(alerts: List[Dict[str, Any]], events: List[Dict[str, Any]]) -> Dict[str, Any]:
    by_severity = defaultdict(int)
    by_rule = defaultdict(int)
    by_source = defaultdict(int)
    for alert in alerts:
        by_severity[alert["severity"]] += 1
        by_rule[alert["rule_id"]] += 1
        for source in alert.get("telemetry_sources", []):
            by_source[source] += 1
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_alerts": len(alerts),
        "critical_alerts": by_severity.get("critical", 0),
        "high_alerts": by_severity.get("high", 0),
        "correlated_alerts": sum(1 for alert in alerts if alert.get("source_count", 0) > 1),
        "external_ip_alerts": sum(1 for alert in alerts if alert.get("entities", {}).get("source_ips")),
        "normalized_event_count": len(events),
        "by_severity": dict(by_severity),
        "by_rule": dict(by_rule),
        "by_source": dict(by_source),
    }


def apply_asset_risk_to_alerts(alerts: List[Dict[str, Any]], asset_store: AssetInventoryStore) -> List[Dict[str, Any]]:
    for alert in alerts:
        hosts = (alert.get("entities") or {}).get("hosts", [])
        if not hosts:
            continue
        asset = asset_store.get_asset(hosts[0])
        if not asset:
            continue
        vuln_summary = asset.get("vulnerability_summary") or {}
        priority_boost = 0
        reasons = []
        if asset.get("business_criticality") == "critical":
            priority_boost += 12
            reasons.append("host business criticality is critical")
        elif asset.get("business_criticality") == "high":
            priority_boost += 8
            reasons.append("host business criticality is high")
        if asset.get("internet_facing"):
            priority_boost += 8
            reasons.append("host is internet-facing")
        if vuln_summary.get("critical", 0):
            priority_boost += min(15, vuln_summary.get("critical", 0) * 5)
            reasons.append(f"{vuln_summary.get('critical', 0)} critical CVE(s) on host")
        elif vuln_summary.get("high", 0):
            priority_boost += min(10, vuln_summary.get("high", 0) * 2)
            reasons.append(f"{vuln_summary.get('high', 0)} high CVE(s) on host")

        if priority_boost:
            alert["priority_score"] = min(100, int(alert.get("priority_score", 0)) + priority_boost)
            alert["why_this_fired"] = f"{alert.get('why_this_fired', '').rstrip()} Asset risk boosted priority because " + ", ".join(reasons) + "."
            alert["asset_priority_context"] = {
                "host_name": asset.get("host_name"),
                "business_criticality": asset.get("business_criticality"),
                "internet_facing": asset.get("internet_facing"),
                "vulnerability_summary": vuln_summary,
                "priority_boost": priority_boost,
            }
    return alerts


def main() -> None:
    rules = load_rules()
    events = load_all_normalized_events()
    detected_alerts = detect(events, rules)
    detected_alerts = apply_asset_risk_to_alerts(detected_alerts, AssetInventoryStore())
    store = AlertStateStore()
    alerts = store.sync_alerts(detected_alerts)
    payload = {
        "summary": store.summary(alerts),
        "alerts": alerts,
    }
    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    with OUTPUT_FILE.open("w") as handle:
        json.dump(payload, handle, indent=2)
    print(f"Generated {len(alerts)} alerts from {len(events)} normalized events.")


if __name__ == "__main__":
    main()
