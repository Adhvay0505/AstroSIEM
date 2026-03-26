#!/bin/bash
set -euo pipefail

STATE_DIR="/var/lib/astro-siem"
INVENTORY_FILE="$STATE_DIR/asset-inventory.json"
OUTPUT_FILE="$STATE_DIR/vuln-results.json"
TMP_FILE="$STATE_DIR/vuln-results.tmp.json"

mkdir -p "$STATE_DIR"

HOSTNAME_VALUE="$(hostname)"
GENERATED_AT="$(date -Iseconds)"

read_inventory_field() {
  local key="$1"
  if [ ! -f "$INVENTORY_FILE" ]; then
    echo ""
    return 0
  fi
  python3 - "$INVENTORY_FILE" "$key" <<'PY'
import json, sys
path, key = sys.argv[1], sys.argv[2]
try:
    payload = json.loads(open(path, "r", encoding="utf-8").read())
except Exception:
    payload = {}
value = payload.get(key, "")
if value is None:
    value = ""
print(value)
PY
}

if [ ! -f "$INVENTORY_FILE" ] && [ -x "/opt/astro-siem/agent/export-asset-inventory.sh" ]; then
  /opt/astro-siem/agent/export-asset-inventory.sh >/dev/null 2>&1 || true
fi

INVENTORY_DIGEST="$(read_inventory_field inventory_digest)"
PACKAGE_COUNT="$(read_inventory_field package_count)"
if [ -z "$PACKAGE_COUNT" ]; then
  PACKAGE_COUNT="0"
fi

SCANNER_NAME="builtin"
SCANNER_VERSION="1.0"
FEED_SOURCE="agent_report"
FEED_URL=""
FEED_VERSION=""
VULNS_JSON="[]"

if command -v trivy >/dev/null 2>&1; then
  SCANNER_NAME="trivy"
  TRIVY_JSON="$(mktemp)"
  if trivy rootfs --quiet --skip-db-update --format json -o "$TRIVY_JSON" / >/dev/null 2>&1; then
    VULNS_JSON="$(python3 - "$TRIVY_JSON" <<'PY'
import json, sys
payload = json.loads(open(sys.argv[1], "r", encoding="utf-8").read())
items = []
for result in payload.get("Results", []):
    for vuln in result.get("Vulnerabilities") or []:
        cve_id = vuln.get("VulnerabilityID")
        if not cve_id:
            continue
        items.append({
            "cve_id": cve_id,
            "severity": str(vuln.get("Severity", "unknown")).lower(),
            "score": vuln.get("CVSS", {}).get("nvd", {}).get("V3Score") or vuln.get("CVSS", {}).get("redhat", {}).get("V3Score"),
            "package_name": vuln.get("PkgName", ""),
            "package_version": vuln.get("InstalledVersion", ""),
            "title": vuln.get("Title", ""),
            "summary": vuln.get("Description", ""),
            "fix_version": vuln.get("FixedVersion", ""),
            "published_at": vuln.get("PublishedDate", ""),
            "scanner": "trivy",
            "status": "open"
        })
print(json.dumps(items))
PY
)"
    FEED_SOURCE="trivy_db"
    FEED_VERSION="$(trivy --version 2>/dev/null | head -n1 | awk '{print $2}' || true)"
  fi
  rm -f "$TRIVY_JSON"
elif command -v grype >/dev/null 2>&1; then
  SCANNER_NAME="grype"
  GRYPE_JSON="$(mktemp)"
  if grype dir:/ -o json > "$GRYPE_JSON" 2>/dev/null; then
    VULNS_JSON="$(python3 - "$GRYPE_JSON" <<'PY'
import json, sys
payload = json.loads(open(sys.argv[1], "r", encoding="utf-8").read())
items = []
for match in payload.get("matches", []):
    vuln = match.get("vulnerability") or {}
    artifact = match.get("artifact") or {}
    cve_id = vuln.get("id")
    if not cve_id:
      continue
    cvss = vuln.get("cvss") or []
    score = None
    if cvss:
      score = cvss[0].get("metrics", {}).get("baseScore")
    items.append({
      "cve_id": cve_id,
      "severity": str(vuln.get("severity", "unknown")).lower(),
      "score": score,
      "package_name": artifact.get("name", ""),
      "package_version": artifact.get("version", ""),
      "title": vuln.get("description", "")[:160],
      "summary": vuln.get("description", ""),
      "fix_version": ", ".join(vuln.get("fix", {}).get("versions") or []),
      "published_at": vuln.get("dataSource", ""),
      "scanner": "grype",
      "status": "open"
    })
print(json.dumps(items))
PY
)"
    FEED_SOURCE="grype_db"
    FEED_VERSION="$(grype version 2>/dev/null | awk '/Version:/ {print $2; exit}' || true)"
  fi
  rm -f "$GRYPE_JSON"
fi

cat > "$TMP_FILE" <<EOF
{
  "hostname": "$HOSTNAME_VALUE",
  "generated_at": "$GENERATED_AT",
  "metadata": {
    "scanner": "$SCANNER_NAME",
    "scanner_version": "$SCANNER_VERSION",
    "inventory_digest": "$INVENTORY_DIGEST",
    "package_count": $PACKAGE_COUNT,
    "feed": {
      "source": "$FEED_SOURCE",
      "version": "$FEED_VERSION",
      "url": "$FEED_URL",
      "last_refreshed": "$GENERATED_AT"
    }
  },
  "vulnerabilities": $VULNS_JSON
}
EOF

mv "$TMP_FILE" "$OUTPUT_FILE"
chmod 644 "$OUTPUT_FILE"
echo "$OUTPUT_FILE"
