#!/bin/bash
set -euo pipefail

STATE_DIR="/var/lib/astro-siem"
LOG_FILE="$STATE_DIR/vuln-scan.log"
LOCK_FILE="$STATE_DIR/vuln-scan.lock"
STATUS_FILE="$STATE_DIR/vuln-scan-status.json"

# If set, this takes precedence over default scanner paths.
SCANNER_PATH="${ASTRO_SIEM_VULN_SCANNER:-}"
DEFAULT_SCANNERS=(
  "/opt/astro-siem/agent/vuln-scanner.sh"
  "/opt/astro-siem/agent/vulnerability-scanner.sh"
  "/opt/astro-siem/agent/vulnerability-scan.sh"
)

mkdir -p "$STATE_DIR"

resolve_scanner() {
  if [ -n "$SCANNER_PATH" ] && [ -x "$SCANNER_PATH" ]; then
    echo "$SCANNER_PATH"
    return 0
  fi

  local candidate
  for candidate in "${DEFAULT_SCANNERS[@]}"; do
    if [ -x "$candidate" ]; then
      echo "$candidate"
      return 0
    fi
  done

  return 1
}

write_status() {
  local state="$1"
  local message="$2"
  local scanner="${3:-}"
  cat > "$STATUS_FILE" <<EOF
{
  "state": "$state",
  "message": "$message",
  "scanner": "$scanner",
  "timestamp": "$(date -Iseconds)"
}
EOF
}

exec 9>"$LOCK_FILE"
if ! flock -n 9; then
  write_status "busy" "Scan already running"
  exit 3
fi

scanner="$(resolve_scanner || true)"
if [ -z "${scanner:-}" ]; then
  msg="No executable vulnerability scanner found. Set ASTRO_SIEM_VULN_SCANNER or install one of the default scanner files."
  echo "[$(date -Iseconds)] ERROR: $msg" >> "$LOG_FILE"
  write_status "error" "$msg"
  exit 2
fi

write_status "running" "Vulnerability scan started" "$scanner"
echo "[$(date -Iseconds)] INFO: Starting vulnerability scan with $scanner" >> "$LOG_FILE"

if "$scanner" >> "$LOG_FILE" 2>&1; then
  write_status "success" "Vulnerability scan completed successfully" "$scanner"
  echo "[$(date -Iseconds)] INFO: Vulnerability scan completed successfully" >> "$LOG_FILE"
else
  write_status "error" "Vulnerability scan failed" "$scanner"
  echo "[$(date -Iseconds)] ERROR: Vulnerability scan failed" >> "$LOG_FILE"
  exit 1
fi
