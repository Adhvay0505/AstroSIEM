#!/bin/bash
set -euo pipefail

SERVICE_NAME="astro-siem-vuln-scan.service"

json_response() {
  local status_code="$1"
  local body="$2"
  echo "Status: $status_code"
  echo "Content-Type: application/json"
  echo "Access-Control-Allow-Origin: *"
  echo "Access-Control-Allow-Methods: GET, POST, OPTIONS"
  echo "Access-Control-Allow-Headers: Content-Type, X-Requested-With"
  echo ""
  echo "$body"
}

method="${REQUEST_METHOD:-GET}"

if [ "$method" = "OPTIONS" ]; then
  json_response "204 No Content" ""
  exit 0
fi

if [ "$method" != "GET" ] && [ "$method" != "POST" ]; then
  json_response "405 Method Not Allowed" '{"status":"error","message":"Only GET, POST, OPTIONS are supported"}'
  exit 0
fi

if systemctl start "$SERVICE_NAME" 2>/dev/null; then
  json_response "202 Accepted" "{\"status\":\"queued\",\"service\":\"$SERVICE_NAME\",\"message\":\"Vulnerability scan queued\"}"
else
  json_response "500 Internal Server Error" "{\"status\":\"error\",\"service\":\"$SERVICE_NAME\",\"message\":\"Failed to queue vulnerability scan\"}"
fi
