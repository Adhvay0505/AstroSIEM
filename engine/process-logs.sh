#!/bin/bash

# AstroSIEM Log Processor
# =======================
# Runs all log parsers to process incoming logs

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "========================================"
echo "AstroSIEM Log Processor"
echo "========================================"
echo ""

# Run all parsers
echo "[*] Running parsers..."
echo ""

echo "[*] Importing asset inventory and vulnerability results..."
python3 "$SCRIPT_DIR/parsers/import-asset-inventory.py"

echo ""
echo "[*] Parsing security/auth logs..."
python3 "$SCRIPT_DIR/parsers/parse-syslog-security.py"

echo ""
echo "[*] Parsing FIM events..."
python3 "$SCRIPT_DIR/parsers/parse-fim-events.py"

echo "[*] Parsing network logs..."
python3 "$SCRIPT_DIR/parsers/parse-network-logs.py"

echo ""
echo "[*] Parsing Apache logs..."
python3 "$SCRIPT_DIR/parsers/parse-apache-logs.py"

echo ""
echo "[*] Parsing Nginx logs..."
python3 "$SCRIPT_DIR/parsers/parse-nginx-logs.py"

echo ""
echo "[*] Parsing Docker logs..."
python3 "$SCRIPT_DIR/parsers/parse-docker-logs.py"

echo ""
echo "[*] Parsing Kubernetes logs..."
python3 "$SCRIPT_DIR/parsers/parse-kubernetes-logs.py"

echo ""
echo "[*] Running detection engine..."
python3 "$SCRIPT_DIR/detection/run-detections.py"

echo ""
echo "[*] Running posture and policy checks..."
python3 "$SCRIPT_DIR/posture/run-posture-assessments.py"

echo ""
echo "========================================"
echo "Log Processing Complete"
echo "========================================"
