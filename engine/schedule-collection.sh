#!/bin/bash

# AstroSIEM Collection Scheduler
# ==============================
# Schedules automatic log collection from all agents via cron
#
# Usage:
#   ./schedule-collection.sh           # Schedule collection every 5 minutes
#   ./schedule-collection.sh remove    # Remove scheduled collection

set -euo pipefail

# Absolute path to project directory
PROJECT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
COLLECTOR_SCRIPT="$PROJECT_DIR/collect-logs.sh"

# Cron schedule (every 5 minutes)
CRON_SCHEDULE="*/5 * * * *"

# Function to add cron job
add_cron_job() {
    echo "[*] Scheduling automatic log collection..."
    
    # Check if collector exists
    if [ ! -f "$COLLECTOR_SCRIPT" ]; then
        echo "[!] Error: Collector script not found at $COLLECTOR_SCRIPT"
        exit 1
    fi
    
    # Build cron job command
    CRON_JOB="$CRON_SCHEDULE cd $PROJECT_DIR && ./collect-logs.sh >> /var/log/astro-siem-collector.log 2>&1"
    
    # Check if cron job already exists
    if crontab -l 2>/dev/null | grep -F "$COLLECTOR_SCRIPT" >/dev/null; then
        echo "[✓] Cron job already exists."
        echo "[*] Current schedule: $CRON_SCHEDULE"
    else
        # Add new cron job
        (crontab -l 2>/dev/null; echo "$CRON_JOB") | crontab -
        echo "[✓] Cron job added to run every 5 minutes."
        echo "[*] Logs will be saved to: /var/log/astro-siem-collector.log"
    fi
}

# Function to remove cron job
remove_cron_job() {
    echo "[*] Removing scheduled collection..."
    
    # Remove any line containing the collector script
    crontab -l 2>/dev/null | grep -v "$COLLECTOR_SCRIPT" | crontab -
    
    echo "[✓] Cron job removed."
}

# Main
main() {
    echo "========================================"
    echo "AstroSIEM Collection Scheduler"
    echo "========================================"
    echo ""
    
    if [ $# -eq 1 ] && [ "$1" == "remove" ]; then
        remove_cron_job
    else
        add_cron_job
    fi
    
    echo ""
    echo "[*] Current crontab:"
    crontab -l 2>/dev/null | grep -E "(astro-siem|$COLLECTOR_SCRIPT)" || echo "    (none)"
    echo "========================================"
}

main "$@"
