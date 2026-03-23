#!/bin/bash
# AstroSIEM Agent - Network Log Collector
# Collects firewall and IDS logs for SIEM analysis

STATE_DIR="/var/lib/astro-siem"
NETWORK_LOG="$STATE_DIR/network-changes.log"

# Common firewall and IDS log locations
FIREWALL_LOGS=(
    "/var/log/messages"
    "/var/log/syslog"
    "/var/log/ufw.log"
    "/var/log/iptables.log"
    "/var/log/kern.log"
    "/var/log/firewalld"
)

IDS_LOGS=(
    "/var/log/suricata/eve.json"
    "/var/log/suricata/fast.log"
    "/var/log/snort/alert"
    "/var/log/nids.log"
)

collect_firewall_logs() {
    echo "[*] Collecting firewall logs..."
    
    # Extract firewall-related lines from system logs
    for logfile in "${FIREWALL_LOGS[@]}"; do
        if [ -f "$logfile" ] && [ -r "$logfile" ]; then
            # Look for common firewall patterns
            grep -i -E "(UFW BLOCK|iptables|firewall|block|reject|drop)" "$logfile" 2>/dev/null || true
        fi
    done
}

collect_ids_logs() {
    echo "[*] Collecting IDS logs..."
    
    # Try to collect from Suricata JSON format
    for logfile in "${IDS_LOGS[@]}"; do
        if [ -f "$logfile" ] && [ -r "$logfile" ]; then
            # If it's JSON, collect recent entries
            if [[ "$logfile" == *.json ]]; then
                tail -100 "$logfile" 2>/dev/null || true
            else
                tail -100 "$logfile" 2>/dev/null || true
            fi
        fi
    done
}

main() {
    echo "AstroSIEM Network Log Collection"
    echo "================================"
    
    mkdir -p "$STATE_DIR"
    
    # Clear previous network log
    > "$NETWORK_LOG"
    
    # Collect and combine all network logs
    {
        echo "# AstroSIEM Network Logs - $(date -Iseconds)"
        echo "# Format: firewall | ids"
        echo ""
        
        # Get hostname
        HOSTNAME=$(hostname)
        
        # Collect firewall logs
        collect_firewall_logs | while read -r line; do
            if [ -n "$line" ]; then
                echo "[FIREWALL] $line"
            fi
        done
        
        # Collect IDS logs  
        collect_ids_logs | while read -r line; do
            if [ -n "$line" ]; then
                echo "[IDS] $line"
            fi
        done
        
    } > "$NETWORK_LOG"
    
    # Count collected entries
    TOTAL=$(wc -l < "$NETWORK_LOG")
    echo "[+] Collected $TOTAL network log entries"
    echo "[+] Network logs saved to: $NETWORK_LOG"
}

main "$@"
