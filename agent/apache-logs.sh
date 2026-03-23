#!/bin/bash
# AstroSIEM Agent - Apache Log Collector
# Collects Apache access and error logs for SIEM analysis

STATE_DIR="/var/lib/astro-siem"
APACHE_LOG="$STATE_DIR/apache-logs.log"

# Apache log locations by distribution
APACHE_LOG_PATHS=(
    "/var/log/apache2/access.log"
    "/var/log/apache2/error.log"
    "/var/log/apache2/ssl_access.log"
    "/var/log/apache2/ssl_error.log"
    "/var/log/httpd/access_log"
    "/var/log/httpd/error_log"
    "/var/log/httpd/ssl_access_log"
    "/var/log/httpd/ssl_error_log"
    "/var/log/apache/access.log"
    "/var/log/apache/error.log"
)

collect_apache_logs() {
    echo "[*] Collecting Apache logs..."
    
    for logfile in "${APACHE_LOG_PATHS[@]}"; do
        if [ -f "$logfile" ] && [ -r "$logfile" ]; then
            # Get last 200 lines for each log
            echo "# Source: $logfile"
            tail -200 "$logfile" 2>/dev/null || true
            echo ""
        fi
    done
}

main() {
    echo "AstroSIEM Apache Log Collection"
    echo "================================"
    
    mkdir -p "$STATE_DIR"
    
    > "$APACHE_LOG"
    
    {
        echo "# AstroSIEM Apache Logs - $(date -Iseconds)"
        echo "# Format: [APACHE_ACCESS] | [APACHE_ERROR]"
        echo ""
        
        HOSTNAME=$(hostname)
        
        # Collect access logs (GET/POST requests, status codes)
        for logfile in "/var/log/apache2/access.log" "/var/log/httpd/access_log" "/var/log/apache/access.log"; do
            if [ -f "$logfile" ] && [ -r "$logfile" ]; then
                tail -200 "$logfile" 2>/dev/null | while read -r line; do
                    echo "[APACHE_ACCESS] $line"
                done
            fi
        done
        
        # Collect error logs
        for logfile in "/var/log/apache2/error.log" "/var/log/httpd/error_log" "/var/log/apache/error.log"; do
            if [ -f "$logfile" ] && [ -r "$logfile" ]; then
                tail -200 "$logfile" 2>/dev/null | while read -r line; do
                    echo "[APACHE_ERROR] $line"
                done
            fi
        done
        
    } > "$APACHE_LOG"
    
    TOTAL=$(wc -l < "$APACHE_LOG")
    echo "[+] Collected $TOTAL Apache log entries"
    echo "[+] Apache logs saved to: $APACHE_LOG"
}

main "$@"
