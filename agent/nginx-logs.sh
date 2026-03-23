#!/bin/bash
# AstroSIEM Agent - Nginx Log Collector
# Collects Nginx access and error logs for SIEM analysis

STATE_DIR="/var/lib/astro-siem"
NGINX_LOG="$STATE_DIR/nginx-logs.log"

NGINX_LOG_PATHS=(
    "/var/log/nginx/access.log"
    "/var/log/nginx/error.log"
    "/var/log/nginx/ssl_access.log"
    "/var/log/nginx/ssl_error.log"
)

main() {
    echo "AstroSIEM Nginx Log Collection"
    echo "==============================="
    
    mkdir -p "$STATE_DIR"
    
    > "$NGINX_LOG"
    
    {
        echo "# AstroSIEM Nginx Logs - $(date -Iseconds)"
        echo "# Format: [NGINX_ACCESS] | [NGINX_ERROR]"
        echo ""
        
        HOSTNAME=$(hostname)
        
        # Collect access logs
        for logfile in "/var/log/nginx/access.log" "/var/log/nginx/ssl_access.log"; do
            if [ -f "$logfile" ] && [ -r "$logfile" ]; then
                tail -200 "$logfile" 2>/dev/null | while read -r line; do
                    echo "[NGINX_ACCESS] $line"
                done
            fi
        done
        
        # Collect error logs
        for logfile in "/var/log/nginx/error.log" "/var/log/nginx/ssl_error.log"; do
            if [ -f "$logfile" ] && [ -r "$logfile" ]; then
                tail -200 "$logfile" 2>/dev/null | while read -r line; do
                    echo "[NGINX_ERROR] $line"
                done
            fi
        done
        
    } > "$NGINX_LOG"
    
    TOTAL=$(wc -l < "$NGINX_LOG")
    echo "[+] Collected $TOTAL Nginx log entries"
    echo "[+] Nginx logs saved to: $NGINX_LOG"
}

main "$@"
