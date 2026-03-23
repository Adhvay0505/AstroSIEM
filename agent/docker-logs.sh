#!/bin/bash
# AstroSIEM Agent - Docker Log Collector
# Collects Docker daemon and container logs for SIEM analysis

STATE_DIR="/var/lib/astro-siem"
DOCKER_LOG="$STATE_DIR/docker-logs.log"

main() {
    echo "AstroSIEM Docker Log Collection"
    echo "==============================="
    
    mkdir -p "$STATE_DIR"
    
    > "$DOCKER_LOG"
    
    {
        echo "# AstroSIEM Docker Logs - $(date -Iseconds)"
        echo "# Format: [DOCKER_DAEMON] | [DOCKER_CONTAINER]"
        echo ""
        
        HOSTNAME=$(hostname)
        
        # Check if Docker is available
        if command -v docker &> /dev/null; then
            # Collect container logs (last 50 containers, 100 lines each)
            echo "[*] Collecting Docker container logs..."
            for container_id in $(docker ps -a --format "{{.ID}}" 2>/dev/null | head -50); do
                container_name=$(docker inspect --format='{{.Name}}' "$container_id" 2>/dev/null | sed 's/\///')
                container_image=$(docker inspect --format='{{.Config.Image}}' "$container_id" 2>/dev/null)
                
                echo "# Container: $container_name (Image: $container_image)"
                docker logs --tail 100 "$container_id" 2>&1 | while read -r line; do
                    echo "[DOCKER_CONTAINER] container=$container_name image=$container_image $line"
                done
            done
            
            # Collect Docker daemon logs if accessible
            if [ -r "/var/log/docker.log" ]; then
                echo "# Docker daemon log"
                tail -200 "/var/log/docker.log" 2>/dev/null | while read -r line; do
                    echo "[DOCKER_DAEMON] $line"
                done
            fi
            
            # Also check journalctl for Docker
            if command -v journalctl &> /dev/null; then
                echo "# Docker daemon (journalctl)"
                journalctl -u docker.service --no-pager -n 200 2>/dev/null | while read -r line; do
                    echo "[DOCKER_DAEMON] $line"
                done
            fi
        else
            echo "[!] Docker command not available"
            
            # Try to collect from log files directly
            for logfile in /var/lib/docker/containers/*/*.log; do
                if [ -f "$logfile" ] && [ -r "$logfile" ]; then
                    container_name=$(basename "$logfile" .log)
                    echo "# Container log: $container_name"
                    tail -100 "$logfile" 2>/dev/null | while read -r line; do
                        echo "[DOCKER_CONTAINER] container=$container_name $line"
                    done
                fi
            done
        fi
        
    } > "$DOCKER_LOG"
    
    TOTAL=$(wc -l < "$DOCKER_LOG")
    echo "[+] Collected $TOTAL Docker log entries"
    echo "[+] Docker logs saved to: $DOCKER_LOG"
}

main "$@"
