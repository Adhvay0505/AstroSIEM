#!/bin/bash
set -euo pipefail

# AstroSIEM Unified Agent - Log Export Script
# ============================================
# Auto-detects distro, discovers log sources, exports incrementally
# Runs via systemd timer every 24 hours

# State and export directories
STATE_DIR="/var/lib/astro-siem"
EXPORT_BASE_DIR="$STATE_DIR/exports"
LAST_RUN_FILE="$STATE_DIR/last_export"

# Function to detect Linux distribution
detect_distro() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        echo "$ID"
    else
        echo "unknown"
    fi
}

# Function to get Apache service name and web root
get_apache_info() {
    local distro="$1"
    case "$distro" in
        debian|ubuntu)
            echo "apache2:/var/www/html"
            ;;
        fedora|rhel|centos)
            echo "httpd:/var/www/html"
            ;;
        opensuse*|suse*)
            echo "apache2:/srv/www/htdocs"
            ;;
        arch)
            echo "httpd:/srv/http"
            ;;
        *)
            echo "apache2:/var/www/html"
            ;;
    esac
}

# Function to get package manager and Apache package name
get_package_info() {
    local distro="$1"
    case "$distro" in
        debian|ubuntu)
            echo "apt-get:apache2"
            ;;
        fedora|rhel|centos)
            echo "dnf:httpd"
            ;;
        opensuse*|suse*)
            echo "zypper:apache2"
            ;;
        arch)
            echo "pacman:apache"
            ;;
        *)
            echo "apt-get:apache2"
            ;;
    esac
}

# Function to export journald logs (incremental)
export_journald() {
    local output_dir="$1"
    
    if ! command -v journalctl &> /dev/null; then
        echo "[!] journalctl not found, skipping journald export"
        return 0
    fi
    
    echo "[*] Exporting journald logs..."
    
    if [ -f "$LAST_RUN_FILE" ]; then
        local since
        since=$(cat "$LAST_RUN_FILE")
        if journalctl --since "$since" -o json > "$output_dir/journald.json" 2>/dev/null; then
            echo "[+] Exported journald logs since $since"
        else
            echo "[!] Failed to export journald logs, continuing..."
        fi
    else
        # First run - export last 24 hours
        if journalctl --since "24 hours ago" -o json > "$output_dir/journald.json" 2>/dev/null; then
            echo "[+] Exported journald logs (last 24 hours)"
        else
            echo "[!] Failed to export journald logs, continuing..."
        fi
    fi
}

# Function to export traditional syslog files
export_syslog_files() {
    local output_dir="$1"
    local exported_count=0
    
    echo "[*] Checking for traditional syslog files..."
    
    for logfile in /var/log/auth.log /var/log/secure /var/log/messages /var/log/syslog; do
        if [ -f "$logfile" ] && [ -r "$logfile" ]; then
            local basename
            basename=$(basename "$logfile")
            if cp "$logfile" "$output_dir/$basename" 2>/dev/null; then
                chmod 644 "$output_dir/$basename"
                echo "[+] Exported $logfile"
                ((exported_count++))
            else
                echo "[!] Failed to export $logfile, continuing..."
            fi
        fi
    done
    
    if [ $exported_count -eq 0 ]; then
        echo "[!] No traditional syslog files found or readable"
    fi
}

# Function to run FIM and export FIM logs
export_fim() {
    local output_dir="$1"
    
    echo "[*] Running FIM scan..."
    
    local fim_script="/opt/astro-siem/agent/fim-agent.py"
    
    if [ -f "$fim_script" ]; then
        if python3 "$fim_script" > /dev/null 2>&1; then
            local fim_log="/var/lib/astro-siem/fim-changes.log"
            if [ -f "$fim_log" ] && [ -s "$fim_log" ]; then
                cp "$fim_log" "$output_dir/fim.json"
                chmod 644 "$output_dir/fim.json"
                echo "[+] Exported FIM changes"
                
                # Clear the FIM log after export
                > "$fim_log"
            else
                echo "[*] No FIM changes to export"
            fi
        else
            echo "[!] FIM scan failed"
        fi
    else
        echo "[*] FIM script not found, skipping..."
    fi
}

# Function to run network log collection and export
export_network() {
    local output_dir="$1"
    
    echo "[*] Running network log collection..."
    
    local network_script="/opt/astro-siem/agent/network-logs.sh"
    
    if [ -f "$network_script" ]; then
        if bash "$network_script" > /dev/null 2>&1; then
            local network_log="/var/lib/astro-siem/network-changes.log"
            if [ -f "$network_log" ] && [ -s "$network_log" ]; then
                cp "$network_log" "$output_dir/network.log"
                chmod 644 "$output_dir/network.log"
                echo "[+] Exported network logs"
                
                # Clear the network log after export
                > "$network_log"
            else
                echo "[*] No network logs to export"
            fi
        else
            echo "[!] Network log collection failed"
        fi
    else
        echo "[*] Network log script not found, skipping..."
    fi
}

# Function to run Apache log collection and export
export_apache() {
    local output_dir="$1"
    
    echo "[*] Running Apache log collection..."
    
    local apache_script="/opt/astro-siem/agent/apache-logs.sh"
    
    if [ -f "$apache_script" ]; then
        if bash "$apache_script" > /dev/null 2>&1; then
            local apache_log="/var/lib/astro-siem/apache-logs.log"
            if [ -f "$apache_log" ] && [ -s "$apache_log" ]; then
                cp "$apache_log" "$output_dir/apache.log"
                chmod 644 "$output_dir/apache.log"
                echo "[+] Exported Apache logs"
                
                > "$apache_log"
            else
                echo "[*] No Apache logs to export"
            fi
        else
            echo "[!] Apache log collection failed"
        fi
    else
        echo "[*] Apache log script not found, skipping..."
    fi
}

# Function to run Nginx log collection and export
export_nginx() {
    local output_dir="$1"
    
    echo "[*] Running Nginx log collection..."
    
    local nginx_script="/opt/astro-siem/agent/nginx-logs.sh"
    
    if [ -f "$nginx_script" ]; then
        if bash "$nginx_script" > /dev/null 2>&1; then
            local nginx_log="/var/lib/astro-siem/nginx-logs.log"
            if [ -f "$nginx_log" ] && [ -s "$nginx_log" ]; then
                cp "$nginx_log" "$output_dir/nginx.log"
                chmod 644 "$output_dir/nginx.log"
                echo "[+] Exported Nginx logs"
                
                > "$nginx_log"
            else
                echo "[*] No Nginx logs to export"
            fi
        else
            echo "[!] Nginx log collection failed"
        fi
    else
        echo "[*] Nginx log script not found, skipping..."
    fi
}

# Function to run Docker log collection and export
export_docker() {
    local output_dir="$1"
    
    echo "[*] Running Docker log collection..."
    
    local docker_script="/opt/astro-siem/agent/docker-logs.sh"
    
    if [ -f "$docker_script" ]; then
        if bash "$docker_script" > /dev/null 2>&1; then
            local docker_log="/var/lib/astro-siem/docker-logs.log"
            if [ -f "$docker_log" ] && [ -s "$docker_log" ]; then
                cp "$docker_log" "$output_dir/docker.log"
                chmod 644 "$output_dir/docker.log"
                echo "[+] Exported Docker logs"
                
                > "$docker_log"
            else
                echo "[*] No Docker logs to export"
            fi
        else
            echo "[!] Docker log collection failed"
        fi
    else
        echo "[*] Docker log script not found, skipping..."
    fi
}

# Function to run Kubernetes log collection and export
export_kubernetes() {
    local output_dir="$1"
    
    echo "[*] Running Kubernetes log collection..."
    
    local k8s_script="/opt/astro-siem/agent/kubernetes-logs.sh"
    
    if [ -f "$k8s_script" ]; then
        if bash "$k8s_script" > /dev/null 2>&1; then
            local k8s_log="/var/lib/astro-siem/kubernetes-logs.log"
            if [ -f "$k8s_log" ] && [ -s "$k8s_log" ]; then
                cp "$k8s_log" "$output_dir/kubernetes.log"
                chmod 644 "$output_dir/kubernetes.log"
                echo "[+] Exported Kubernetes logs"
                
                > "$k8s_log"
            else
                echo "[*] No Kubernetes logs to export"
            fi
        else
            echo "[!] Kubernetes log collection failed"
        fi
    else
        echo "[*] Kubernetes log script not found, skipping..."
    fi
}

# Function to export host inventory
export_inventory() {
    local output_dir="$1"

    echo "[*] Exporting host inventory..."

    local inventory_script="/opt/astro-siem/agent/export-asset-inventory.sh"
    local inventory_file="/var/lib/astro-siem/asset-inventory.json"

    if [ -x "$inventory_script" ]; then
        if bash "$inventory_script" > /dev/null 2>&1 && [ -f "$inventory_file" ] && [ -s "$inventory_file" ]; then
            cp "$inventory_file" "$output_dir/inventory.json"
            chmod 644 "$output_dir/inventory.json"
            echo "[+] Exported host inventory"
        else
            echo "[!] Host inventory export failed"
        fi
    else
        echo "[*] Host inventory exporter not found, skipping..."
    fi
}

# Function to export vulnerability results
export_vulnerability_results() {
    local output_dir="$1"

    echo "[*] Exporting vulnerability results..."

    local vuln_results="/var/lib/astro-siem/vuln-results.json"
    local vuln_status="/var/lib/astro-siem/vuln-scan-status.json"

    if [ -f "$vuln_results" ] && [ -s "$vuln_results" ]; then
        cp "$vuln_results" "$output_dir/vuln-results.json"
        chmod 644 "$output_dir/vuln-results.json"
        echo "[+] Exported vulnerability results"
    else
        echo "[*] No vulnerability results to export"
    fi

    if [ -f "$vuln_status" ] && [ -s "$vuln_status" ]; then
        cp "$vuln_status" "$output_dir/vuln-status.json"
        chmod 644 "$output_dir/vuln-status.json"
        echo "[+] Exported vulnerability scan status"
    fi
}

# Function to generate manifest
export_manifest() {
    local output_dir="$1"
    local timestamp="$2"
    local distro="$3"
    
    echo "[*] Generating manifest..."
    
    # Build sources array
    local sources="["
    local first=true
    
    # Check journald
    if [ -f "$output_dir/journald.json" ]; then
        if [ "$first" = true ]; then
            first=false
        else
            sources+=","
        fi
        sources+='{"type":"journald","format":"json","filename":"journald.json","present":true}'
    fi
    
    # Check syslog files
    for logfile in auth.log secure messages syslog; do
        if [ -f "$output_dir/$logfile" ]; then
            if [ "$first" = true ]; then
                first=false
            else
                sources+=","
            fi
            sources+="{\"type\":\"syslog\",\"format\":\"text\",\"filename\":\"$logfile\",\"present\":true}"
        fi
    done
    
    # Check FIM
    if [ -f "$output_dir/fim.json" ]; then
        if [ "$first" = true ]; then
            first=false
        else
            sources+=","
        fi
        sources+='{"type":"fim","format":"json","filename":"fim.json","present":true}'
    fi
    
    # Check network logs
    if [ -f "$output_dir/network.log" ]; then
        if [ "$first" = true ]; then
            first=false
        else
            sources+=","
        fi
        sources+='{"type":"network","format":"text","filename":"network.log","present":true}'
    fi
    
    # Check Apache logs
    if [ -f "$output_dir/apache.log" ]; then
        if [ "$first" = true ]; then
            first=false
        else
            sources+=","
        fi
        sources+='{"type":"apache","format":"text","filename":"apache.log","present":true}'
    fi
    
    # Check Nginx logs
    if [ -f "$output_dir/nginx.log" ]; then
        if [ "$first" = true ]; then
            first=false
        else
            sources+=","
        fi
        sources+='{"type":"nginx","format":"text","filename":"nginx.log","present":true}'
    fi
    
    # Check Docker logs
    if [ -f "$output_dir/docker.log" ]; then
        if [ "$first" = true ]; then
            first=false
        else
            sources+=","
        fi
        sources+='{"type":"docker","format":"text","filename":"docker.log","present":true}'
    fi
    
    # Check Kubernetes logs
    if [ -f "$output_dir/kubernetes.log" ]; then
        if [ "$first" = true ]; then
            first=false
        else
            sources+=","
        fi
        sources+='{"type":"kubernetes","format":"text","filename":"kubernetes.log","present":true}'
    fi

    # Check host inventory
    if [ -f "$output_dir/inventory.json" ]; then
        if [ "$first" = true ]; then
            first=false
        else
            sources+=","
        fi
        sources+='{"type":"inventory","format":"json","filename":"inventory.json","present":true}'
    fi

    # Check vulnerability results
    if [ -f "$output_dir/vuln-results.json" ]; then
        if [ "$first" = true ]; then
            first=false
        else
            sources+=","
        fi
        sources+='{"type":"vulnerability","format":"json","filename":"vuln-results.json","present":true}'
    fi

    # Check vulnerability status
    if [ -f "$output_dir/vuln-status.json" ]; then
        if [ "$first" = true ]; then
            first=false
        else
            sources+=","
        fi
        sources+='{"type":"vulnerability_status","format":"json","filename":"vuln-status.json","present":true}'
    fi
    
    sources+="]"
    
    cat > "$output_dir/manifest.json" << EOF
{
    "export_timestamp": "$timestamp",
    "distro": "$distro",
    "sources": $sources
}
EOF
    
    echo "[+] Manifest generated"
}

# Main execution
main() {
    echo "======================================"
    echo "AstroSIEM Unified Agent - Log Export"
    echo "======================================"
    
    # Detect distribution
    local distro
    distro=$(detect_distro)
    echo "[*] Detected distribution: $distro"
    
    # Get Apache info
    local apache_info
    apache_info=$(get_apache_info "$distro")
    local apache_service="${apache_info%%:*}"
    local apache_web_root="${apache_info##*:}"
    
    # Create state directory if it doesn't exist
    mkdir -p "$STATE_DIR"
    
    # Create timestamped export directory
    local timestamp
    timestamp=$(date -Iseconds)
    local timestamp_dir
    timestamp_dir=$(date +%Y%m%d_%H%M%S)
    local export_dir="$EXPORT_BASE_DIR/$timestamp_dir"
    
    mkdir -p "$export_dir"
    echo "[*] Export directory: $export_dir"
    
    # Export journald logs
    export_journald "$export_dir"
    
    # Export syslog files
    export_syslog_files "$export_dir"
    
    # Run and export FIM logs
    export_fim "$export_dir"
    
    # Run and export network logs
    export_network "$export_dir"
    
    # Run and export Apache logs
    export_apache "$export_dir"
    
    # Run and export Nginx logs
    export_nginx "$export_dir"
    
    # Run and export Docker logs
    export_docker "$export_dir"
    
    # Run and export Kubernetes logs
    export_kubernetes "$export_dir"

    # Export host inventory
    export_inventory "$export_dir"

    # Export vulnerability results
    export_vulnerability_results "$export_dir"

    # Generate manifest
    export_manifest "$export_dir" "$timestamp" "$distro"
    
    # Update last export timestamp
    echo "$timestamp" > "$LAST_RUN_FILE"
    echo "[+] Updated last export timestamp"
    
    # Create/update latest symlink
    local web_export_dir="$apache_web_root/log_export"
    mkdir -p "$web_export_dir"
    ln -sfn "$export_dir" "$EXPORT_BASE_DIR/latest"
    ln -sfn "$EXPORT_BASE_DIR/latest" "$web_export_dir/latest"
    echo "[+] Updated 'latest' symlink"
    
    # Set permissions
    chmod -R 644 "$export_dir"/* 2>/dev/null || true
    chmod 755 "$export_dir"
    chmod 755 "$EXPORT_BASE_DIR"
    chmod 755 "$STATE_DIR"
    
    # Get IP for display
    local ip
    ip=$(hostname -I | awk '{print $1}')
    
    echo ""
    echo "======================================"
    echo "Export Complete!"
    echo "======================================"
    echo "Agent URL: http://$ip/log_export/latest/"
    echo "Exported files:"
    ls -la "$export_dir/"
    echo "======================================"
}

# Run main function
main "$@"
