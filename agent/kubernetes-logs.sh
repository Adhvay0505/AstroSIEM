#!/bin/bash
# AstroSIEM Agent - Kubernetes Log Collector
# Collects Kubernetes audit, pod, and node logs for SIEM analysis
# Only runs if Kubernetes is detected

STATE_DIR="/var/lib/astro-siem"
K8S_LOG="$STATE_DIR/kubernetes-logs.log"

K8S_LOG_PATHS=(
    "/var/log/kube-apiserver.log"
    "/var/log/kube-controller-manager.log"
    "/var/log/kube-scheduler.log"
    "/var/log/kubelet.log"
    "/var/log/kube-proxy.log"
    "/var/log/pods/*.log"
    "/var/log/kubernetes/audit.log"
)

detect_kubernetes() {
    # Check if we're running in Kubernetes
    if [ -f /var/run/secrets/kubernetes.io/serviceaccount/token ]; then
        echo "in_cluster"
    elif command -v kubectl &> /dev/null; then
        # Try to get cluster info
        if kubectl cluster-info &> /dev/null; then
            echo "kubectl"
        else
            echo "none"
        fi
    elif [ -d /etc/kubernetes ]; then
        echo "local"
    else
        echo "none"
    fi
}

collect_kubectl_logs() {
    echo "[*] Collecting Kubernetes logs via kubectl..."
    
    # Get pods across all namespaces
    for ns in default kube-system kube-public; do
        kubectl get pods -n "$ns" -o json 2>/dev/null | jq -r '.items[] | select(.status.phase=="Running") | "\(.metadata.namespace)/\(.metadata.name)"' 2>/dev/null | head -20 | while read -r pod; do
            echo "# Pod: $pod"
            kubectl logs -n "${pod%/*}" "${pod#*/}" --tail 50 2>/dev/null | while read -r line; do
                echo "[K8S_POD] namespace=${pod%/*} pod=${pod#*/} $line"
            done
        done
    done
    
    # Get events
    kubectl get events --sort-by='.lastTimestamp' --field-selector type=Warning -n default -o json 2>/dev/null | jq -r '.items[] | "# \(.reason): \(.message)"' 2>/dev/null | head -50 | while read -r line; do
        echo "[K8S_EVENT] $line"
    done
    
    # Get component status
    kubectl get componentstatuses -o json 2>/dev/null | jq -r '.items[] | select(.conditions[] | select(.type=="Healthy" and .status!="True")) | "# Component: \(.name) - \(.conditions[].message)"' 2>/dev/null | while read -r line; do
        echo "[K8S_COMPONENT] $line"
    done
}

collect_k8s_file_logs() {
    echo "[*] Collecting Kubernetes logs from files..."
    
    for logfile in "${K8S_LOG_PATHS[@]}"; do
        if [[ "$logfile" == *\** ]]; then
            # Glob pattern
            for file in $logfile; do
                if [ -f "$file" ] && [ -r "$file" ]; then
                    echo "# Source: $file"
                    tail -100 "$file" 2>/dev/null | while read -r line; do
                        echo "[K8S_LOG] source=$(basename "$file") $line"
                    done
                fi
            done
        else
            if [ -f "$logfile" ] && [ -r "$logfile" ]; then
                echo "# Source: $logfile"
                tail -100 "$logfile" 2>/dev/null | while read -r line; do
                    echo "[K8S_LOG] source=$(basename "$logfile") $line"
                done
            fi
        fi
    done
}

main() {
    echo "AstroSIEM Kubernetes Log Collection"
    echo "==================================="
    
    mkdir -p "$STATE_DIR"
    
    K8S_TYPE=$(detect_kubernetes)
    
    if [ "$K8S_TYPE" = "none" ]; then
        echo "[!] Kubernetes not detected, collecting from log files only"
    else
        echo "[*] Detected Kubernetes mode: $K8S_TYPE"
    fi
    
    > "$K8S_LOG"
    
    {
        echo "# AstroSIEM Kubernetes Logs - $(date -Iseconds)"
        echo "# Format: [K8S_POD] | [K8S_EVENT] | [K8S_LOG] | [K8S_AUDIT]"
        echo ""
        
        HOSTNAME=$(hostname)
        
        # Collect from files
        collect_k8s_file_logs
        
        # Collect via kubectl if available
        if [ "$K8S_TYPE" = "kubectl" ] || [ "$K8S_TYPE" = "in_cluster" ]; then
            collect_kubectl_logs
        fi
        
        # Try Kubernetes audit log if exists
        if [ -f /var/log/kubernetes/audit.log ]; then
            tail -100 /var/log/kubernetes/audit.log 2>/dev/null | while read -r line; do
                echo "[K8S_AUDIT] $line"
            done
        fi
        
    } > "$K8S_LOG"
    
    TOTAL=$(wc -l < "$K8S_LOG")
    echo "[+] Collected $TOTAL Kubernetes log entries"
    echo "[+] Kubernetes logs saved to: $K8S_LOG"
}

main "$@"
