#!/bin/bash

# AstroSIEM Unified Log Collector
# ================================
# Collects logs from all unified agents
# Fetches manifest.json first, then downloads all discovered sources
#
# Usage:
#   ./collect-logs.sh              # Collect from all agents
#   ./collect-logs.sh endpoint1    # Collect from specific agent

set -euo pipefail

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="$SCRIPT_DIR/config/agents.yaml"
CONFIG_READER="$SCRIPT_DIR/config/read_config.py"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_error() {
    echo -e "${RED}[!]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[+]${NC} $1"
}

print_info() {
    echo -e "${YELLOW}[*]${NC} $1"
}

print_agent() {
    echo -e "${BLUE}[Agent]${NC} $1"
}

# Function to check dependencies
check_dependencies() {
    # Check for Python and PyYAML
    if ! python3 -c "import yaml" 2>/dev/null; then
        print_error "Python PyYAML module not installed"
        echo "Install with: pip3 install pyyaml"
        exit 1
    fi
    
    # Check for curl
    if ! command -v curl &> /dev/null; then
        print_error "curl is not installed"
        exit 1
    fi
    
    # Check for jq
    if ! command -v jq &> /dev/null; then
        print_error "jq is not installed"
        echo "Install with: apt-get install jq (Debian/Ubuntu)"
        echo "             dnf install jq (Fedora/RHEL)"
        echo "             pacman -S jq (Arch)"
        exit 1
    fi
}

# Function to get global settings from config
get_global_setting() {
    local key="$1"
    python3 -c "
import yaml
with open('$CONFIG_FILE', 'r') as f:
    config = yaml.safe_load(f)
    print(config.get('settings', {}).get('$key', ''))
"
}

# Function to get all agent names
get_all_agents() {
    python3 "$CONFIG_READER" --list
}

# Function to get agent config
get_agent_config() {
    local agent_name="$1"
    python3 "$CONFIG_READER" "$agent_name"
}

# Function to collect logs from a single agent
collect_from_agent() {
    local agent_name="$1"
    
    print_agent "Collecting from: $agent_name"
    
    # Get agent configuration
    local agent_config
    agent_config=$(get_agent_config "$agent_name")
    
    local agent_ip
    agent_ip=$(echo "$agent_config" | python3 -c "import sys, json; print(json.load(sys.stdin)['ip'])")
    
    local description
    description=$(echo "$agent_config" | python3 -c "import sys, json; print(json.load(sys.stdin).get('description', 'No description'))")
    
    local protocol
    protocol=$(get_global_setting "protocol")
    
    local port
    port=$(get_global_setting "default_port")
    
    local timeout
    timeout=$(get_global_setting "timeout")
    
    local export_path
    export_path=$(get_global_setting "export_path")
    
    local incoming_dir
    incoming_dir=$(get_global_setting "incoming_dir")
    
    # Create incoming directory
    mkdir -p "$SCRIPT_DIR/$incoming_dir"
    
    # Build agent URL
    local agent_url="$protocol://$agent_ip:$port"
    
    print_info "Agent IP: $agent_ip"
    print_info "Description: $description"
    print_info "URL: $agent_url/$export_path/"
    
    # Step 1: Fetch manifest.json
    local manifest_url="$agent_url/$export_path/manifest.json"
    local manifest_file="/tmp/astro-siem-manifest-$agent_name.json"
    
    print_info "Fetching manifest..."
    if ! curl -s --max-time "$timeout" "$manifest_url" -o "$manifest_file" 2>/dev/null; then
        print_error "Failed to fetch manifest from $agent_name"
        print_error "URL: $manifest_url"
        return 1
    fi
    
    # Check if manifest is valid JSON
    if ! jq empty "$manifest_file" 2>/dev/null; then
        print_error "Invalid manifest JSON from $agent_name"
        rm -f "$manifest_file"
        return 1
    fi
    
    # Step 2: Parse manifest and download each source
    local sources_count
    sources_count=$(jq '.sources | length' "$manifest_file")
    
    print_success "Manifest received - Found $sources_count source(s)"
    
    local downloaded_count=0
    
    # Iterate through sources
    jq -c '.sources[]' "$manifest_file" | while read -r source; do
        local source_type
        source_type=$(echo "$source" | jq -r '.type')
        
        local filename
        filename=$(echo "$source" | jq -r '.filename')
        
        local present
        present=$(echo "$source" | jq -r '.present')
        
        if [ "$present" != "true" ]; then
            print_info "Skipping $filename (not present)"
            continue
        fi
        
        # Build source URL
        local source_url="$agent_url/$export_path/$filename"
        local local_filename="${agent_name}_${filename}"
        local dest_file="$SCRIPT_DIR/$incoming_dir/$local_filename"
        
        print_info "Downloading: $filename"
        
        if curl -s --max-time "$timeout" "$source_url" -o "$dest_file" 2>/dev/null; then
            if [ -s "$dest_file" ]; then
                local filesize
                filesize=$(du -h "$dest_file" | cut -f1)
                print_success "Downloaded: $local_filename ($filesize)"
                ((downloaded_count++))
            else
                print_error "Downloaded file is empty: $filename"
                rm -f "$dest_file"
            fi
        else
            print_error "Failed to download: $filename"
        fi
    done
    
    # Cleanup
    rm -f "$manifest_file"
    
    print_success "Collection complete for $agent_name"
    echo ""
}

# Main execution
main() {
    echo "========================================"
    echo "AstroSIEM Unified Log Collector"
    echo "========================================"
    echo ""
    
    # Check dependencies
    check_dependencies
    
    # Determine which agents to collect from
    local agents_to_collect=()
    
    if [ $# -eq 0 ]; then
        # No arguments - collect from all agents
        print_info "No agent specified, collecting from all agents..."
        while IFS= read -r agent; do
            agents_to_collect+=("$agent")
        done < <(get_all_agents)
    else
        # Collect from specified agent(s)
        agents_to_collect=("$@")
    fi
    
    if [ ${#agents_to_collect[@]} -eq 0 ]; then
        print_error "No agents configured in $CONFIG_FILE"
        exit 1
    fi
    
    print_info "Agents to collect: ${agents_to_collect[*]}"
    echo ""
    
    # Collect from each agent
    local success_count=0
    local fail_count=0
    
    for agent in "${agents_to_collect[@]}"; do
        if collect_from_agent "$agent"; then
            ((success_count++))
        else
            ((fail_count++))
        fi
    done
    
    # Summary
    echo "========================================"
    echo "Collection Summary"
    echo "========================================"
    print_success "Successful: $success_count"
    if [ $fail_count -gt 0 ]; then
        print_error "Failed: $fail_count"
    fi
    echo "========================================"
    
    # Exit with error if any collections failed
    if [ $fail_count -gt 0 ]; then
        exit 1
    fi
}

# Run main function
main "$@"
