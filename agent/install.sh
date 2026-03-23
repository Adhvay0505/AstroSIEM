#!/bin/bash
set -euo pipefail

# AstroSIEM Unified Agent Installer
# ==================================
# One-command installer for all Linux distributions

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AGENT_INSTALL_DIR="/opt/astro-siem/agent"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
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

# Function to detect Linux distribution
detect_distro() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        echo "$ID"
    else
        echo "unknown"
    fi
}

# Function to install Apache
install_apache() {
    local distro="$1"
    
    print_info "Installing Apache for $distro..."
    
    case "$distro" in
        debian|ubuntu)
            apt-get update
            apt-get install -y apache2
            systemctl enable apache2
            systemctl start apache2
            ;;
        fedora|rhel|centos)
            dnf install -y httpd
            systemctl enable httpd
            systemctl start httpd
            ;;
        opensuse*|suse*)
            zypper --non-interactive --gpg-auto-import-keys install --no-recommends --auto-agree-with-licenses apache2
            systemctl enable apache2
            systemctl start apache2
            ;;
        arch)
            pacman -S --noconfirm apache
            systemctl enable httpd
            systemctl start httpd
            ;;
        *)
            print_error "Unknown distribution: $distro"
            print_info "Attempting to install Apache with apt-get..."
            apt-get update
            apt-get install -y apache2
            systemctl enable apache2
            systemctl start apache2
            ;;
    esac
    
    print_success "Apache installed and started"
}

# Function to get Apache service name
get_apache_service() {
    local distro="$1"
    case "$distro" in
        debian|ubuntu|opensuse*|suse*)
            echo "apache2"
            ;;
        fedora|rhel|centos|arch)
            echo "httpd"
            ;;
        *)
            echo "apache2"
            ;;
    esac
}

# Function to get Apache config directory
get_apache_conf_dir() {
    local distro="$1"
    case "$distro" in
        debian|ubuntu)
            echo "/etc/apache2/conf-available"
            ;;
        fedora|rhel|centos)
            echo "/etc/httpd/conf.d"
            ;;
        opensuse*|suse*)
            echo "/etc/apache2/conf.d"
            ;;
        arch)
            echo "/etc/httpd/conf/extra"
            ;;
        *)
            echo "/etc/apache2/conf-available"
            ;;
    esac
}

# Function to configure Apache
configure_apache() {
    local distro="$1"
    local apache_service
    apache_service=$(get_apache_service "$distro")
    local conf_dir
    conf_dir=$(get_apache_conf_dir "$distro")
    
    print_info "Configuring Apache..."
    
    # Create Apache configuration
    mkdir -p "$conf_dir"
    
    cat > "$conf_dir/astro-siem.conf" << 'EOF'
# AstroSIEM Agent Log Export Configuration
Alias /log_export /var/lib/astro-siem/exports
ScriptAlias /vuln-scan/trigger /opt/astro-siem/agent/vuln-trigger.cgi

<Directory /var/lib/astro-siem/exports>
    Options Indexes FollowSymLinks
    AllowOverride None
    Require all granted
</Directory>

<Directory /opt/astro-siem/agent>
    Options +ExecCGI
    AddHandler cgi-script .cgi
    AllowOverride None
    Require all granted
</Directory>
EOF
    
    print_success "Apache configuration created"
    
    # Enable configuration based on distro
    case "$distro" in
        debian|ubuntu)
            if command -v a2enconf &> /dev/null; then
                a2enconf astro-siem
            fi
            if command -v a2enmod &> /dev/null; then
                a2enmod cgi >/dev/null 2>&1 || a2enmod cgid >/dev/null 2>&1 || true
            fi
            ;;
    esac
    
    # Restart Apache
    systemctl restart "$apache_service"
    print_success "Apache restarted"
}

# Function to install systemd service
install_systemd_service() {
    print_info "Installing systemd service and timer..."
    
    # Copy service file
    cat > /etc/systemd/system/astro-siem-agent.service << EOF
[Unit]
Description=AstroSIEM Unified Agent - Log Exporter
After=network.target

[Service]
Type=oneshot
ExecStart=$AGENT_INSTALL_DIR/agent-http-server.sh
User=root
StandardOutput=journal
StandardError=journal
EOF
    
    # Copy timer file
    cat > /etc/systemd/system/astro-siem-agent.timer << 'EOF'
[Unit]
Description=AstroSIEM Agent - Daily log export
Requires=astro-siem-agent.service

[Timer]
OnCalendar=daily
Persistent=true
RandomizedDelaySec=300

[Install]
WantedBy=timers.target
EOF
    
    # Reload systemd
    systemctl daemon-reload
    
    # Enable timer
    systemctl enable astro-siem-agent.timer

    # Install vulnerability scan service
    cat > /etc/systemd/system/astro-siem-vuln-scan.service << EOF
[Unit]
Description=AstroSIEM Vulnerability Scan Trigger
After=network.target

[Service]
Type=oneshot
ExecStart=$AGENT_INSTALL_DIR/run-vuln-scan.sh
User=root
StandardOutput=journal
StandardError=journal
EOF

    systemctl daemon-reload
    
    print_success "Systemd service and timer installed"
}

# Function to install agent files
install_agent_files() {
    print_info "Installing agent files..."
    
    # Create installation directory
    mkdir -p "$AGENT_INSTALL_DIR"
    
    # Copy agent script
    cp "$SCRIPT_DIR/agent-http-server.sh" "$AGENT_INSTALL_DIR/"
    chmod +x "$AGENT_INSTALL_DIR/agent-http-server.sh"
    
    # Copy FIM script
    if [ -f "$SCRIPT_DIR/fim-agent.py" ]; then
        cp "$SCRIPT_DIR/fim-agent.py" "$AGENT_INSTALL_DIR/"
        chmod +x "$AGENT_INSTALL_DIR/fim-agent.py"
        print_success "FIM agent installed"
    fi
    
    # Copy network logs script
    if [ -f "$SCRIPT_DIR/network-logs.sh" ]; then
        cp "$SCRIPT_DIR/network-logs.sh" "$AGENT_INSTALL_DIR/"
        chmod +x "$AGENT_INSTALL_DIR/network-logs.sh"
        print_success "Network log collector installed"
    fi

    # Copy vulnerability scan trigger runner
    if [ -f "$SCRIPT_DIR/run-vuln-scan.sh" ]; then
        cp "$SCRIPT_DIR/run-vuln-scan.sh" "$AGENT_INSTALL_DIR/"
        chmod +x "$AGENT_INSTALL_DIR/run-vuln-scan.sh"
        print_success "Vulnerability scan runner installed"
    fi

    # Copy asset inventory exporter
    if [ -f "$SCRIPT_DIR/export-asset-inventory.sh" ]; then
        cp "$SCRIPT_DIR/export-asset-inventory.sh" "$AGENT_INSTALL_DIR/"
        chmod +x "$AGENT_INSTALL_DIR/export-asset-inventory.sh"
        print_success "Asset inventory exporter installed"
    fi

    # Copy Apache CGI trigger endpoint
    if [ -f "$SCRIPT_DIR/vuln-trigger.cgi" ]; then
        cp "$SCRIPT_DIR/vuln-trigger.cgi" "$AGENT_INSTALL_DIR/"
        chmod +x "$AGENT_INSTALL_DIR/vuln-trigger.cgi"
        print_success "Vulnerability scan trigger endpoint installed"
    fi
    
    print_success "Agent files installed to $AGENT_INSTALL_DIR"
}

# Main installation
main() {
    echo "========================================"
    echo "AstroSIEM Unified Agent Installer"
    echo "========================================"
    echo ""
    
    # Check if running as root
    if [ "$EUID" -ne 0 ]; then
        print_error "This script must be run as root"
        print_info "Please run: sudo $0"
        exit 1
    fi
    
    # Detect distribution
    local distro
    distro=$(detect_distro)
    print_info "Detected distribution: $distro"
    
    # Install Apache
    install_apache "$distro"
    
    # Configure Apache
    configure_apache "$distro"
    
    # Install agent files
    install_agent_files
    
    # Install systemd service
    install_systemd_service
    
    # Create necessary directories
    mkdir -p /var/lib/astro-siem/exports
    
    # Run initial export
    print_info "Running initial log export..."
    if "$AGENT_INSTALL_DIR/agent-http-server.sh"; then
        print_success "Initial export completed"
    else
        print_error "Initial export failed, but installation is complete"
    fi
    
    # Start timer
    systemctl start astro-siem-agent.timer
    
    # Get IP for display
    local ip
    ip=$(hostname -I | awk '{print $1}')
    
    echo ""
    echo "========================================"
    print_success "Installation Complete!"
    echo "========================================"
    echo ""
    echo "Agent Status:"
    systemctl status astro-siem-agent.timer --no-pager
    echo ""
    echo "Agent URL: http://$ip/log_export/latest/"
    echo "Vuln Trigger URL: http://$ip/vuln-scan/trigger"
    echo ""
    echo "The agent will automatically export logs every 24 hours."
    echo "To manually trigger an export: sudo systemctl start astro-siem-agent"
    echo ""
    echo "Installation directory: $AGENT_INSTALL_DIR"
    echo "Export directory: /var/lib/astro-siem/exports/"
    echo "========================================"
}

# Run main installation
main "$@"
