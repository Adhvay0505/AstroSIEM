#!/bin/bash
set -euo pipefail

STATE_DIR="/var/lib/astro-siem"
OUTPUT_FILE="$STATE_DIR/asset-inventory.json"

mkdir -p "$STATE_DIR"

HOSTNAME_VALUE="$(hostname)"
ARCH="$(uname -m)"
KERNEL="$(uname -r)"
OS_NAME="unknown"
OS_VERSION="unknown"
PRIMARY_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
IPS_JSON="[]"
PACKAGES_JSON="[]"
SERVICES_JSON="[]"
CONFIG_CHECKS_JSON="[]"
INVENTORY_DIGEST=""
PACKAGE_COUNT=0

if [ -f /etc/os-release ]; then
  . /etc/os-release
  OS_NAME="${NAME:-${ID:-unknown}}"
  OS_VERSION="${VERSION_ID:-${VERSION:-unknown}}"
fi

if command -v systemctl >/dev/null 2>&1; then
  SERVICES_JSON="$(python3 - <<'PY'
import json, subprocess

targets = [
    "sshd.service", "ssh.service", "auditd.service", "docker.service", "containerd.service",
    "kubelet.service", "apache2.service", "httpd.service", "nginx.service", "firewalld.service", "ufw.service"
]
services = []

def run(cmd):
    try:
        return subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL).strip()
    except Exception:
        return ""

for service in targets:
    enabled = run(["systemctl", "is-enabled", service]) or "not-found"
    active = run(["systemctl", "is-active", service]) or "unknown"
    if enabled == "not-found" and active in {"unknown", ""}:
        continue
    services.append({"name": service, "enabled_state": enabled, "active_state": active})

print(json.dumps(services))
PY
)"
fi

CONFIG_CHECKS_JSON="$(python3 - <<'PY'
import json, os, subprocess
checks = []

def add(key, value, source):
    checks.append({"key": key, "value": value, "source": source})

sshd_path = "/etc/ssh/sshd_config"
if os.path.exists(sshd_path):
    values = {}
    try:
        with open(sshd_path, "r", encoding="utf-8", errors="ignore") as handle:
            for raw_line in handle:
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(None, 1)
                if len(parts) == 2:
                    values[parts[0].lower()] = parts[1]
    except Exception:
        values = {}
    add("ssh_permit_root_login", values.get("permitrootlogin", "default"), sshd_path)
    add("ssh_password_authentication", values.get("passwordauthentication", "default"), sshd_path)

if os.path.exists("/etc/sudoers"):
    add("sudoers_present", "true", "/etc/sudoers")

if os.path.exists("/var/run/docker.sock") or os.path.exists("/run/docker.sock"):
    add("docker_socket_present", "true", "/var/run/docker.sock")

try:
    ufw_state = subprocess.check_output(["ufw", "status"], text=True, stderr=subprocess.DEVNULL).splitlines()[0].strip()
    add("firewall_status", ufw_state, "ufw")
except Exception:
    try:
        fw_state = subprocess.check_output(["firewall-cmd", "--state"], text=True, stderr=subprocess.DEVNULL).strip()
        add("firewall_status", fw_state, "firewalld")
    except Exception:
        add("firewall_status", "unknown", "system")

print(json.dumps(checks))
PY
)"

if command -v python3 >/dev/null 2>&1; then
  IPS_JSON="$(python3 - <<'PY'
import json, subprocess
try:
    output = subprocess.check_output(["hostname", "-I"], text=True).strip().split()
except Exception:
    output = []
print(json.dumps(output))
PY
)"
fi

if command -v dpkg-query >/dev/null 2>&1; then
  PACKAGES_JSON="$(python3 - <<'PY'
import json, subprocess
pkgs = []
try:
    output = subprocess.check_output(["dpkg-query", "-W", "-f=${Package}\t${Version}\n"], text=True)
    for line in output.splitlines():
        if not line.strip():
            continue
        name, version = line.split("\t", 1)
        pkgs.append({"name": name, "version": version, "manager": "dpkg"})
except Exception:
    pass
print(json.dumps(pkgs[:500]))
PY
)"
elif command -v rpm >/dev/null 2>&1; then
  PACKAGES_JSON="$(python3 - <<'PY'
import json, subprocess
pkgs = []
try:
    output = subprocess.check_output(["rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\n"], text=True)
    for line in output.splitlines():
        if not line.strip():
            continue
        name, version = line.split("\t", 1)
        pkgs.append({"name": name, "version": version, "manager": "rpm"})
except Exception:
    pass
print(json.dumps(pkgs[:500]))
PY
)"
elif command -v pacman >/dev/null 2>&1; then
  PACKAGES_JSON="$(python3 - <<'PY'
import json, subprocess
pkgs = []
try:
    output = subprocess.check_output(["pacman", "-Q"], text=True)
    for line in output.splitlines():
        if not line.strip():
            continue
        name, version = line.split(" ", 1)
        pkgs.append({"name": name, "version": version, "manager": "pacman"})
except Exception:
    pass
print(json.dumps(pkgs[:500]))
PY
)"
fi

if command -v python3 >/dev/null 2>&1; then
  INVENTORY_META="$(python3 - "$PACKAGES_JSON" <<'PY'
import hashlib, json, sys

try:
    packages = json.loads(sys.argv[1])
except Exception:
    packages = []

digest = hashlib.sha256(json.dumps(packages, sort_keys=True).encode()).hexdigest() if packages else ""
print(json.dumps({"inventory_digest": digest, "package_count": len(packages)}))
PY
)"
  INVENTORY_DIGEST="$(printf '%s' "$INVENTORY_META" | python3 -c 'import sys, json; print(json.load(sys.stdin).get("inventory_digest",""))')"
  PACKAGE_COUNT="$(printf '%s' "$INVENTORY_META" | python3 -c 'import sys, json; print(json.load(sys.stdin).get("package_count",0))')"
fi

cat > "$OUTPUT_FILE" <<EOF
{
  "hostname": "$HOSTNAME_VALUE",
  "os_name": "$OS_NAME",
  "os_version": "$OS_VERSION",
  "kernel_version": "$KERNEL",
  "architecture": "$ARCH",
  "primary_ip": "$PRIMARY_IP",
  "ips": $IPS_JSON,
  "environment": "unknown",
  "business_criticality": "medium",
  "owner": "",
  "internet_facing": false,
  "generated_at": "$(date -Iseconds)",
  "inventory_digest": "$INVENTORY_DIGEST",
  "package_count": $PACKAGE_COUNT,
  "packages": $PACKAGES_JSON,
  "services": $SERVICES_JSON,
  "config_checks": $CONFIG_CHECKS_JSON
}
EOF

chmod 644 "$OUTPUT_FILE"
echo "$OUTPUT_FILE"
