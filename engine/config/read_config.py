#!/usr/bin/env python3
"""
Configuration reader for AstroSIEM agent settings.
Reads agent configuration from YAML file and outputs values.

Usage:
  read_config.py <agent_name>           - Get full config as JSON
  read_config.py <agent_name> <key>     - Get specific value
  read_config.py --list                 - List all agent names

Examples:
  read_config.py debian ip              # Output: 192.168.122.100
  read_config.py redhat remote_path     # Output: log_export/secure.log
  read_config.py --list                 # Output: debian, redhat, suse, arch
"""

import yaml
import sys
import json
from pathlib import Path

# Get the directory where this script is located
SCRIPT_DIR = Path(__file__).parent.resolve()
CONFIG_FILE = SCRIPT_DIR / "agents.yaml"


def load_config():
    """Load and return the full configuration."""
    try:
        with open(CONFIG_FILE, "r") as f:
            return yaml.safe_load(f)
    except FileNotFoundError:
        print(f"Error: Config file not found at {CONFIG_FILE}", file=sys.stderr)
        sys.exit(1)
    except yaml.YAMLError as e:
        print(f"Error: Invalid YAML format: {e}", file=sys.stderr)
        sys.exit(1)


def get_agent_config(agent_name):
    """Get configuration for a specific agent."""
    config = load_config()
    agents = config.get("agents", {})

    if agent_name not in agents:
        print(
            f"Error: Agent '{agent_name}' not found in configuration", file=sys.stderr
        )
        print(f"Available agents: {', '.join(agents.keys())}", file=sys.stderr)
        sys.exit(1)

    agent_config = agents[agent_name].copy()

    # Add global settings
    settings = config.get("settings", {})
    agent_config["logs_dir"] = settings.get("logs_dir", "logs")
    agent_config["protocol"] = settings.get("protocol", "http")
    agent_config["default_port"] = settings.get("default_port", 80)
    agent_config["timeout"] = settings.get("timeout", 30)

    return agent_config


def get_all_agents():
    """Get list of all configured agent names."""
    config = load_config()
    return list(config.get("agents", {}).keys())


def main():
    if len(sys.argv) < 2:
        print(__doc__, file=sys.stderr)
        print("\nAvailable agents:", file=sys.stderr)
        for agent in get_all_agents():
            print(f"  - {agent}", file=sys.stderr)
        sys.exit(1)

    if sys.argv[1] == "--list":
        # Output all agent names
        agents = get_all_agents()
        print("\n".join(agents))
        sys.exit(0)

    if sys.argv[1] in ["--help", "-h"]:
        print(__doc__)
        sys.exit(0)

    agent_name = sys.argv[1]
    agent_config = get_agent_config(agent_name)

    if len(sys.argv) >= 3:
        # Output specific key
        key = sys.argv[2]
        if key in agent_config:
            print(agent_config[key])
        else:
            print(
                f"Error: Key '{key}' not found for agent '{agent_name}'",
                file=sys.stderr,
            )
            print(f"Available keys: {', '.join(agent_config.keys())}", file=sys.stderr)
            sys.exit(1)
    else:
        # Output full config as JSON
        print(json.dumps(agent_config, indent=2))


if __name__ == "__main__":
    main()
