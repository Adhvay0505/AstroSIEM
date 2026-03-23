import os
import json
from pathlib import Path

# Get the directory where this script is located
SCRIPT_DIR = Path(__file__).parent.resolve()
ENGINE_DIR = SCRIPT_DIR.parent

# Define absolute paths
FIM_LOG_DIR = ENGINE_DIR / "incoming-logs"
OUTPUT_JSON = ENGINE_DIR / "processed-data" / "events-fim-processed.json"

# Convert to strings for compatibility
FIM_LOG_DIR = str(FIM_LOG_DIR)
OUTPUT_JSON = str(OUTPUT_JSON)


def parse_fim_logs():
    parsed_entries = []
    for fname in os.listdir(FIM_LOG_DIR):
        # Accept both _fim.log and _fim.json files
        if fname.endswith("_fim.log") or fname.endswith("_fim.json"):
            full_path = os.path.join(FIM_LOG_DIR, fname)
            with open(full_path, "r") as f:
                content = f.read().strip()
                if not content:
                    continue
                # Handle both line-by-line JSON and single JSON array
                try:
                    # Try parsing as single JSON array first
                    data = json.loads(content)
                    if isinstance(data, list):
                        parsed_entries.extend(data)
                    else:
                        parsed_entries.append(data)
                except json.JSONDecodeError:
                    # Fall back to line-by-line JSON
                    for line in content.split("\n"):
                        line = line.strip()
                        if line:
                            try:
                                entry = json.loads(line)
                                parsed_entries.append(entry)
                            except json.JSONDecodeError:
                                continue

    parsed_entries.sort(key=lambda x: x["timestamp_utc"], reverse=True)

    os.makedirs(os.path.dirname(OUTPUT_JSON), exist_ok=True)
    with open(OUTPUT_JSON, "w") as f:
        json.dump(parsed_entries, f, indent=2)

    print(f"Parsed {len(parsed_entries)} FIM entries.")


if __name__ == "__main__":
    parse_fim_logs()
