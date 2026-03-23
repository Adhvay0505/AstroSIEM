#!/bin/bash

# AstroSIEM Web Dashboard Launcher
# Starts the web server so users can view the dashboard at http://127.0.0.1:8080/dashboard/

# Get the directory where this script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Navigate to the engine directory
# This allows serving both dashboard/ and processed-data/ folders
cd "$SCRIPT_DIR/engine" || {
    echo "❌ Error: Could not find engine directory"
    echo "Make sure you're running this script from the project root"
    exit 1
}

# Check if Python 3 is available
if ! command -v python3 &> /dev/null; then
    echo "❌ Error: Python 3 is not installed"
    exit 1
fi

# Check if parsed logs exist
if [ ! -f "processed-data/events-security-processed.json" ]; then
    echo "⚠️  Warning: No parsed logs found!"
    echo "   Run: python3 parsers/parse-syslog-security.py"
    echo ""
fi

# Check if port 8080 is already in use
if lsof -Pi :8080 -sTCP:LISTEN -t >/dev/null 2>&1; then
    echo "⚠️  Port 8080 is already in use."
    echo "   Trying to find an available port..."
    
    # Try ports 8081-8090
    PORT=8081
    while [ $PORT -le 8090 ]; do
        if ! lsof -Pi :$PORT -sTCP:LISTEN -t >/dev/null 2>&1; then
            break
        fi
        PORT=$((PORT + 1))
    done
    
    if [ $PORT -gt 8090 ]; then
        echo "❌ Error: Could not find an available port between 8080-8090"
        exit 1
    fi
else
    PORT=8080
fi

echo ""
echo "🚀 Starting AstroSIEM..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "🔐 Open this URL in your browser:"
echo "   http://127.0.0.1:$PORT/dashboard/login.html"
echo ""
echo "📝 To view logs:"
echo "   1. Login with your credentials"
echo "   2. If no logs appear, run: python3 parsers/parse-syslog-security.py"
echo ""
echo "⏹️  Press Ctrl+C to stop the server"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Start the AstroSIEM dashboard server with alert workflow API
python3 "$SCRIPT_DIR/engine/dashboard/server.py" --bind 127.0.0.1 --port "$PORT" --root "$SCRIPT_DIR/engine"
