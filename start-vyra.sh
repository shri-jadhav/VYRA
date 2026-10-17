#!/usr/bin/env bash
# ==============================================================================
# VYRA — Cloud Security Workbench Developer Launch Script (macOS / Linux)
# Tagline: Find the change. Prevent the regression. Verify the fix.
# ==============================================================================

set -euo pipefail

echo "=================================================================="
echo "   VYRA — Cloud Security Workbench [v1.0.0]"
echo "   Tagline: Find the change. Prevent the regression. Verify the fix."
echo "=================================================================="

# 1. Environment file check
if [ ! -f ".env" ]; then
    echo "[+] Creating .env from .env.example (Safe default offline demo mode)..."
    cp .env.example .env
fi

# 2. Virtual Environment check
if [ ! -f "venv/bin/python" ]; then
    echo "[+] Creating Python virtual environment..."
    python3 -m venv venv
    ./venv/bin/pip install --upgrade pip
    ./venv/bin/pip install -r requirements.txt
fi

echo "[✓] Python environment verified."

# 3. Check and build frontend if needed
if [ -d "frontend" ] && [ -f "frontend/package.json" ]; then
    if [ ! -f "frontend/dist/index.html" ]; then
        echo "[+] Building frontend bundle..."
        (cd frontend && npm install && npm run build)
    fi
    echo "[✓] Frontend production bundle ready."
fi

echo ""
echo "------------------------------------------------------------------"
echo "   MODE: Safe Offline Demo Mode (Zero AWS network calls)"
echo "   API:  http://127.0.0.1:8000 (Docs: /docs)"
echo "   UI:   http://127.0.0.1:5173 (or run 'npm run dev' in frontend/)"
echo "------------------------------------------------------------------"
echo ""
echo "Starting VYRA API server (Press Ctrl+C to terminate)..."

./venv/bin/python -m backend.app.cli start --host 127.0.0.1 --port 8000
