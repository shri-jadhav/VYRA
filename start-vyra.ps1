# ==============================================================================
# VYRA — Cloud Security Workbench Developer Launch Script (Windows PowerShell)
# Tagline: Find the change. Prevent the regression. Verify the fix.
# ==============================================================================

$ErrorActionPreference = "Stop"
Write-Host "==================================================================" -ForegroundColor Cyan
Write-Host "   VYRA — Cloud Security Workbench" -ForegroundColor White -NoNewline
Write-Host " [v1.0.0]" -ForegroundColor DarkGray
Write-Host "   Tagline: Find the change. Prevent the regression. Verify the fix." -ForegroundColor DarkGray
Write-Host "==================================================================" -ForegroundColor Cyan

# 1. Environment file check
if (-not (Test-Path ".env")) {
    Write-Host "[+] Creating .env from .env.example (Safe default offline demo mode)..." -ForegroundColor Yellow
    Copy-Item ".env.example" ".env"
}

# 2. Virtual Environment check
if (-not (Test-Path "venv\Scripts\python.exe")) {
    Write-Host "[+] Creating Python virtual environment..." -ForegroundColor Yellow
    python -m venv venv
    & ".\venv\Scripts\pip.exe" install --upgrade pip
    & ".\venv\Scripts\pip.exe" install -r requirements.txt
}

Write-Host "[✓] Python environment verified." -ForegroundColor Green

# 3. Check and build frontend if needed
if (Test-Path "frontend\package.json") {
    if (-not (Test-Path "frontend\dist\index.html")) {
        Write-Host "[+] Building frontend bundle..." -ForegroundColor Yellow
        Push-Location frontend
        npm install
        npm run build
        Pop-Location
    }
    Write-Host "[✓] Frontend production bundle ready." -ForegroundColor Green
}

Write-Host ""
Write-Host "------------------------------------------------------------------" -ForegroundColor DarkGray
Write-Host "   MODE: Safe Offline Demo Mode (Zero AWS network calls)" -ForegroundColor Green
Write-Host "   API:  http://127.0.0.1:8000 (Docs: /docs)" -ForegroundColor White
Write-Host "   UI:   http://127.0.0.1:5173 (or run 'npm run dev' in frontend/)" -ForegroundColor White
Write-Host "------------------------------------------------------------------" -ForegroundColor DarkGray
Write-Host ""
Write-Host "Starting VYRA API server (Press Ctrl+C to terminate)..." -ForegroundColor Cyan

& ".\venv\Scripts\python.exe" -m backend.app.cli start --host 127.0.0.1 --port 8000
