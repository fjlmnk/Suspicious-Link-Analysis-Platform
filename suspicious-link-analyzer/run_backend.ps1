# Suspicious Link Analyzer - Backend Launcher (PowerShell)
$Host.UI.RawUI.WindowTitle = "Suspicious Link Analyzer - Backend (FastAPI)"
Set-Location "$PSScriptRoot\backend"

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "   Starting Suspicious Link Analyzer - Backend API" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

if (-not (Test-Path "venv")) {
    Write-Host "[INFO] Creating Python virtual environment..." -ForegroundColor Yellow
    python -m venv venv
}

Write-Host "[INFO] Activating virtual environment..." -ForegroundColor Yellow
& ".\venv\Scripts\Activate.ps1"

Write-Host "[INFO] Installing / updating backend dependencies..." -ForegroundColor Yellow
pip install -r requirements.txt

Write-Host "[INFO] Starting FastAPI application on http://127.0.0.1:8000 ..." -ForegroundColor Green
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
