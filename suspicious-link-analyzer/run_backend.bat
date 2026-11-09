@echo off
title Suspicious Link Analyzer - Backend (FastAPI)
cd /d "%~dp0backend"

echo ============================================================
echo   Starting Suspicious Link Analyzer - Backend API
echo ============================================================

if not exist venv (
    echo [INFO] Creating Python virtual environment...
    python -m venv venv
)

echo [INFO] Activating virtual environment...
call venv\Scripts\activate

echo [INFO] Installing / updating backend dependencies...
pip install -r requirements.txt

echo [INFO] Starting FastAPI application on http://localhost:8000 ...
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
pause
