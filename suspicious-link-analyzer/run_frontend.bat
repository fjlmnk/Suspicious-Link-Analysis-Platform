@echo off
title Suspicious Link Analyzer - Frontend (React Vite)
cd /d "%~dp0frontend"

echo ============================================================
echo   Starting Suspicious Link Analyzer - React Frontend
echo ============================================================

echo [INFO] Installing frontend dependencies...
call npm install

echo [INFO] Starting Vite development server on http://localhost:5173 ...
call npm run dev
pause
