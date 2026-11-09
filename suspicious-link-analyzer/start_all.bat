@echo off
title Suspicious Link Analyzer - Launcher
cd /d "%~dp0"

echo ============================================================
echo   Suspicious Link Analysis Platform
echo ============================================================
echo Starting Backend API in a separate window...
start "Suspicious Link Analyzer - Backend" cmd /c "run_backend.bat"

timeout /t 3 /nobreak >nul

echo Starting Frontend Dev Server in a separate window...
start "Suspicious Link Analyzer - Frontend" cmd /c "run_frontend.bat"

echo.
echo Application is starting!
echo - Backend API:  http://localhost:8000 (Docs: http://localhost:8000/docs)
echo - Frontend Web: http://localhost:5173
echo.
pause
