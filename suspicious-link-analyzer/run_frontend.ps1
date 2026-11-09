# Suspicious Link Analyzer - Frontend Launcher (PowerShell)
$Host.UI.RawUI.WindowTitle = "Suspicious Link Analyzer - Frontend (React Vite)"
Set-Location "$PSScriptRoot\frontend"

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "   Starting Suspicious Link Analyzer - React Frontend" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

Write-Host "[INFO] Installing frontend dependencies..." -ForegroundColor Yellow
npm install

Write-Host "[INFO] Starting Vite development server on http://localhost:5173 ..." -ForegroundColor Green
npm run dev
