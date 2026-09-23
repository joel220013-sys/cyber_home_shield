# Cyber Home Shield - Backend Server Launcher
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  Starting Cyber Home Shield Backend (FastAPI)...        " -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Cyan

$venvPython = "$PSScriptRoot\.venv\Scripts\python.exe"
if (Test-Path $venvPython) {
    & $venvPython -m uvicorn app.main:app --reload
} else {
    python -m uvicorn app.main:app --reload
}
