@echo off
title Cyber Home Shield - Backend Server
echo Starting Cyber Home Shield FastAPI Backend...
if exist "%~dp0.venv\Scripts\python.exe" (
    "%~dp0.venv\Scripts\python.exe" -m uvicorn app.main:app --reload
) else (
    python -m uvicorn app.main:app --reload
)
pause
