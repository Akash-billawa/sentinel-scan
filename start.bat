@echo off
title SentinelScan AI
cd /d "%~dp0"

REM Check for Administrator privileges
net session >nul 2>&1
if %errorLevel% == 0 (
    goto :run
) else (
    echo ============================================
    echo   Requesting Administrator privileges...
    echo ============================================
    powershell -Command "Start-Process '%~dpnx0' -Verb RunAs"
    exit /b
)

:run
echo ============================================
echo   SentinelScan AI - Starting (Elevated)...
echo ============================================
echo.
REM Activate virtual environment if present
if exist "venv\Scripts\activate.bat" (
    call venv\Scripts\activate.bat
) else if exist ".venv\Scripts\activate.bat" (
    call .venv\Scripts\activate.bat
)
python run.py
echo.
echo ============================================
echo   Server stopped. Press any key to exit.
echo ============================================
pause >nul
