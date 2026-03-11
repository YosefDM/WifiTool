@echo off
:: ============================================================
:: WifiTool Launcher
:: Double-click this file to start WifiTool.
:: It will request Administrator privileges automatically.
:: ============================================================

:: ---- Self-elevate to Administrator -------------------------
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo Requesting Administrator privileges...
    PowerShell -Command "Start-Process -FilePath '%~dpnx0' -Verb RunAs"
    exit /b
)

:: ---- Move to the folder that contains this script ----------
cd /d "%~dp0"

:: ---- Sanity-check: Python installed? -----------------------
python --version >nul 2>&1
if %errorLevel% neq 0 (
    echo.
    echo   ERROR: Python is not installed or not on PATH.
    echo   Please run setup.bat first to install all dependencies.
    echo.
    pause
    exit /b 1
)

:: ---- Launch WifiTool ---------------------------------------
python main.py

:: Keep window open if the app exits with an error
if %errorLevel% neq 0 (
    echo.
    echo   WifiTool exited with an error (code %errorLevel%).
    pause
)
