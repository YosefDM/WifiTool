@echo off
:: ============================================================
:: WifiTool Launcher
:: Double-click to pull latest changes and start WifiTool.
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

:: ---- Pull latest changes from GitHub ----------------------
echo Checking for updates...
git pull
if %errorLevel% neq 0 (
    echo.
    echo   WARNING: git pull failed. Running with current local code.
    echo.
)

:: ---- Install any new dependencies --------------------------
python -m pip install -r requirements.txt --quiet

:: ---- Launch WifiTool ---------------------------------------
python main.py

:: Keep window open if the app exits with an error
if %errorLevel% neq 0 (
    echo.
    echo   WifiTool exited with an error (code %errorLevel%).
    pause
)
