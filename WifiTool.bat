@echo off
:: ============================================================
:: WifiTool Launcher
:: Double-click to pull latest changes and start WifiTool.
:: ============================================================

cd /d "%~dp0"

:: ---- If already elevated (second pass), skip straight to launch ---
if "%1"=="--elevated" goto :run_app

:: ---- First pass: running as normal user ----------------------
:: Do git pull HERE, before elevation, so your user credentials work.
if exist ".git" (
    echo Checking for updates...
    echo.
    git pull 2>&1
    echo.
    echo   Now running:
    git log --oneline -1
    echo.
)

python -m pip install -r requirements.txt --quiet

:: ---- Re-launch this script as Administrator ------------------
echo Requesting Administrator privileges...
PowerShell -Command "Start-Process -FilePath '%~dpnx0' -ArgumentList '--elevated' -Verb RunAs"
exit /b

:: ---- Elevated pass: just launch the app ---------------------
:run_app
python main.py

if %errorLevel% neq 0 (
    echo.
    echo   WifiTool exited with an error (code %errorLevel%).
    pause
)
