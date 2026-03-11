@echo off
:: ============================================================
:: WifiTool Windows Setup Script
:: Double-click (or run as Administrator) to install all
:: dependencies and prepare WifiTool for use.
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

echo.
echo ============================================================
echo   WifiTool Windows Setup
echo ============================================================
echo.

:: ---- 1. Python ----------------------------------------------
echo [1/4] Checking for Python...
python --version >nul 2>&1
if %errorLevel% neq 0 (
    echo   Python not found.  Installing via winget...
    winget install --id Python.Python.3 --source winget --accept-package-agreements --accept-source-agreements
    if %errorLevel% neq 0 (
        echo.
        echo   ERROR: winget could not install Python.
        echo   Please install Python 3.8+ manually from https://python.org
        echo   then re-run this script.
        echo.
        pause
        exit /b 1
    )
    echo.
    echo   Python installed.  Please CLOSE this window and re-run
    echo   setup.bat so the new Python PATH is picked up.
    echo.
    pause
    exit /b 0
) else (
    for /f "tokens=*" %%v in ('python --version 2^>^&1') do echo   Found %%v
)

:: ---- 2. Python dependencies (rich + scapy) -----------------
echo.
echo [2/4] Installing Python dependencies (rich, scapy)...
python -m pip install --upgrade pip --quiet
python -m pip install -r requirements.txt
if %errorLevel% neq 0 (
    echo.
    echo   ERROR: pip install failed.
    echo   Make sure you have an internet connection and try again.
    echo.
    pause
    exit /b 1
)
echo   Dependencies installed.

:: ---- 3. Optional Wi-Fi tools via winget --------------------
echo.
echo [3/4] Optional Wi-Fi tools
echo   The following tools can be installed via winget:
echo     - aircrack-ng  (airodump-ng, aireplay-ng, aircrack-ng)
echo     - hashcat      (GPU-accelerated password cracking)
echo     - Git          (needed to clone KRACK test scripts)
echo.
set /p INSTALL_TOOLS="   Install these tools now? [Y/n]: "
if /i not "%INSTALL_TOOLS%"=="n" (
    echo.
    echo   Installing aircrack-ng...
    winget install --id Aircrack-ng.Aircrack-ng --source winget --accept-package-agreements --accept-source-agreements
    echo   Installing hashcat...
    winget install --id Hashcat.Hashcat --source winget --accept-package-agreements --accept-source-agreements
    echo   Installing Git...
    winget install --id Git.Git --source winget --accept-package-agreements --accept-source-agreements
    echo   Wi-Fi tools install commands completed.
    echo   (Some may already be installed or require a PATH refresh.)
)

:: ---- 4. Npcap reminder -------------------------------------
echo.
echo [4/4] Npcap (REQUIRED for monitor mode and packet capture)
echo.
echo   Npcap is NOT available via winget and must be installed manually.
echo.
echo   Download from: https://npcap.com/#download
echo   During installation, enable:
echo     "Support raw 802.11 traffic (monitor mode)"
echo.
set /p OPEN_NPCAP="   Open the Npcap download page in your browser now? [Y/n]: "
if /i not "%OPEN_NPCAP%"=="n" (
    start https://npcap.com/#download
)

:: ---- Done --------------------------------------------------
echo.
echo ============================================================
echo   Setup complete!
echo ============================================================
echo.
echo   To run WifiTool:
echo     - Double-click  WifiTool.bat  (recommended)
echo     - Or open an Administrator PowerShell and run:
echo         python main.py
echo.
echo   WifiTool requires Administrator privileges to enable
echo   monitor mode and capture packets.
echo.
pause
