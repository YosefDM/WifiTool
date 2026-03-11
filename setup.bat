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
echo [1/5] Checking for Python...
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
echo [2/5] Installing Python dependencies (rich, scapy)...
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

:: ---- 3. Optional Wi-Fi tools --------------------------
echo.
echo [3/5] Wi-Fi tools (aircrack-ng and hashcat)
echo.
echo   aircrack-ng and hashcat are NOT available as winget or Chocolatey
echo   packages and must be installed manually from their official sites:
echo.
echo     aircrack-ng  (airodump-ng, aireplay-ng, aircrack-ng):
echo       https://www.aircrack-ng.org/downloads.html
echo       Download the Windows .zip, extract it, and add the folder to PATH.
echo.
echo     hashcat  (GPU-accelerated password cracking):
echo       https://hashcat.net/hashcat/
echo       Download the Windows .7z archive, extract it to a permanent folder,
echo       and run hashcat.exe from that folder directly.
echo       NOTE: hashcat on Windows must be run from its own directory —
echo       adding it to PATH alone is not sufficient (it cannot find its
echo       kernel files when called from a different directory).
echo.
set /p OPEN_AIRCRACK="   Open the aircrack-ng download page in your browser now? [Y/n]: "
if /i not "%OPEN_AIRCRACK%"=="n" (
    start https://www.aircrack-ng.org/downloads.html
)
set /p OPEN_HASHCAT="   Open the hashcat download page in your browser now? [Y/n]: "
if /i not "%OPEN_HASHCAT%"=="n" (
    start https://hashcat.net/hashcat/
)

:: ---- 4. Git via winget ----------------------------------
echo.
echo [4/5] Git (needed to clone KRACK test scripts)
echo.
set /p INSTALL_GIT="   Install Git via winget now? [Y/n]: "
if /i not "%INSTALL_GIT%"=="n" (
    winget install --id Git.Git --source winget --accept-package-agreements --accept-source-agreements
    echo   Git install command completed.
    echo   (Git may already be installed or require a PATH refresh.)
)

:: ---- 5. Npcap reminder -------------------------------------
echo.
echo [5/5] Npcap (REQUIRED for monitor mode and packet capture)
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
