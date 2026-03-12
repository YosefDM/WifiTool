<#
.SYNOPSIS
    Build the WifiTool Windows installer (WifiTool-Setup.exe).

.DESCRIPTION
    This script:
      1. Downloads the pre-built Windows binaries for aircrack-ng, hashcat,
         and the Npcap driver installer into installer\assets\.
      2. Installs PyInstaller and all Python runtime dependencies.
      3. Runs PyInstaller to produce dist\WifiTool\ (the standalone EXE bundle).
      4. Runs the Inno Setup 6 compiler (ISCC.exe) to produce
         installer\Output\WifiTool-Setup.exe.

.PARAMETER SkipDownloads
    Skip re-downloading assets that already exist in installer\assets\.

.PARAMETER SkipPyInstaller
    Skip the PyInstaller step (useful when dist\WifiTool\ already exists).

.EXAMPLE
    # Full build from a clean repo:
    powershell -ExecutionPolicy Bypass -File installer\build_installer.ps1

    # Rebuild installer only (keep existing assets + dist):
    powershell -ExecutionPolicy Bypass -File installer\build_installer.ps1 `
               -SkipDownloads -SkipPyInstaller

.NOTES
    Requirements:
      - Windows 10/11, x64
      - Python 3.8+  (https://python.org — add to PATH during install)
      - Inno Setup 6 (https://jrsoftware.org/isinfo.php)
      - 7-Zip        (https://www.7-zip.org)  — needed to extract hashcat .7z
      - Internet access to download aircrack-ng, hashcat, and Npcap
#>
param(
    [switch]$SkipDownloads,
    [switch]$SkipPyInstaller
)

$ErrorActionPreference = "Stop"

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
$ScriptDir  = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot   = Split-Path -Parent $ScriptDir
$AssetsDir  = Join-Path $ScriptDir  "assets"
$OutputDir  = Join-Path $ScriptDir  "Output"
$DistDir    = Join-Path $RepoRoot   "dist"

# ---------------------------------------------------------------------------
# Tool download URLs (update version numbers here when new releases ship)
# ---------------------------------------------------------------------------
$AircrackVersion = "1.7"
$AircrackUrl     = "https://download.aircrack-ng.org/aircrack-ng-$AircrackVersion-win.zip"

$HashcatVersion  = "6.2.6"
$HashcatUrl      = "https://hashcat.net/files/hashcat-$HashcatVersion.7z"

$NpcapVersion    = "1.79"
$NpcapUrl        = "https://npcap.com/dist/npcap-$NpcapVersion.exe"

# ---------------------------------------------------------------------------
# Helper: write coloured status messages
# ---------------------------------------------------------------------------
function Write-Step([string]$Msg) {
    Write-Host "`n>>> $Msg" -ForegroundColor Cyan
}
function Write-OK([string]$Msg) {
    Write-Host "    [OK] $Msg" -ForegroundColor Green
}
function Write-Info([string]$Msg) {
    Write-Host "    $Msg" -ForegroundColor Gray
}

# ---------------------------------------------------------------------------
# Helper: find 7-Zip on common install paths
# ---------------------------------------------------------------------------
function Find-7Zip {
    $candidates = @(
        (Get-Command "7z" -ErrorAction SilentlyContinue)?.Source,
        "$Env:ProgramFiles\7-Zip\7z.exe",
        "${Env:ProgramFiles(x86)}\7-Zip\7z.exe"
    ) | Where-Object { $_ -and (Test-Path $_) }
    return ($candidates | Select-Object -First 1)
}

# ---------------------------------------------------------------------------
# 1. Create assets directory
# ---------------------------------------------------------------------------
Write-Step "Preparing assets directory"
New-Item -ItemType Directory -Force -Path $AssetsDir | Out-Null
Write-OK "Assets dir: $AssetsDir"

# ---------------------------------------------------------------------------
# 2. Download external tools
# ---------------------------------------------------------------------------
if (-not $SkipDownloads) {

    Write-Step "Downloading Npcap $NpcapVersion"
    $NpcapDest = Join-Path $AssetsDir "npcap-installer.exe"
    if (Test-Path $NpcapDest) {
        Write-Info "Already downloaded — skipping."
    } else {
        Invoke-WebRequest -Uri $NpcapUrl -OutFile $NpcapDest -UseBasicParsing
        Write-OK "Saved: $NpcapDest"
    }

    Write-Step "Downloading aircrack-ng $AircrackVersion"
    $AircrackDir = Join-Path $AssetsDir "aircrack-ng"
    if (Test-Path $AircrackDir) {
        Write-Info "Already extracted — skipping."
    } else {
        $AircrackZip = Join-Path $AssetsDir "aircrack-ng.zip"
        Invoke-WebRequest -Uri $AircrackUrl -OutFile $AircrackZip -UseBasicParsing
        Write-Info "Extracting..."
        $TempExtract = Join-Path $AssetsDir "_aircrack_tmp"
        Expand-Archive -Path $AircrackZip -DestinationPath $TempExtract -Force
        Remove-Item $AircrackZip
        # Find the directory containing airodump-ng.exe (may be nested)
        $ExeFile = Get-ChildItem -Path $TempExtract -Recurse -Filter "airodump-ng.exe" |
                   Select-Object -First 1
        if (-not $ExeFile) {
            throw "airodump-ng.exe not found in the aircrack-ng archive."
        }
        Move-Item -Path $ExeFile.DirectoryName -Destination $AircrackDir
        Remove-Item $TempExtract -Recurse -Force -ErrorAction SilentlyContinue
        Write-OK "Extracted to: $AircrackDir"
    }

    Write-Step "Downloading hashcat $HashcatVersion"
    $HashcatDir = Join-Path $AssetsDir "hashcat"
    if (Test-Path $HashcatDir) {
        Write-Info "Already extracted — skipping."
    } else {
        $SevenZip = Find-7Zip
        if (-not $SevenZip) {
            Write-Host @"
    ERROR: 7-Zip is required to extract hashcat ($HashcatUrl).
    Install 7-Zip from https://www.7-zip.org and re-run this script,
    or manually download and extract hashcat to:
        $HashcatDir
"@ -ForegroundColor Red
            exit 1
        }
        $HashcatArchive = Join-Path $AssetsDir "hashcat.7z"
        Invoke-WebRequest -Uri $HashcatUrl -OutFile $HashcatArchive -UseBasicParsing
        Write-Info "Extracting with 7-Zip..."
        $TempExtract = Join-Path $AssetsDir "_hashcat_tmp"
        & $SevenZip x $HashcatArchive "-o$TempExtract" -y | Out-Null
        Remove-Item $HashcatArchive
        # The archive contains a single top-level folder (e.g. hashcat-6.2.6/)
        $TopDir = Get-ChildItem -Path $TempExtract -Directory | Select-Object -First 1
        if (-not $TopDir) {
            throw "Could not find extracted hashcat directory."
        }
        Move-Item -Path $TopDir.FullName -Destination $HashcatDir
        Remove-Item $TempExtract -Recurse -Force -ErrorAction SilentlyContinue
        Write-OK "Extracted to: $HashcatDir"
    }

} else {
    Write-Info "Skipping downloads (-SkipDownloads)."
}

# ---------------------------------------------------------------------------
# 3. Download and filter wordlists (WPA2-compatible passwords, 8-63 chars)
# ---------------------------------------------------------------------------
if (-not $SkipDownloads) {
    Write-Step "Downloading and filtering wordlists"
    $WordlistDir  = Join-Path $AssetsDir "wordlists"
    $WordlistFile = Join-Path $WordlistDir "wifitool-wordlist.txt"

    if (Test-Path $WordlistFile) {
        Write-Info "Wordlist already built — skipping."
    } else {
        New-Item -ItemType Directory -Force -Path $WordlistDir | Out-Null

        $PythonScript = @'
import urllib.request, gzip, os, sys

SOURCES = [
    ("rockyou_2025_00", "https://raw.githubusercontent.com/josuamarcelc/common-password-list/main/rockyou_2025_00.txt", False),
    ("rockyou_2025_01", "https://raw.githubusercontent.com/josuamarcelc/common-password-list/main/rockyou_2025_01.txt", False),
    ("rockyou_2025_02", "https://raw.githubusercontent.com/josuamarcelc/common-password-list/main/rockyou_2025_02.txt", False),
    ("rockyou_2025_03", "https://raw.githubusercontent.com/josuamarcelc/common-password-list/main/rockyou_2025_03.txt", False),
    ("rockyou_2025_04", "https://raw.githubusercontent.com/josuamarcelc/common-password-list/main/rockyou_2025_04.txt", False),
    ("rockyou_2025_05", "https://raw.githubusercontent.com/josuamarcelc/common-password-list/main/rockyou_2025_05.txt", False),
    ("totse.info",      "https://raw.githubusercontent.com/josuamarcelc/common-password-list/main/totse.info.txt",       False),
    ("openwall",        "https://raw.githubusercontent.com/josuamarcelc/common-password-list/main/openwall.net.gz",      True),
]

out_file = sys.argv[1]
total = 0
with open(out_file, "w", encoding="utf-8", errors="ignore") as fout:
    for label, url, is_gz in SOURCES:
        print(f"  Downloading {label}...")
        try:
            with urllib.request.urlopen(url, timeout=120) as resp:
                data = resp.read()
            if is_gz:
                data = gzip.decompress(data)
            count = 0
            for line in data.decode("utf-8", errors="ignore").splitlines():
                word = line.strip()
                if 8 <= len(word) <= 63:
                    fout.write(word + "\n")
                    count += 1
            total += count
            print(f"    {count:,} WPA2-compatible passwords")
        except Exception as exc:
            print(f"    WARNING: {exc}", file=sys.stderr)

size_mb = os.path.getsize(out_file) / 1024 / 1024
print(f"  Wordlist: {out_file} ({size_mb:.1f} MB, {total:,} passwords)")
'@
        $TmpScript = [System.IO.Path]::GetTempFileName() + ".py"
        Set-Content -Path $TmpScript -Value $PythonScript -Encoding UTF8
        python $TmpScript $WordlistFile
        Remove-Item $TmpScript
        Write-OK "Wordlist ready: $WordlistFile"
    }
} else {
    Write-Info "Skipping wordlist download (-SkipDownloads)."
}

# ---------------------------------------------------------------------------
# 4. Verify required assets exist
# ---------------------------------------------------------------------------
Write-Step "Verifying assets"
$Required = @{
    "Npcap installer"    = Join-Path $AssetsDir "npcap-installer.exe"
    "aircrack-ng dir"    = Join-Path $AssetsDir "aircrack-ng"
    "hashcat dir"        = Join-Path $AssetsDir "hashcat"
    "wordlist"           = Join-Path $AssetsDir "wordlists\wifitool-wordlist.txt"
}
foreach ($label in $Required.Keys) {
    $path = $Required[$label]
    if (-not (Test-Path $path)) {
        Write-Host "    MISSING: $label  ($path)" -ForegroundColor Red
        Write-Host "    Run without -SkipDownloads, or add the file manually." -ForegroundColor Red
        exit 1
    }
    Write-OK "$label : $path"
}

# ---------------------------------------------------------------------------
# 5. Install Python build dependencies (PyInstaller + runtime deps)
# ---------------------------------------------------------------------------
Write-Step "Installing Python build dependencies"
Set-Location $RepoRoot
python -m pip install --upgrade pip --quiet
# Pin PyInstaller to a known-good version for reproducible builds.
# Runtime dependencies (rich, scapy) come from requirements.txt.
python -m pip install "pyinstaller==6.3.0" --quiet
python -m pip install -r requirements.txt --quiet
Write-OK "Python dependencies installed."

# ---------------------------------------------------------------------------
# 6. Build the WifiTool EXE with PyInstaller
# ---------------------------------------------------------------------------
if (-not $SkipPyInstaller) {
    Write-Step "Building WifiTool.exe with PyInstaller"
    Set-Location $RepoRoot
    $SpecFile = Join-Path $RepoRoot "WifiTool.spec"
    pyinstaller $SpecFile --noconfirm
    if ($LASTEXITCODE -ne 0) {
        Write-Host "PyInstaller failed." -ForegroundColor Red
        exit 1
    }
    Write-OK "PyInstaller output: $DistDir\WifiTool\"
} else {
    Write-Info "Skipping PyInstaller (-SkipPyInstaller)."
    if (-not (Test-Path "$DistDir\WifiTool\WifiTool.exe")) {
        Write-Host "    ERROR: dist\WifiTool\WifiTool.exe not found." -ForegroundColor Red
        Write-Host "    Run without -SkipPyInstaller to build it first." -ForegroundColor Red
        exit 1
    }
}

# ---------------------------------------------------------------------------
# 7. Compile the Inno Setup installer
# ---------------------------------------------------------------------------
Write-Step "Compiling Windows installer with Inno Setup 6"

$IssFile = Join-Path $ScriptDir "WifiTool.iss"
$InnoExe = @(
    "$Env:ProgramFiles (x86)\Inno Setup 6\ISCC.exe",
    "$Env:ProgramFiles\Inno Setup 6\ISCC.exe"
) | Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1

if (-not $InnoExe) {
    Write-Host @"
    ERROR: Inno Setup 6 compiler (ISCC.exe) not found.
    Download and install Inno Setup 6 from: https://jrsoftware.org/isinfo.php
    Then re-run this script.
"@ -ForegroundColor Red
    exit 1
}

& $InnoExe $IssFile
if ($LASTEXITCODE -ne 0) {
    Write-Host "Inno Setup compilation failed." -ForegroundColor Red
    exit 1
}

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------
$InstallerExe = Get-ChildItem -Path $OutputDir -Filter "WifiTool-Setup-*.exe" |
                Select-Object -First 1 -ExpandProperty FullName
Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host "  Build complete!" -ForegroundColor Green
Write-Host "  Installer: $InstallerExe" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
