# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec — builds a self-contained Windows EXE for WifiTool.

Build from the repository root:

    pip install pyinstaller
    pyinstaller WifiTool.spec --noconfirm

Output:  dist/WifiTool/WifiTool.exe  (and supporting files)

The resulting dist/WifiTool/ folder is bundled by the Inno Setup script
(installer/WifiTool.iss) into the final WifiTool-Setup.exe installer.
"""

import os
from PyInstaller.utils.hooks import collect_data_files

block_cipher = None

# customtkinter ships JSON theme files and PNG assets it reads from disk at
# runtime.  collect_data_files() locates the installed package directory and
# returns (src, dest) pairs so PyInstaller copies them into the bundle.
_ctk_datas = collect_data_files("customtkinter")

a = Analysis(
    ["main.py"],
    pathex=[],
    binaries=[],
    datas=_ctk_datas,
    hiddenimports=[
        # customtkinter detects the OS dark/light theme via darkdetect;
        # PyInstaller does not auto-discover this dependency.
        "darkdetect",
        # scapy sub-packages are not auto-discovered by PyInstaller
        "scapy.all",
        "scapy.layers.all",
        "scapy.layers.dot11",
        "scapy.layers.l2",
        "scapy.layers.eap",
        "scapy.sendrecv",
        "scapy.utils",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="WifiTool",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,                  # GUI app — suppress the console window
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    uac_admin=True,                 # Request Administrator elevation on Windows
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name="WifiTool",
)
