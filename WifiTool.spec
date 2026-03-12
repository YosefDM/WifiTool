# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec — builds a self-contained Windows EXE for WifiTool.

Build from the repository root:

    pip install pyinstaller
    pyinstaller WifiTool.spec --noconfirm

Output:  dist/WifiTool/WifiTool.exe  (and supporting files)

The resulting dist/WifiTool/ folder is bundled by the Inno Setup script
(installer/WifiTool.iss) into the final WifiTool-Setup.exe installer.
"""

block_cipher = None

a = Analysis(
    ["main.py"],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=[
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
    console=True,                   # Rich terminal UI — keep console window
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
