# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller spec file for IronRod — Universal Data Recovery.

Usage:
    pyinstaller IronRod.spec

This produces a single-folder distribution (faster startup than --onefile).
The build scripts wrap this with platform-specific installers.
"""

import sys
import os
from PyInstaller.utils.hooks import collect_submodules

block_cipher = None

# Collect all recovery submodules automatically
hidden_imports = collect_submodules('recovery')
hidden_imports += [
    'tkinter',
    'tkinter.ttk',
    'tkinter.filedialog',
    'tkinter.messagebox',
    'tkinterweb',
    'webview',
    'PIL',
    'PIL.Image',
    'PIL.ImageFile',
    'json',
    'csv',
    'hashlib',
    'struct',
    'mmap',
    'ctypes',
    'logging',
    'threading',
    'webbrowser',
    'collections',
    'dataclasses',
    'argparse',
    'platform',
]

# Optional: pytsk3 (may not be installed)
try:
    import pytsk3
    hidden_imports.append('pytsk3')
except ImportError:
    pass

# Optional: pyewf
try:
    import pyewf
    hidden_imports.append('pyewf')
except ImportError:
    pass

a = Analysis(
    ['main.py'],
    pathex=[],
    binaries=[],
    datas=[
        ('recovery', 'recovery'),          # Include the recovery package
        ('README.md', '.'),                 # Include README
    ],
    hiddenimports=hidden_imports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        'matplotlib', 'numpy', 'scipy', 'pandas',  # Not needed
        'test', 'unittest', 'pytest',
    ],
    noarchive=False,
    optimize=0,
    cipher=block_cipher,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='IronRod',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,           # GUI app — no console window
    disable_windowed_traceback=False,
    argv_emulation=True,     # macOS argv emulation for drag-and-drop
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='assets/icon.ico' if sys.platform == 'win32' else
         'assets/icon.icns' if sys.platform == 'darwin' else
         'assets/icon.png',
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='IronRod',
)

# macOS: Create .app bundle
if sys.platform == 'darwin':
    app = BUNDLE(
        coll,
        name='IronRod.app',
        icon='assets/icon.icns',
        bundle_identifier='com.ironrod.recovery',
        info_plist={
            'CFBundleName': 'IronRod',
            'CFBundleDisplayName': 'IronRod Data Recovery',
            'CFBundleVersion': '1.0',
            'CFBundleShortVersionString': '1.0',
            'NSHighResolutionCapable': True,
            'NSRequiresAquaSystemAppearance': False,  # Support dark mode
            'LSMinimumSystemVersion': '10.15',
            'NSAppleEventsUsageDescription': 'IronRod needs access to manage disk recovery.',
            'NSSystemAdministrationUsageDescription': 'IronRod needs admin access to read raw disk sectors.',
        },
    )
