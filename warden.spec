# PyInstaller spec: one self-contained, windowed Warden.exe (no console window).
# Build:  pyinstaller --noconfirm warden.spec   ->   dist\Warden.exe
# Data files land at the same relative paths the code resolves from __file__
# (rules/, assets/, desktop/assets/), so no frozen-mode path logic is needed.

a = Analysis(
    ["desktop/main.py"],
    pathex=["."],
    datas=[
        ("rules", "rules"),
        ("assets/logo.ico", "assets"),
        ("assets/logo_report.png", "assets"),
        ("desktop/assets", "desktop/assets"),
    ],
    # dnfile is imported inside a try/except (optional .NET checks); name it
    # explicitly so the frozen EXE always bundles it.
    hiddenimports=["dnfile"],
    excludes=["tkinter", "matplotlib", "numpy", "pandas", "PyQt5", "PyQt6", "IPython", "pytest"],
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="Warden",
    console=False,
    icon="assets/logo.ico",
    upx=False,
)
