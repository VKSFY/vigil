@echo off
REM Installs deps, creates a Start Menu shortcut for the tray app, and
REM registers an HKCU\...\Run key so the tray launches at login.
REM Run from the repo root:  installer\install.bat
setlocal EnableDelayedExpansion

REM This script lives in <root>\installer\, so the repo is one level up.
set "REPO_ROOT=%~dp0.."
pushd "%REPO_ROOT%"
set "REPO_ROOT=%CD%"
popd

echo.
echo ===== Vigil installer =====
echo  repo:        %REPO_ROOT%
where python >nul 2>&1
if errorlevel 1 (
    echo  ERROR: python not on PATH. Install Python 3.10+ first.
    exit /b 1
)

echo.
echo [1/3] Installing Python dependencies from requirements.txt...
python -m pip install --upgrade pip
if errorlevel 1 goto :pip_fail
python -m pip install -r "%REPO_ROOT%\requirements.txt"
if errorlevel 1 goto :pip_fail

echo.
echo [2/3] Creating Start Menu shortcut...
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0create_shortcut.ps1" -RepoRoot "%REPO_ROOT%"
if errorlevel 1 (
    echo  WARNING: shortcut creation failed. Continuing.
)

echo.
echo [3/3] Registering tray app to start on login...
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0register_runkey.ps1" -RepoRoot "%REPO_ROOT%"
if errorlevel 1 (
    echo  WARNING: Run-key registration failed. Continuing.
)

echo.
echo ===== install complete =====
echo  - Launch via Start Menu -^> "Vigil"
echo  - Or run:  python -m antivirus
echo.
echo To uninstall the autostart hook:
echo   reg delete HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v AVMonitor /f
exit /b 0

:pip_fail
echo  ERROR: pip install failed. Check internet connection and rerun.
exit /b 1
