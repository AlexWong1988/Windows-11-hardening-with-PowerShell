@echo off
REM ═══════════════════════════════════════════════════════════════════════════
REM  Windows 11 Hardening Suite — Main Launcher
REM  CIS Benchmark L1 + Microsoft Security Baseline
REM ═══════════════════════════════════════════════════════════════════════════

setlocal enabledelayedexpansion
cd /d "%~dp0"

cls
color 0A
echo.
echo ╔═══════════════════════════════════════════════════════════════════════╗
echo ║         Windows 11 Security Hardening Suite v1.0                     ║
echo ║     CIS Benchmark L1 + Microsoft Security Baseline (Nov 2023)        ║
echo ║                    LLSG Digital Services                             ║
echo ╚═══════════════════════════════════════════════════════════════════════╝
echo.

REM ─────────────────────────────────────────────────────────────────────────
REM  Check for Administrator rights
REM ─────────────────────────────────────────────────────────────────────────
net session >nul 2>&1
if %errorlevel% neq 0 (
  echo ✗ ERROR: This script requires Administrator privileges.
  echo.
  echo Please:
  echo   1. Right-click this batch file
  echo   2. Select "Run as Administrator"
  echo.
  pause
  exit /b 1
)

echo ✓ Administrator privileges confirmed
echo.

REM ─────────────────────────────────────────────────────────────────────────
REM  Menu
REM ─────────────────────────────────────────────────────────────────────────
:menu
echo ┌─────────────────────────────────────────────────────────────────────┐
echo │                          Main Menu                                  │
echo ├─────────────────────────────────────────────────────────────────────┤
echo │ [1] Run Hardening Script                                            │
echo │     Apply security controls to this PC                              │
echo │     Estimated time: 5-10 minutes                                    │
echo │                                                                     │
echo │ [2] View Report Dashboard                                           │
echo │     Visualize hardening results from previous runs                  │
echo │     Open the HTML report viewer in your browser                     │
echo │                                                                     │
echo │ [3] View Documentation                                              │
echo │     Open the technical documentation (Word)                         │
echo │                                                                     │
echo │ [4] Open PowerShell ISE for Editing                                 │
echo │     Review or modify the hardening script before running            │
echo │                                                                     │
echo │ [5] Exit                                                            │
echo │                                                                     │
echo └─────────────────────────────────────────────────────────────────────┘
echo.

set /p choice="Enter your choice (1-5): "

if "%choice%"=="1" goto :hardening
if "%choice%"=="2" goto :dashboard
if "%choice%"=="3" goto :docs
if "%choice%"=="4" goto :ise
if "%choice%"=="5" goto :exit_clean
echo ✗ Invalid choice. Please enter 1-5.
echo.
goto :menu

REM ─────────────────────────────────────────────────────────────────────────
REM  Option 1: Run Hardening Script
REM ─────────────────────────────────────────────────────────────────────────
:hardening
cls
echo.
echo ╔═══════════════════════════════════════════════════════════════════════╗
echo ║                    RUNNING HARDENING SCRIPT                          ║
echo ╚═══════════════════════════════════════════════════════════════════════╝
echo.

REM Check if the PS1 script exists
if not exist "Harden-Windows11.ps1" (
  echo ✗ ERROR: Harden-Windows11.ps1 not found in %cd%
  echo.
  echo Please ensure the script file is in the same directory.
  echo.
  pause
  goto :menu
)

echo Warnings:
echo   • This script applies 300+ security controls.
echo   • Some settings may conflict with existing Group Policy.
echo   • It is STRONGLY RECOMMENDED to test in non-production first.
echo   • A restart will be required after completion.
echo.
echo ───────────────────────────────────────────────────────────────────────
echo.

set /p confirm="Do you want to continue? (Y/N): "
if /i not "%confirm%"=="Y" (
  echo Cancelled.
  echo.
  goto :menu
)

echo.
echo Starting PowerShell…
echo.
timeout /t 2 /nobreak

REM Launch PowerShell as Administrator with the script
powershell -NoProfile -ExecutionPolicy Bypass -File "Harden-Windows11.ps1"

echo.
echo ───────────────────────────────────────────────────────────────────────
echo Hardening script execution completed.
echo.
echo Next steps:
echo   1. Review the log file in C:\HardeningLog_*.txt
echo   2. Review the CSV results in C:\HardeningLog_*.csv
echo   3. Use the Report Dashboard to visualize the results
echo   4. Restart the PC to activate all settings
echo.
pause
goto :menu

REM ─────────────────────────────────────────────────────────────────────────
REM  Option 2: View Report Dashboard
REM ─────────────────────────────────────────────────────────────────────────
:dashboard
cls
echo.
echo ╔═══════════════════════════════════════════════════════════════════════╗
echo ║                   REPORT DASHBOARD VIEWER                            ║
echo ╚═══════════════════════════════════════════════════════════════════════╝
echo.

if not exist "Win11-Hardening-Report-Dashboard.html" (
  echo ✗ ERROR: Win11-Hardening-Report-Dashboard.html not found
  echo.
  echo Please ensure the dashboard file is in the same directory.
  echo.
  pause
  goto :menu
)

echo Opening dashboard in your default browser…
echo.

REM Open the HTML file in the default browser
start "" "Win11-Hardening-Report-Dashboard.html"

echo.
echo Dashboard opened. Use the file upload feature to load your hardening CSV.
echo.
echo CSV files are located at:  C:\HardeningLog_*.csv
echo.
timeout /t 3 /nobreak
goto :menu

REM ─────────────────────────────────────────────────────────────────────────
REM  Option 3: View Documentation
REM ─────────────────────────────────────────────────────────────────────────
:docs
cls
echo.
echo ╔═══════════════════════════════════════════════════════════════════════╗
echo ║                    TECHNICAL DOCUMENTATION                           ║
echo ╚═══════════════════════════════════════════════════════════════════════╝
echo.

if not exist "Windows11_Hardening_Documentation.docx" (
  echo ✗ ERROR: Windows11_Hardening_Documentation.docx not found
  echo.
  echo Please ensure the documentation file is in the same directory.
  echo.
  pause
  goto :menu
)

echo Opening documentation…
echo.

REM Open the Word document
start "" "Windows11_Hardening_Documentation.docx"

echo.
echo Documentation opened in Microsoft Word.
echo.
timeout /t 2 /nobreak
goto :menu

REM ─────────────────────────────────────────────────────────────────────────
REM  Option 4: Open PowerShell ISE
REM ─────────────────────────────────────────────────────────────────────────
:ise
cls
echo.
echo ╔═══════════════════════════════════════════════════════════════════════╗
echo ║                  POWERSHELL ISE EDITOR                               ║
echo ╚═══════════════════════════════════════════════════════════════════════╝
echo.

if not exist "Harden-Windows11.ps1" (
  echo ✗ ERROR: Harden-Windows11.ps1 not found
  echo.
  pause
  goto :menu
)

echo Opening PowerShell ISE…
echo.

REM Open in PowerShell ISE
powershell -NoProfile -Command "ise Harden-Windows11.ps1"

goto :menu

REM ─────────────────────────────────────────────────────────────────────────
REM  Exit
REM ─────────────────────────────────────────────────────────────────────────
:exit_clean
cls
echo.
echo ╔═══════════════════════════════════════════════════════════════════════╗
echo ║                          Goodbye!                                    ║
echo ╚═══════════════════════════════════════════════════════════════════════╝
echo.
echo For support, contact: Digital Services (LLSG)
echo Documentation: Windows11_Hardening_Documentation.docx
echo.
exit /b 0
