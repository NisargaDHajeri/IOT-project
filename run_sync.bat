@echo off
setlocal
echo ======================================================================
echo  Starting Google Sheets Background Synchronizer
echo ======================================================================
cd /d "%~dp0backend"
.venv\Scripts\python.exe sync_google_sheets.py --interval 3
pause
