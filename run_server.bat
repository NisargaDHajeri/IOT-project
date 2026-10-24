@echo off
setlocal
echo ======================================================================
echo  Starting Agentic PQC Smart Door Lock Server
echo ======================================================================
call "%~dp0update_ip.bat"
cd /d "%~dp0backend"
if not exist ".venv\Scripts\python.exe" (
    echo Virtual environment not found. Running setup first...
    call "%~dp0setup_windows.bat"
)
.venv\Scripts\python.exe app.py
pause
