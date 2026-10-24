@echo off
setlocal
echo ======================================================================
echo  Running Agentic PQC Smart Door Lock Master Test Suite
echo ======================================================================
cd /d "%~dp0backend"
.venv\Scripts\python.exe -m unittest discover -s tests -t . -p "test_*.py" -v
pause
