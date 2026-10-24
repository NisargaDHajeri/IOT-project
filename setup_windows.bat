@echo off
setlocal enabledelayedexpansion

echo ======================================================================
echo  AGENTIC AI ADAPTIVE PQC SMART DOOR LOCK - WINDOWS SETUP
echo ======================================================================

cd /d "%~dp0backend"

echo [1/3] Preparing Python Virtual Environment (.venv)...
if not exist ".venv\Scripts\python.exe" (
    py -3.13 -m venv .venv 2>nul || py -3 -m venv .venv 2>nul || python -m venv .venv
)

echo [2/3] Installing Python Dependencies from requirements.txt...
.venv\Scripts\python.exe -m pip install --upgrade pip
.venv\Scripts\python.exe -m pip install -r requirements.txt

echo [3/3] Training Machine Learning Risk Model...
.venv\Scripts\python.exe ml\train_model.py

echo.
echo ======================================================================
echo  Setup Completed Successfully on Windows!
echo  To start the server: run_server.bat
echo  To run the test suite: run_tests.bat
echo ======================================================================
pause
