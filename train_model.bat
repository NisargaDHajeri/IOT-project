@echo off
setlocal
echo ======================================================================
echo  Training Random Forest Intrusion Risk Classifier
echo ======================================================================
cd /d "%~dp0backend"
.venv\Scripts\python.exe ml\train_model.py
pause
