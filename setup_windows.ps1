Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host " AGENTIC AI ADAPTIVE PQC SMART DOOR LOCK - WINDOWS SETUP" -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan

$backendDir = Join-Path $PSScriptRoot "backend"
Push-Location $backendDir

Write-Host "[1/3] Preparing Python Virtual Environment (.venv)..." -ForegroundColor Yellow
if (-not (Test-Path ".venv\Scripts\python.exe")) {
    try {
        py -3.13 -m venv .venv
    } catch {
        python -m venv .venv
    }
}

Write-Host "[2/3] Installing Dependencies from requirements.txt..." -ForegroundColor Yellow
& .venv\Scripts\python.exe -m pip install --upgrade pip
if ($LASTEXITCODE -ne 0) { Pop-Location; exit $LASTEXITCODE }
& .venv\Scripts\python.exe -m pip install -r requirements.txt
if ($LASTEXITCODE -ne 0) { Pop-Location; exit $LASTEXITCODE }

Write-Host "[3/3] Training Machine Learning Risk Model..." -ForegroundColor Yellow
& .venv\Scripts\python.exe ml\train_model.py
if ($LASTEXITCODE -ne 0) { Pop-Location; exit $LASTEXITCODE }

Pop-Location

Write-Host "`n======================================================================" -ForegroundColor Green
Write-Host " Setup Completed Successfully on Windows!" -ForegroundColor Green
Write-Host " Run '.\run_server.ps1' to start the application." -ForegroundColor Green
Write-Host " Run '.\run_tests.ps1' to run the verification test suite." -ForegroundColor Green
Write-Host "======================================================================" -ForegroundColor Green
