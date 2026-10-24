Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host " Training Random Forest Intrusion Risk Classifier" -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan
$backendDir = Join-Path $PSScriptRoot "backend"
Push-Location $backendDir
& .venv\Scripts\python.exe ml\train_model.py
$trainExitCode = $LASTEXITCODE
Pop-Location
exit $trainExitCode
