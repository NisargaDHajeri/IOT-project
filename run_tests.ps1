Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host " Running Agentic PQC Smart Door Lock Master Test Suite" -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan
$backendDir = Join-Path $PSScriptRoot "backend"
Push-Location $backendDir
& .venv\Scripts\python.exe -m unittest discover -s tests -t . -p "test_*.py" -v
$testExitCode = $LASTEXITCODE
Pop-Location
exit $testExitCode
