Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host " Starting Agentic PQC Smart Door Lock Server" -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan
$backendDir = Join-Path $PSScriptRoot "backend"
& "$PSScriptRoot\update_ip.ps1"
Set-Location $backendDir
if (-not (Test-Path ".venv\Scripts\python.exe")) {
    Write-Host "Virtual environment not found. Running setup first..." -ForegroundColor Yellow
    & "$PSScriptRoot\setup_windows.ps1"
}
& .venv\Scripts\python.exe app.py
