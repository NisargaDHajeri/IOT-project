Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host " Starting Google Sheets Background Synchronizer" -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan
$backendDir = Join-Path $PSScriptRoot "backend"
Set-Location $backendDir
& .venv\Scripts\python.exe sync_google_sheets.py --interval 3
