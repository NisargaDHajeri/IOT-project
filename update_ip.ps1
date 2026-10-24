param(
    [string]$IpFile = (Join-Path $PSScriptRoot "ip\ipfile")
)

$envPath = Join-Path $PSScriptRoot ".env"
$port = if ($env:FLASK_PORT) { $env:FLASK_PORT } else { "5000" }

if (-not (Test-Path -LiteralPath $IpFile)) {
    throw "IP file not found: $IpFile"
}

$rawIp = Get-Content -LiteralPath $IpFile | Where-Object {
    $_.Trim() -and -not $_.Trim().StartsWith("#")
} | Select-Object -First 1

if (-not $rawIp) {
    throw "Paste this computer's Wi-Fi IPv4 address into ip\ipfile first."
}

$ip = $rawIp.Trim()
if ($ip -match "^https?://") {
    $ip = $ip -replace "^https?://", ""
    $ip = ($ip -split "/")[0]
    $ip = ($ip -split ":")[0]
}

if ($ip -notmatch "^(\d{1,3}\.){3}\d{1,3}$") {
    throw "Invalid IPv4 address in ip\ipfile: $rawIp"
}

$url = "http://${ip}:${port}"

if (Test-Path -LiteralPath $envPath) {
    $content = Get-Content -LiteralPath $envPath
} else {
    $content = @()
}

function Set-Or-AddEnvLine {
    param(
        [string[]]$Lines,
        [string]$Key,
        [string]$Value
    )

    $pattern = "^$([regex]::Escape($Key))="
    $updated = $false
    $result = foreach ($line in $Lines) {
        if ($line -match $pattern) {
            $updated = $true
            "$Key=$Value"
        } else {
            $line
        }
    }

    if (-not $updated) {
        $result += "$Key=$Value"
    }

    return $result
}

$content = Set-Or-AddEnvLine -Lines $content -Key "FLASK_LAN_IP" -Value $ip
$content = Set-Or-AddEnvLine -Lines $content -Key "FLASK_BACKEND_URL" -Value $url
$content = Set-Or-AddEnvLine -Lines $content -Key "DEVICE_API_BASE_URL" -Value $url
$content | Set-Content -LiteralPath $envPath

Write-Host "Updated project IP config:" -ForegroundColor Green
Write-Host "  FLASK_LAN_IP=$ip"
Write-Host "  FLASK_BACKEND_URL=$url"
Write-Host "  DEVICE_API_BASE_URL=$url"
