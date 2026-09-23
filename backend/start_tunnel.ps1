# Cyber Home Shield - Public Secure Cloudflare Tunnel Launcher
# Implements: Phone/Vercel -> Cloudflare -> cloudflared on PC -> FastAPI (:8000)

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "   Cyber Home Shield - Cloudflare Tunnel Launcher         " -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Cyan

$cloudflaredPath = "C:\Program Files (x86)\cloudflared\cloudflared.exe"
if (-not (Test-Path $cloudflaredPath)) {
    $cloudflaredPath = "cloudflared"
}

# Find workspace root
$rootDir = $PSScriptRoot
if (-not (Test-Path "$rootDir\src\services\api.ts")) {
    $rootDir = Split-Path -Parent $PSScriptRoot
}

$logFile = "$rootDir\tunnel.log"
if (Test-Path $logFile) {
    Remove-Item $logFile -Force -ErrorAction SilentlyContinue
}

Write-Host "[1/3] Starting Cloudflare secure tunnel to http://127.0.0.1:8000..." -ForegroundColor Yellow

$proc = Start-Process -FilePath $cloudflaredPath -ArgumentList "tunnel --url http://127.0.0.1:8000 --logfile `"$logFile`"" -PassThru -WindowStyle Hidden

$tunnelUrl = $null
$attempts = 0
while ($attempts -lt 30) {
    Start-Sleep -Seconds 1
    $attempts++
    if (Test-Path $logFile) {
        $content = Get-Content $logFile -Raw -ErrorAction SilentlyContinue
        if ($content -match 'https://[a-zA-Z0-9\.\-]+\.trycloudflare\.com') {
            $tunnelUrl = $matches[0]
            break
        }
    }
}

if ($tunnelUrl) {
    Write-Host "[2/3] Tunnel Established Successfully!" -ForegroundColor Green
    Write-Host "  Public HTTPS: $tunnelUrl" -ForegroundColor Cyan

    $apiFile = "$rootDir\src\services\api.ts"
    if (Test-Path $apiFile) {
        $apiContent = Get-Content $apiFile -Raw
        $apiContent = $apiContent -replace "export const DEFAULT_TUNNEL_URL = 'https://[^']+';", "export const DEFAULT_TUNNEL_URL = '$tunnelUrl';"
        Set-Content -Path $apiFile -Value $apiContent -NoNewline
        Write-Host "[3/3] Updated src/services/api.ts with active tunnel URL." -ForegroundColor Green
    }

    Write-Host ""
    Write-Host "==========================================================" -ForegroundColor Cyan
    Write-Host " CONCEPT ACTIVE:                                          " -ForegroundColor Green
    Write-Host " Phone / Vercel  --> Cloudflare Global Server             " -ForegroundColor White
    Write-Host "                  --> cloudflared on your PC              " -ForegroundColor White
    Write-Host "                  --> FastAPI Backend (:8000)             " -ForegroundColor White
    Write-Host "==========================================================" -ForegroundColor Cyan
    Write-Host "Leave this window open to keep the tunnel alive!" -ForegroundColor Yellow
} else {
    Write-Host "Failed to extract tunnel URL within 30 seconds. Check $logFile" -ForegroundColor Red
}

$proc.WaitForExit()
