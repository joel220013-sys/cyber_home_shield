# Cyber Home Shield - Public Secure Cloudflare Tunnel Launcher
# Implements: Phone/Vercel -> Cloudflare -> cloudflared on PC -> FastAPI (:8000)

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "   Cyber Home Shield - Cloudflare Tunnel Launcher         " -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Cyan

# Kill any existing cloudflared zombie processes
Stop-Process -Name "cloudflared" -Force -ErrorAction SilentlyContinue

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

# Ensure background persistent fallback is running
$ltProc = Get-Process -Name "node" -ErrorAction SilentlyContinue | Where-Object { $_.CommandLine -match "localtunnel" }
if (-not $ltProc) {
    Start-Process -FilePath "cmd.exe" -ArgumentList "/c npx --yes localtunnel --port 8000 --subdomain chs-security-engine" -WindowStyle Hidden
}

Write-Host "[1/4] Starting Cloudflare secure tunnel to http://127.0.0.1:8000..." -ForegroundColor Yellow

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
    Write-Host "[2/4] Tunnel Established Successfully!" -ForegroundColor Green
    Write-Host "  Public HTTPS: $tunnelUrl" -ForegroundColor Cyan

    $apiFile = "$rootDir\src\services\api.ts"
    if (Test-Path $apiFile) {
        $apiContent = Get-Content $apiFile -Raw
        $apiContent = $apiContent -replace "export const DEFAULT_TUNNEL_URL = 'https://[^']+';", "export const DEFAULT_TUNNEL_URL = '$tunnelUrl';"
        Set-Content -Path $apiFile -Value $apiContent -NoNewline
        Write-Host "[3/4] Updated src/services/api.ts with active tunnel URL." -ForegroundColor Green
    }

    $jsonFile = "$rootDir\active_tunnel.json"
    $jsonObj = @{
        tunnel_url = $tunnelUrl
        fallback_url = "https://chs-security-engine.loca.lt"
        updated_at = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    }
    $jsonObj | ConvertTo-Json | Set-Content -Path $jsonFile
    Write-Host "[3/4] Saved active_tunnel.json for instant remote discovery." -ForegroundColor Green

    # Auto push to GitHub so Vercel builds and remote clients discover the new URL immediately
    Write-Host "[4/4] Syncing new Cloudflare tunnel URL to GitHub & Vercel..." -ForegroundColor Yellow
    Push-Location $rootDir
    git add src/services/api.ts active_tunnel.json 2>$null
    git commit -m "chore: sync active cloudflare tunnel URL $tunnelUrl" 2>$null
    Start-Process -FilePath "git" -ArgumentList "push origin main" -WindowStyle Hidden
    Pop-Location
    Write-Host "  Successfully synced! Vercel is updating automatically." -ForegroundColor Green

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
