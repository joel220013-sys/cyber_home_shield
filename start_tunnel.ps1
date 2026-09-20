# Cyber Home Shield - Public Secure Tunnel Launcher
# Exposes local FastAPI backend (http://127.0.0.1:8000) over free Cloudflare HTTPS Tunnel

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  Cyber Home Shield - Cloudflare Tunnel Launcher         " -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "Exposing local backend to the public Internet with free SSL..." -ForegroundColor Yellow

$cloudflaredPath = "C:\Program Files (x86)\cloudflared\cloudflared.exe"

if (-not (Test-Path $cloudflaredPath)) {
    Write-Host "cloudflared.exe not found at default path. Checking system PATH..." -ForegroundColor Yellow
    $cloudflaredPath = "cloudflared"
}

& $cloudflaredPath tunnel --url http://127.0.0.1:8000
