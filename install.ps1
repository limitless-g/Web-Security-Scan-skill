# Web Security Full v5.5 — One-command installer for Claude Code (Windows)
# Usage: .\install.ps1

$ErrorActionPreference = "Stop"
$SkillDir = "$env:USERPROFILE\.claude\skills\web-security-full"

Write-Host "=== Web Security Full v5.5 Installer (Windows) ===" -ForegroundColor Cyan
Write-Host ""

if (Test-Path $SkillDir) {
    Write-Host "[!] Already installed at $SkillDir" -ForegroundColor Yellow
    Write-Host "    To reinstall: Remove-Item -Recurse -Force $SkillDir; .\install.ps1"
    exit 1
}

Write-Host "[1/3] Installing skill files..." -ForegroundColor Green
New-Item -ItemType Directory -Force -Path $SkillDir | Out-Null
Copy-Item -Recurse -Force "$PSScriptRoot\*" $SkillDir
Write-Host "       Done."

Write-Host "[2/3] Installing Python dependencies..." -ForegroundColor Green
pip install playwright pyyaml --quiet
Write-Host "       Done."

Write-Host "[3/3] Installing Chromium browser..." -ForegroundColor Green
playwright install chromium
Write-Host "       Done."

Write-Host ""
Write-Host "=== Installation Complete ===" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Skill: /web-security-full"
Write-Host "  Usage: /web-security-full https://target.com"
Write-Host "  Manual: python $SkillDir\scripts\web_auto_scanner.py --help"
Write-Host ""
Write-Host "  Optional: Download CVE database (200K+ CVEs, ~50MB)"
Write-Host "    python $SkillDir\scripts\nvd_downloader.py --init"
