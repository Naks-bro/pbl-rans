# ============================================================
# RDRS TEST SCRIPT 4 -- Delete Honeytoken
# Expected: CRITICAL (~85)
# ============================================================
# Deletes a honeytoken file -- simulates ransomware wiping
# originals after encryption, or deleting backup files.
#
# Score breakdown:
#   Base          55
#   Deleted      +10
#   PowerShell   +10
#   TriggerCount  +3 (if token was hit before)
#   ----------------
#   Total        ~75-85  (CRITICAL)
#
# Note: RDRS will replant this token on next restart.
# ============================================================

$ErrorActionPreference = "Continue"

Write-Host "=== RDRS TEST 4: Delete Honeytoken ===" -ForegroundColor Cyan
Write-Host "Deletes a honeytoken file to trigger a Deleted alert."
Write-Host ""

$downloads = Join-Path $env:USERPROFILE "Downloads"
$target    = Join-Path $downloads "_AAAA_passwords_backup.txt"

Write-Host "[*] Looking for: $target"

if (-not (Test-Path -LiteralPath $target -ErrorAction SilentlyContinue)) {
    Write-Host "[!] Honeytoken not found." -ForegroundColor Yellow
    Write-Host "    Make sure RDRS is running and honeytokens are planted."
    exit 1
}

Write-Host "[*] Found. Removing Hidden+System attributes..."
try { (Get-Item -LiteralPath $target -Force).Attributes = "Normal" } catch {}

Write-Host "[*] Deleting: $target"
Remove-Item -LiteralPath $target -Force

Write-Host "[+] Delete complete. RDRS should fire a CRITICAL alert." -ForegroundColor Green
Write-Host "[i] Restart RDRS to replant this token." -ForegroundColor DarkGray
