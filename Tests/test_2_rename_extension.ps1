# ============================================================
# RDRS TEST SCRIPT 2 -- Rename with Extension Change
# Expected: CRITICAL (~100)
# ============================================================
# Renames a honeytoken to simulate ransomware appending .locked
# after in-place encryption.
#
# Score breakdown:
#   Base               55
#   Renamed           +20
#   Extension change  +15
#   PowerShell        +10
#   -------------------
#   Total             ~100  (CRITICAL)
# ============================================================

$ErrorActionPreference = "Continue"

Write-Host "=== RDRS TEST 2: Rename with Extension Change ===" -ForegroundColor Cyan
Write-Host "Renames honeytoken to .locked -- simulates post-encryption rename."
Write-Host ""

$desktop  = [Environment]::GetFolderPath("Desktop")
$original = Join-Path $desktop "_AAAA_tax_return_2024.pdf"
$renamed  = "$original.locked"

Write-Host "[*] Looking for: $original"

if (-not (Test-Path -LiteralPath $original -ErrorAction SilentlyContinue)) {
    Write-Host "[!] Honeytoken not found." -ForegroundColor Yellow
    Write-Host "    Make sure RDRS is running and honeytokens are planted."
    exit 1
}

Write-Host "[*] Found. Removing Hidden+System attributes..."
try { (Get-Item -LiteralPath $original -Force).Attributes = "Normal" } catch {}

Write-Host "[*] Renaming to: $renamed"
Rename-Item -LiteralPath $original -NewName "$original.locked" -Force

Write-Host "[+] Rename complete. RDRS should fire a CRITICAL alert." -ForegroundColor Green
Write-Host ""

Start-Sleep -Milliseconds 800

# Restore the file for future tests
if (Test-Path -LiteralPath $renamed) {
    Rename-Item -LiteralPath $renamed -NewName (Split-Path $original -Leaf) -Force
    Write-Host "[*] Restored original filename for future tests." -ForegroundColor DarkGray
}
