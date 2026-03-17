# ============================================================
# RDRS TEST SCRIPT 1 -- Write Normal Data
# Expected: CRITICAL (~80)
# ============================================================
# Writes low-entropy text to one honeytoken (Desktop).
# Triggers a "Changed" FSW event.
#
# Score breakdown:
#   Base             55
#   Changed         +15
#   PowerShell      +10
#   -------------------
#   Total           ~80  (CRITICAL)
# ============================================================

$ErrorActionPreference = "Continue"

Write-Host "=== RDRS TEST 1: Normal Write ===" -ForegroundColor Cyan
Write-Host "Writes plain text to a honeytoken. Triggers Changed event."
Write-Host ""

$desktop = [Environment]::GetFolderPath("Desktop")
$target  = Join-Path $desktop "_AAAA_resume_final.docx"

Write-Host "[*] Looking for: $target"

if (-not (Test-Path -LiteralPath $target -ErrorAction SilentlyContinue)) {
    Write-Host "[!] Honeytoken not found." -ForegroundColor Yellow
    Write-Host "    Make sure RDRS is running and honeytokens are planted."
    exit 1
}

Write-Host "[*] Found. Removing Hidden+System attributes..."
try { (Get-Item -LiteralPath $target -Force).Attributes = "Normal" } catch {}

Write-Host "[*] Writing normal low-entropy text..."
[System.IO.File]::WriteAllText($target, "This is a test write for RDRS detection - plain text, low entropy.")

Write-Host "[+] Done. Check tray icon or dashboard for a HIGH/CRITICAL alert." -ForegroundColor Green
