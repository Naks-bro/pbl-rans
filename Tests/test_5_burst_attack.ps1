# ============================================================
# RDRS TEST SCRIPT 5 -- Burst Attack (All Tokens)
# Expected: CRITICAL x8 + BURST ALERT
# ============================================================
# Rapidly writes to ALL 8 honeytokens across all 4 directories
# within a 2-second window. This triggers:
#   1. Multiple individual CRITICAL alerts (one per token)
#   2. BurstDetector threshold (>= 3 events in <= 2s)
#
# Per-alert score:
#   Base:              55
#   Changed:          +15
#   PowerShell:       +10
#   TriggerCount:     +3 per repeat hit
#   ---------------------------
#   Total: 80+ CRITICAL x8 alerts + 1 BURST ALERT
# ============================================================

$ErrorActionPreference = "Continue"

Write-Host "=== RDRS TEST 5: Burst Attack (All Tokens) ===" -ForegroundColor Red
Write-Host "Rapidly touches all 8 honeytokens to trigger burst detection."
Write-Host ""

$desktop   = [Environment]::GetFolderPath("Desktop")
$docs      = [Environment]::GetFolderPath("MyDocuments")
$downloads = Join-Path $env:USERPROFILE "Downloads"
$pictures  = Join-Path $env:USERPROFILE "Pictures"

$tokens = @(
    (Join-Path $desktop   "_AAAA_resume_final.docx"),
    (Join-Path $desktop   "_AAAA_tax_return_2024.pdf"),
    (Join-Path $docs      "_AAAA_family_vacation.jpg"),
    (Join-Path $docs      "_AAAA_bank_statement.xlsx"),
    (Join-Path $downloads "_AAAA_passwords_backup.txt"),
    (Join-Path $downloads "_AAAA_project_contracts.docx"),
    (Join-Path $pictures  "_AAAA_crypto_wallet.txt"),
    (Join-Path $pictures  "_AAAA_medical_records.pdf")
)

$found = ($tokens | Where-Object { Test-Path -LiteralPath $_ }).Count

if ($found -eq 0) {
    Write-Host "[!] No honeytokens found. Make sure RDRS is running." -ForegroundColor Yellow
    exit 1
}

Write-Host "[*] Found $found / $($tokens.Count) honeytokens."
Write-Host "[*] Starting burst -- touching all tokens as fast as possible..."
Write-Host ""

$sw = [System.Diagnostics.Stopwatch]::StartNew()

foreach ($t in $tokens) {
    if (-not (Test-Path -LiteralPath $t -ErrorAction SilentlyContinue)) {
        Write-Host "  [skip] Not found: $([System.IO.Path]::GetFileName($t))" -ForegroundColor DarkGray
        continue
    }
    try { (Get-Item -LiteralPath $t -Force).Attributes = "Normal" } catch {}
    [System.IO.File]::AppendAllText($t, " ")
    Write-Host "  [hit ] $([System.IO.Path]::GetFileName($t))" -ForegroundColor Yellow
}

$sw.Stop()
Write-Host ""
Write-Host "[+] Burst complete in $($sw.ElapsedMilliseconds) ms." -ForegroundColor Green
Write-Host "[+] Expected: $found CRITICAL alerts + 1 BURST ALERT in dashboard." -ForegroundColor Red
