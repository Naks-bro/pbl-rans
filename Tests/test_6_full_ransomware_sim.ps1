# ============================================================
# RDRS TEST SCRIPT 6 -- Full Ransomware Simulation (Max Score)
# Expected: CRITICAL x6+ + Burst Alert + Containment
# ============================================================
# Simulates a complete ransomware attack chain:
#   Stage 1: Read multiple files (recon)
#   Stage 2: Overwrite with high-entropy data (fake encryption)
#   Stage 3: Rename with .rdrs_enc extension
#   Stage 4: Restore files (test cleanup -- NOT part of attack)
#
# WARNING: This triggers full containment if RDRS is in
# KillAndSuspend mode. Your PowerShell window may be killed.
# Run this from a second PowerShell window.
# ============================================================

$ErrorActionPreference = "Continue"

Write-Host "=== RDRS TEST 6: Full Ransomware Simulation ===" -ForegroundColor Red
Write-Host "WARNING: Full containment may kill this PowerShell window!" -ForegroundColor Yellow
Write-Host ""
Write-Host "Press ENTER to continue, or Ctrl+C to abort..."
Read-Host | Out-Null

$desktop = [Environment]::GetFolderPath("Desktop")
$docs    = [Environment]::GetFolderPath("MyDocuments")

$targets = @(
    (Join-Path $desktop "_AAAA_resume_final.docx"),
    (Join-Path $docs    "_AAAA_bank_statement.xlsx"),
    (Join-Path $desktop "_AAAA_tax_return_2024.pdf")
)

$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()

# --- Stage 1: Recon ---
Write-Host ""
Write-Host "--- STAGE 1: Recon (reading files) ---" -ForegroundColor Cyan
foreach ($t in $targets) {
    if (Test-Path -LiteralPath $t -ErrorAction SilentlyContinue) {
        try { (Get-Item -LiteralPath $t -Force).Attributes = "Normal" } catch {}
        $bytes = [System.IO.File]::ReadAllBytes($t)
        Write-Host "  [read] $([System.IO.Path]::GetFileName($t)) ($($bytes.Length) bytes)"
    } else {
        Write-Host "  [skip] Not found: $([System.IO.Path]::GetFileName($t))" -ForegroundColor DarkGray
    }
}

Start-Sleep -Milliseconds 200

# --- Stage 2: Fake Encryption ---
Write-Host ""
Write-Host "--- STAGE 2: In-place Encryption (random bytes write) ---" -ForegroundColor Red
foreach ($t in $targets) {
    if (Test-Path -LiteralPath $t -ErrorAction SilentlyContinue) {
        $buf = New-Object byte[] 8192
        $rng.GetBytes($buf)
        [System.IO.File]::WriteAllBytes($t, $buf)
        Write-Host "  [enc ] $([System.IO.Path]::GetFileName($t)) -- 8KB random bytes"
    }
}

Start-Sleep -Milliseconds 200

# --- Stage 3: Rename with ransom extension ---
Write-Host ""
Write-Host "--- STAGE 3: Rename with .rdrs_enc extension ---" -ForegroundColor Red
$renamed = @()
foreach ($t in $targets) {
    if (Test-Path -LiteralPath $t -ErrorAction SilentlyContinue) {
        $newPath = "$t.rdrs_enc"
        Rename-Item -LiteralPath $t -NewName "$t.rdrs_enc" -Force
        $renamed += $newPath
        Write-Host "  [ren ] $([System.IO.Path]::GetFileName($t)) -> .rdrs_enc"
    }
}

Start-Sleep -Milliseconds 800

# --- Stage 4: Restore (cleanup, not part of real attack) ---
Write-Host ""
Write-Host "--- STAGE 4: Restoring files (test cleanup) ---" -ForegroundColor DarkGray
foreach ($r in $renamed) {
    if (Test-Path -LiteralPath $r -ErrorAction SilentlyContinue) {
        $orig = $r -replace '\.rdrs_enc$', ''
        Rename-Item -LiteralPath $r -NewName (Split-Path $orig -Leaf) -Force
        Write-Host "  [rst ] Restored $([System.IO.Path]::GetFileName($orig))"
    }
}

Write-Host ""
Write-Host "[+] Simulation complete." -ForegroundColor Green
Write-Host "[+] Check dashboard: expect 6+ CRITICAL alerts, burst, and containment." -ForegroundColor Red
