# ============================================================
# RDRS TEST SCRIPT 3 -- High Entropy Write (Fake Encryption)
# Expected: CRITICAL (100)
# ============================================================
# Overwrites a honeytoken with random bytes, exactly as
# ransomware does when encrypting a file in-place.
# Triggers the HIGH_ENTROPY_WRITE indicator (+25 pts).
#
# Score breakdown:
#   Base                    55
#   Changed                +15
#   HIGH_ENTROPY_WRITE     +25
#   PowerShell             +10
#   -------------------------
#   Total:             105 -> clamped to 100  (CRITICAL)
# ============================================================

$ErrorActionPreference = "Continue"

Write-Host "=== RDRS TEST 3: High Entropy Write (Fake Encryption) ===" -ForegroundColor Red
Write-Host "Overwrites honeytoken with 4096 random bytes (simulates AES ciphertext)."
Write-Host ""

$docs   = [Environment]::GetFolderPath("MyDocuments")
$target = Join-Path $docs "_AAAA_family_vacation.jpg"

Write-Host "[*] Looking for: $target"

if (-not (Test-Path -LiteralPath $target -ErrorAction SilentlyContinue)) {
    Write-Host "[!] Honeytoken not found." -ForegroundColor Yellow
    Write-Host "    Make sure RDRS is running and honeytokens are planted."
    exit 1
}

Write-Host "[*] Found. Removing Hidden+System attributes..."
try { (Get-Item -LiteralPath $target -Force).Attributes = "Normal" } catch {}

Write-Host "[*] Writing 4096 cryptographically random bytes (Shannon entropy ~8.0 bits/byte, threshold is 7.2)..."

$rng       = [System.Security.Cryptography.RandomNumberGenerator]::Create()
$randomBuf = New-Object byte[] 4096
$rng.GetBytes($randomBuf)
[System.IO.File]::WriteAllBytes($target, $randomBuf)

Write-Host "[+] High-entropy write complete." -ForegroundColor Green
Write-Host "[+] RDRS should fire CRITICAL with HIGH_ENTROPY_WRITE indicator." -ForegroundColor Red
Write-Host "[+] Tray icon should show a balloon notification." -ForegroundColor Green
