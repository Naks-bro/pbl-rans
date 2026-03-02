$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Start-Process powershell -Verb RunAs -ArgumentList "-ExecutionPolicy Bypass -NoExit -File `"$PSCommandPath`""
    exit
}
$path  = [Environment]::GetFolderPath('MyDocuments') + '\_AAAA_bank_statement.xlsx'
$bytes = [byte[]](1..255 | ForEach-Object { Get-Random -Max 256 })
[System.IO.File]::WriteAllBytes($path, $bytes)
Write-Host "Entropy test fired -> $path ($($bytes.Length) random bytes written)"
Read-Host "Press Enter to close"
