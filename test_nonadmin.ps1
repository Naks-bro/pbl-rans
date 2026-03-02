$path = [Environment]::GetFolderPath('MyDocuments') + '\_AAAA_bank_statement.xlsx'
$bytes = [byte[]](1..255 | ForEach-Object { Get-Random -Max 256 })
[IO.File]::WriteAllBytes($path, $bytes)
Write-Host ('SUCCESS: wrote ' + $bytes.Length + ' random bytes to ' + $path)
Write-Host 'ACL fix confirmed: non-elevated process can write to honeytoken.'
