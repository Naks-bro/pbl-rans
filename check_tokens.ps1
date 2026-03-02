$dirs = @(
    [Environment]::GetFolderPath('Desktop'),
    [Environment]::GetFolderPath('MyDocuments'),
    [Environment]::GetFolderPath('UserProfile') + '\Downloads',
    [Environment]::GetFolderPath('UserProfile') + '\Pictures'
)
foreach ($d in $dirs) {
    Write-Host "--- $d ---"
    Get-ChildItem $d -Filter '_AAAA_*' -Force -ErrorAction SilentlyContinue | Select-Object Name, Attributes
}
