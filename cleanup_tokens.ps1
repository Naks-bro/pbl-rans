$dirs = @(
    [Environment]::GetFolderPath('Desktop'),
    [Environment]::GetFolderPath('MyDocuments'),
    [Environment]::GetFolderPath('UserProfile') + '\Downloads',
    [Environment]::GetFolderPath('UserProfile') + '\Pictures'
)
foreach ($dir in $dirs) {
    $files = Get-ChildItem -Path $dir -Filter '_AAAA_*' -Force -ErrorAction SilentlyContinue
    foreach ($f in $files) {
        Set-ItemProperty -Path $f.FullName -Name Attributes -Value 'Normal' -ErrorAction SilentlyContinue
        Remove-Item $f.FullName -Force -ErrorAction SilentlyContinue
        Write-Host "Deleted: $($f.FullName)"
    }
}
Write-Host "Done"
