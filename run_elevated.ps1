$cmd = "cd 'D:\PBL RANS'; dotnet run"
$enc = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($cmd))
Start-Process powershell -Verb RunAs -ArgumentList "-EncodedCommand $enc"
