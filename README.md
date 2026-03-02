# HoneytokenWatcher

HoneytokenWatcher is a Windows-focused .NET 8 console tool that plants realistic decoy files (honeytokens), watches them for suspicious access/modification, and emits scored alerts to JSON.

## What It Does

- Plants hidden/system decoy files in high-value user folders:
  - Desktop
  - Documents
  - Downloads
  - Pictures
- Generates realistic file types (`.docx`, `.pdf`, `.jpg`, `.xlsx`, `.txt`) with valid structures.
- Uses `FileSystemWatcher` to detect token access events (`Created`, `Changed`, `Renamed`, `Deleted`).
- Attempts process attribution using Restart Manager API + shell-process fallback heuristics.
- Computes Shannon entropy on write events to flag likely encryption behavior.
- Scores alerts (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`) and writes them to `rdrs_alerts.json`.

## Requirements

- Windows 10/11
- .NET SDK 8.0+
- Administrator privileges recommended for best watcher and ACL behavior

## Quick Start

```bash
dotnet restore
dotnet build
dotnet run
```

Stop with `Ctrl+C` to trigger cleanup (watchers stop and planted tokens are removed).

## Alert Output

Alerts are appended to:

- `rdrs_alerts.json`

Each alert includes:

- Timestamp and event type
- Triggered token path/file
- Process attribution (name, pid, parent pid, path, signature hint)
- Entropy score for write events
- Risk score and risk label
- Indicator list (for example, high-entropy write)

## Example Test Trigger (PowerShell)

```powershell
Get-ChildItem -Force -Hidden $env:USERPROFILE\Documents |
  Where-Object {$_.Name -like '_AAAA_*'} |
  ForEach-Object { Get-Content $_.FullName }
```

## Project Files

- `Program.cs` - entry point
- `DeceptionEngine.cs` - orchestration
- `HoneytokenPlanter.cs` - decoy creation/cleanup
- `WatcherManager.cs` - filesystem monitoring
- `AlertBuilder.cs` - process attribution + scoring
- `AlertManager.cs` - alert storage + dispatch
- `Analysis/EntropyAnalyzer.cs` - entropy analysis
- `ConsoleUI.cs` - terminal UI

## Notes

- This project is intended for defensive security testing and ransomware detection research in authorized environments.
- File and process behavior can vary by endpoint hardening policy, AV/EDR controls, and user privilege level.
