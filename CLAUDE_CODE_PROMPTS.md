# RDRS HoneytokenWatcher — Claude Code Vibe Coding Guide
# Use these prompts IN ORDER after loading the project

## ── STEP 0: INITIAL SETUP ────────────────────────────────────────────────────

Open Claude Code in the HoneytokenWatcher/ directory, then say:

> "Read all .cs files in this project, understand the structure, 
>  then run `dotnet build` and fix any errors."


## ── STEP 1: RUN IT ───────────────────────────────────────────────────────────

> "Run the project with `dotnet run` — it needs to be run as Administrator 
>  on Windows for FileSystemWatcher to catch System-attributed files. 
>  If there are permission errors on any directory, skip that directory 
>  silently and continue with the others."


## ── STEP 2: TEST IT (in a second terminal) ──────────────────────────────────

To prove it actually works, open a second terminal and run:

# Option A — PowerShell (simulates a ransomware-like process touching decoys)
> powershell -Command "Get-ChildItem -Force -Hidden $env:USERPROFILE\Documents | Where-Object {$_.Name -like '_AAAA_*'} | ForEach-Object { Get-Content $_.FullName }"

# Option B — Direct file touch
> powershell -Command "& { $f = \"$env:USERPROFILE\Desktop\_AAAA_resume_final.docx\"; [System.IO.File]::OpenRead($f).Close() }"

Watch the HoneytokenWatcher terminal fire an alert with PowerShell's PID!


## ── STEP 3: IMPROVE PROCESS ATTRIBUTION ─────────────────────────────────────

> "The current process attribution is a heuristic (most recent non-system process).
>  Improve it: use the Windows Restart Manager API (RstrtMgr.dll) via P/Invoke
>  to find which processes actually have a file handle open on the triggered 
>  honeytoken path. This gives us exact attribution instead of a guess.
>  Add the P/Invoke signatures for RmStartSession, RmRegisterResources, 
>  RmGetList, RmEndSession in a new file Watchers/HandleFinder.cs"


## ── STEP 4: ADD ENTROPY DETECTION ───────────────────────────────────────────

> "When a honeytoken is CHANGED (written to), read the new content and calculate 
>  Shannon entropy. If entropy > 7.2 bits/byte, it's likely been encrypted.
>  Add this as a new signal 'ContentEntropy' to HoneytokenAlert and factor 
>  it into the risk score (+25 if entropy > 7.2, +15 if 6.5-7.2).
>  Add this in a new file Analysis/EntropyAnalyzer.cs"


## ── STEP 5: ADD SIEM-READY JSON OUTPUT ──────────────────────────────────────

> "Extend AlertManager to also write alerts in a SIEM-compatible format.
>  Create a second log file 'rdrs_siem.ndjson' (newline-delimited JSON, 
>  one alert per line) with these exact field names matching Elastic Common 
>  Schema: @timestamp, event.action, event.category, process.name, 
>  process.pid, process.parent.pid, file.path, file.name, 
>  threat.indicator.type, risk_score.
>  This makes it directly ingestible by Splunk/Elastic."


## ── STEP 6: EXTENSION WATCHLIST ─────────────────────────────────────────────

> "Add a ransomware extension watchlist. After a Renamed event on ANY file 
>  in the monitored directories (not just honeytokens), check if the new 
>  extension matches known ransomware extensions like .locked, .encrypted, 
>  .enc, .ryk, .ransom, .WNCRY, .zepto, .cerber, .locky, .crypto.
>  If yes, raise a separate RansomwareExtensionAlert even if no honeytoken 
>  was involved. Add this to WatcherManager."


## ── STEP 7: SHADOW COPY DELETION WATCH ──────────────────────────────────────

> "Add a ProcessStartMonitor class that watches for vssadmin, wmic, 
>  and bcdedit process launches using WMI event subscription 
>  (SELECT * FROM Win32_ProcessStartTrace).
>  If any process runs: 'vssadmin delete shadows', 'wmic shadowcopy delete', 
>  or 'bcdedit /set {default} recoveryenabled No' — raise an immediate 
>  CRITICAL alert. This catches a near-universal ransomware pre-encryption step."


## ── STEP 8: CONNECT TO YOUR EXISTING RDRS PIPELINE ──────────────────────────

> "Add a --output-pipe flag. When set, instead of (or in addition to) writing 
>  to rdrs_alerts.json, stream alerts as JSON to stdout in a format that 
>  the RDRS main process can read from stdin. This lets HoneytokenWatcher 
>  run as a subprocess of the main RDRS service and feed directly into 
>  the multi-signal risk scorer."


## ── ARCHITECTURE NOTES ───────────────────────────────────────────────────────

Project structure when done:

HoneytokenWatcher/
├── Program.cs
├── Core/
│   └── DeceptionEngine.cs          ← orchestrator
├── Honeytokens/
│   ├── HoneytokenFile.cs            ← model
│   └── HoneytokenPlanter.cs         ← plants real-structured decoy files
├── Watchers/
│   ├── WatcherManager.cs            ← FileSystemWatcher per directory
│   └── HandleFinder.cs              ← (Step 3) exact process attribution
├── Analysis/
│   └── EntropyAnalyzer.cs           ← (Step 4) content entropy on write
├── Alerting/
│   ├── HoneytokenAlert.cs + AlertManager.cs
│   └── AlertBuilder.cs              ← risk scoring + process attribution
└── UI/
    └── ConsoleUI.cs                 ← live colored terminal board


## ── WHAT MAKES THIS "TOO REAL FOR RANSOMWARE" ───────────────────────────────

Your honeytokens are not fake empty files. They are:

  _AAAA_resume_final.docx   → Real ZIP/OOXML structure, real word/document.xml
  _AAAA_tax_return_2024.pdf → Real PDF with xref table, valid object tree
  _AAAA_family_vacation.jpg → Valid JFIF/JPEG header + quantization table
  _AAAA_bank_statement.xlsx → Real ZIP/OOXML with xl/workbook.xml + sheet data
  _AAAA_passwords_backup.txt→ Looks like a real credential store
  _AAAA_crypto_wallet.txt   → Looks like a seed phrase

Ransomware that checks file magic bytes, runs format detection, or scores 
files by "value" will target all of these — and the moment it does, 
HoneytokenWatcher fires.

Named _AAAA_ so they sort alphabetically FIRST in any directory listing.
Ransomware typically encrypts in directory order → hits your traps immediately.
