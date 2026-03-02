# RDRS — Ransomware Detection & Response Service
### Honeytoken Watcher

A Windows defensive-security tool built in **.NET 8** that detects ransomware activity early by planting realistic decoy files (honeytokens) and watching them for suspicious access, modification, or encryption.

> **Educational / Research Use Only.** Run only on systems you own or have explicit written authorisation to test.

---

## What We Are Building

Ransomware typically targets common user folders (Desktop, Documents, Downloads, Pictures) and encrypts files in alphabetical order. **RDRS exploits this predictable behaviour** using a deception layer:

1. **Plant** — realistic decoy files with valid internal structures (`.docx`, `.pdf`, `.jpg`, `.xlsx`, `.txt`) are written to all four target directories. Every filename starts with `_AAAA_` so they sort alphabetically first and become the *first files ransomware touches*.
2. **Watch** — a `FileSystemWatcher` on each directory fires the moment any decoy is read, written, renamed, or deleted.
3. **Attribute** — a three-stage process-attribution pipeline identifies which program touched the file:
   - Stage 1: Windows **Restart Manager API** (catches long-running apps that still hold the file handle)
   - Stage 2: **FSW-time snapshot** — the shell/script process captured at the exact instant the event fires (catches one-shot PowerShell/cmd commands)
   - Stage 3: **Live process scan** fallback — ranks running processes by handle count
4. **Analyse** — Shannon entropy is computed on any written data. Encrypted content scores close to 8.0 bits/byte (random noise), whereas plain text scores 3–5. A threshold of **7.2** triggers the `HIGH_ENTROPY_WRITE` indicator.
5. **Score & Alert** — every event receives a risk score (0–100) mapped to `LOW / MEDIUM / HIGH / CRITICAL`, then appended to `rdrs_alerts.json` and displayed live in the terminal.
6. **Clean up** — pressing `Ctrl+C` stops all watchers and deletes every planted token automatically.

### Architecture

```
Program.cs
  └─ DeceptionEngine          ← orchestrates the full lifecycle
       ├─ HoneytokenPlanter   ← creates & removes decoy files
       ├─ WatcherManager      ← FileSystemWatcher per directory
       ├─ AlertBuilder        ← process attribution + entropy + scoring
       ├─ AlertManager        ← thread-safe log (rdrs_alerts.json) + event bus
       ├─ EntropyAnalyzer     ← Shannon entropy (Analysis/)
       └─ ConsoleUI           ← live terminal dashboard
```

### Risk Scoring Breakdown

| Factor | Points |
|---|---|
| Base score | 55 |
| Event: Renamed (extension change) | +20 (+15 bonus) |
| Event: Changed (write) | +15 |
| Event: Deleted | +10 |
| Event: Created | +5 |
| Repeat triggers | +3 per hit (max +15) |
| High-entropy write detected | **+25** |
| Suspicious process (powershell, cmd, etc.) | +10 |
| Unsigned process binary | +10 |
| Process running from Temp/AppData | +8 |

Scores map to: `< 40` LOW · `≥ 40` MEDIUM · `≥ 60` HIGH · `≥ 80` CRITICAL

---

## Requirements

| Requirement | Details |
|---|---|
| OS | Windows 10 / 11 (x64) |
| .NET SDK | 8.0 or later |
| Privileges | **Administrator recommended** — required for ACL and Restart Manager API |
| Shell | PowerShell 5.1+ (for test scripts) |

Install .NET 8 SDK: https://dotnet.microsoft.com/download

---

## Build & Run

### 1. Restore dependencies

```bash
dotnet restore
```

### 2. Build

```bash
dotnet build
```

### 3. Run (as Administrator)

Right-click your terminal → **Run as Administrator**, then:

```bash
dotnet run
```

Or run the compiled binary directly:

```bash
.\bin\Release\net8.0-windows\HoneytokenWatcher.exe
```

The tool will:
- Display a live status dashboard in the terminal
- Plant 8 decoy files across Desktop, Documents, Downloads, Pictures
- Begin watching immediately
- Log all alerts to `rdrs_alerts.json` in the working directory

**Stop with `Ctrl+C`** — this triggers clean shutdown: watchers stop and all planted tokens are deleted.

---

## How to Test

All test scripts are in the project root and require PowerShell.

### Check that honeytokens were planted

Run this *while the watcher is active* to confirm the decoy files exist:

```powershell
.\check_tokens.ps1
```

Expected output — one `_AAAA_*` file per directory with `Hidden, System` attributes.

---

### Test 1 — Simple file read (triggers LOW/MEDIUM alert)

Open a **second** PowerShell window (does **not** need to be elevated) and run:

```powershell
Get-ChildItem -Force -Hidden $env:USERPROFILE\Documents |
  Where-Object { $_.Name -like '_AAAA_*' } |
  ForEach-Object { Get-Content $_.FullName }
```

You should see an alert appear in the watcher terminal immediately.

---

### Test 2 — High-entropy write (simulates ransomware encryption)

Requires an **elevated** PowerShell window:

```powershell
.\test_entropy.ps1
```

This writes 255 random bytes to `_AAAA_bank_statement.xlsx` in Documents.
Expected alert: `CRITICAL` with `HIGH_ENTROPY_WRITE` indicator and entropy score ≈ 7.9–8.0.

---

### Test 3 — Non-elevated write (tests ACL fix)

Run from a **standard (non-admin)** PowerShell window:

```powershell
.\test_nonadmin.ps1
```

This confirms that honeytokens are writable by non-privileged processes (simulating real ransomware running in user context). It should trigger a `Changed` alert in the watcher.

---

### Test 4 — Rename/extension change (highest-scoring event)

In any PowerShell window:

```powershell
$src = "$env:USERPROFILE\Documents\_AAAA_resume_final.docx"
$dst = "$env:USERPROFILE\Documents\_AAAA_resume_final.docx.locked"
Rename-Item $src $dst
```

Expected alert: `CRITICAL` — rename with extension change scores +35 bonus points on top of the base.

---

### Test 5 — Delete (simulates wiper malware)

```powershell
Remove-Item -Force "$env:USERPROFILE\Desktop\_AAAA_resume_final.docx"
```

Expected alert: `HIGH` with `Deleted` event type.

---

## Alert Output

All alerts are appended to `rdrs_alerts.json` (created automatically in the run directory).

Example alert entry:

```json
{
  "AlertId": "A3F9C1B2",
  "Timestamp": "2025-01-15T14:32:07.123",
  "TokenFileName": "_AAAA_bank_statement.xlsx",
  "TokenDirectory": "C:\\Users\\User\\Documents",
  "EventType": "Changed",
  "ProcessName": "powershell",
  "ProcessId": 9812,
  "ParentProcessName": "explorer",
  "ParentProcessId": 4520,
  "ProcessPath": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
  "IsSigned": true,
  "EntropyScore": 7.9621,
  "RiskScore": 95,
  "RiskLabel": "CRITICAL",
  "Indicators": ["HIGH_ENTROPY_WRITE"]
}
```

To view alerts while the tool is running:

```powershell
Get-Content .\rdrs_alerts.json | ConvertFrom-Json | Format-List
```

---

## Project Files

| File | Purpose |
|---|---|
| `Program.cs` | Entry point — wires up cancellation and starts the engine |
| `DeceptionEngine.cs` | Lifecycle orchestration (plant → watch → alert → cleanup) |
| `HoneytokenFile.cs` | Data model for a deployed honeytoken |
| `HoneytokenPlanter.cs` | Creates/removes decoy files with valid file structures and correct ACLs |
| `WatcherManager.cs` | `FileSystemWatcher` per directory; three-stage process capture at event time |
| `AlertBuilder.cs` | Process attribution (Restart Manager + fallback) + entropy + risk scoring |
| `AlertManager.cs` | Thread-safe alert log writer (`rdrs_alerts.json`) and event publisher |
| `Analysis/EntropyAnalyzer.cs` | Shannon entropy calculator (0.0 – 8.0 bits/byte) |
| `ConsoleUI.cs` | Live terminal dashboard with colour-coded status board and alert cards |
| `check_tokens.ps1` | Verify planted tokens exist in all target directories |
| `test_entropy.ps1` | Simulate ransomware encryption (high-entropy write, requires admin) |
| `test_nonadmin.ps1` | Confirm non-elevated processes can trigger honeytokens |
| `cleanup_tokens.ps1` | Manually delete leftover tokens if the watcher was force-killed |

---

## Troubleshooting

**"Access denied" when planting tokens**
Run the terminal as Administrator.

**No alert fires when reading a file**
`LastAccess` timestamps are disabled by default on Windows 10/11. Read-only access does not trigger `Changed`. Use a write test (`test_entropy.ps1`) or a rename/delete test instead.

**Alert shows `ProcessName: unknown`**
The accessing process exited before the three attribution stages could capture it. One-shot commands like `Get-Content` in a script may exit within milliseconds. Use `test_nonadmin.ps1` which holds the process open slightly longer.

**Watcher exited without cleanup**
Run `cleanup_tokens.ps1` to delete leftover honeytoken files manually.
