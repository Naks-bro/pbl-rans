# RDRS — Ransomware Detection & Response Service

> A multi-layer, real-time ransomware detection and automatic containment system for Windows,
> built as a **Project-Based Learning (PBL)** exercise in applied cybersecurity.

---

## Table of Contents

1. [Overview](#overview)
2. [How It Works — The Big Picture](#how-it-works--the-big-picture)
3. [Architecture](#architecture)
4. [Detection Layers](#detection-layers)
   - [Layer 1 — Honeytoken Deception](#layer-1--honeytoken-deception)
   - [Layer 2 — ETW Kernel File Monitor](#layer-2--etw-kernel-file-monitor)
   - [Layer 3 — Crypto API Monitor](#layer-3--crypto-api-monitor)
   - [Layer 4 — Process Behaviour Scorer](#layer-4--process-behaviour-scorer)
   - [Layer 5 — Network Monitor](#layer-5--network-monitor)
   - [Layer 6 — VSS / Shadow Copy Watcher](#layer-6--vss--shadow-copy-watcher)
   - [Layer 7 — Burst Detector](#layer-7--burst-detector)
5. [Signal Fusion Engine](#signal-fusion-engine)
6. [Automatic Containment](#automatic-containment)
7. [Alert Format](#alert-format)
8. [Project Structure](#project-structure)
9. [Requirements](#requirements)
10. [Installation & Build](#installation--build)
11. [Running the Tool](#running-the-tool)
12. [Testing Detection](#testing-detection)
13. [Output Files](#output-files)
14. [Design Decisions & Limitations](#design-decisions--limitations)

---

## Overview

RDRS is a Windows endpoint security tool that detects ransomware **before** it finishes encrypting
your files and **automatically kills the attacking process**.

It combines seven independent detection techniques — deception files, kernel event tracing,
crypto-API monitoring, process behaviour analysis, network monitoring, shadow-copy watch, and
burst detection — into a single weighted **Signal Fusion Engine** that produces a composite
threat score per process in real time.

When the fused score of any process reaches **≥ 70 / 100** the containment engine:

1. **Suspends** all threads instantly (`NtSuspendProcess`)
2. **Kills** the process and its entire child tree (`Process.Kill(entireProcessTree: true)`)
3. **Blocks** re-execution if the binary lives in `Temp` / `AppData` (`icacls /deny Everyone:(X)`)
4. **Queues** a Windows Defender on-demand scan of the binary path

All events are logged to `rdrs_alerts.json` and `rdrs_containment.json`.

---

## How It Works — The Big Picture

```
Ransomware starts  →  touches honeytoken files    →  FileSystemWatcher fires
                   →  loads bcrypt.dll repeatedly  →  ETW ImageLoad fires
                   →  encrypts 50+ files / 5 sec   →  ETW FileIO rate fires
                   →  renames *.docx → *.locked    →  extension rename fires
                   →  deletes shadow copies         →  WMI VssWatcher fires
                   →  WMI I/O write rate spikes     →  ProcessBehaviorScorer fires
                   →  makes outbound connection     →  NetworkMonitor fires
                                   |
                                   v
                         SignalFusion accumulates
                         weighted scores per PID
                                   |
                                   v
                      Fused score >= 70  ->  CONTAINMENT
                      Suspend -> Kill -> Block -> Defender
```

The key insight is **no single signal is reliable alone** — a user can open a DOCX, bcrypt.dll
loads all the time, and file writes are normal. Only the *combination* of signals from the same
process within a short time window reaches a conclusive score.

---

## Architecture

```
+---------------------------------------------------------------------------+
|                          DeceptionEngine.Run()                            |
|                                                                           |
|  +------------------+   +-----------------+   +----------------------+   |
|  | HoneytokenPlanter|   |  WatcherManager  |   |     AlertManager     |   |
|  | Plants 8 decoy   |-->|  FileSystemWatch |-->|  JSON log + OnAlert  |   |
|  | files on Desktop,|   |  per directory   |   |  event               |   |
|  | Documents, etc.  |   +-----------------+   +----------------------+   |
|  +------------------+                                    |               |
|                                                           v               |
|  +------------------------------------------------------------------------+
|  |                       SignalFusion Engine                              |
|  |                                                                        |
|  |  Source         Weight   Feeds from                                   |
|  |  -------------  ------   ------------------------------------         |
|  |  Honeytoken     0.35  <- AlertBuilder (FSW rename/write/delete)       |
|  |  CryptoApi      0.25  <- CryptoApiMonitor (DLL load correlation)      |
|  |  EtwFileRate    0.20  <- EtwMonitor (kernel FileIO + extension rename) |
|  |  Network        0.12  <- NetworkMonitor (TCP + Tor + exfil)           |
|  |  Signature      0.08  <- ProcessBehaviorScorer (I/O + parent-child)   |
|  |                                                                        |
|  |  Per-process rolling score -> fires OnFusedThreat when >= 70/100      |
|  +------------------------------------------------------------------------+
|                                    |                                      |
|                                    v                                      |
|                    +-------------------------------+                      |
|                    |      ContainmentEngine        |                      |
|                    | Suspend -> Kill -> Block path |                      |
|                    | + Defender scan               |                      |
|                    +-------------------------------+                      |
+---------------------------------------------------------------------------+

  Side monitors (independent background threads):
  +--------------+  +------------------+  +--------------+
  |  VssWatcher  |  |  BurstDetector   |  |  EtwMonitor  |
  |  WMI process |  |  >10 FSW events  |  |  NT Kernel   |
  |  creation    |  |  in 3 seconds    |  |  Logger      |
  |  vssadmin /  |  |  + entropy check |  |  (admin req) |
  |  wbadmin etc |  +------------------+  +--------------+
  +--------------+
```

---

## Detection Layers

### Layer 1 — Honeytoken Deception

**Files:** `HoneytokenPlanter.cs`, `WatcherManager.cs`, `AlertBuilder.cs`

Honeytoken files are **fake high-value documents** planted in directories ransomware always
targets first:

| Directory | File 1 | File 2 |
|-----------|--------|--------|
| Desktop | `_AAAA_resume_final.docx` | `_AAAA_tax_return_2024.pdf` |
| Documents | `_AAAA_family_vacation.jpg` | `_AAAA_bank_statement.xlsx` |
| Downloads | `_AAAA_passwords_backup.txt` | `_AAAA_project_contracts.docx` |
| Pictures | `_AAAA_crypto_wallet.txt` | `_AAAA_medical_records.pdf` |

**Why `_AAAA_` prefix?**
Files sort alphabetically. Ransomware encrypts in directory order, so it hits our decoys
*first* — triggering detection before any real file is touched.

**File realism:**
Each honeytoken is structurally valid — DOCX/XLSX are real ZIP+XML Office packages, PDFs
have a working xref table, JPEGs have a correct JFIF/APP0 header. Ransomware that
inspects magic bytes or file structure still treats them as genuine encryption targets.

**ACL setup:**
Files are set `Hidden + System` (invisible in Explorer) with `BUILTIN\Users:Modify` DACL
and `icacls /setintegritylevel Medium` so non-elevated ransomware running in user context
can write to them — making them maximally attractive as encryption targets.

**When triggered:**
Any `Changed`, `Renamed`, `Deleted`, or `Created` event on a honeytoken fires
`AlertBuilder.Build()` which performs:
- 3-stage process attribution (Restart Manager → FSW-time shell hint → handle-count scan)
- Shannon entropy measurement on the written bytes (>7.2 bits/byte = encrypted content)
- Risk scoring (55 base + event-type bonus + entropy bonus + process modifiers)
- A `ThreatSignal(Honeytoken, rawScore)` submitted to SignalFusion

---

### Layer 2 — ETW Kernel File Monitor

**File:** `Monitoring/EtwMonitor.cs`
**Requires:** Administrator

Opens a private ETW session (`RDRS-FileMonitor`) using `Microsoft.Diagnostics.Tracing.TraceEvent`
and subscribes to:

```
KernelTraceEventParser.Keywords.FileIOInit | FileIO | ImageLoad
```

**Detection rules:**

| Rule | Threshold | Raw Score | Indicator |
|------|-----------|-----------|-----------|
| File I/O rate | >50 files/5 s from one process | 0.50 – 1.0 | `FILE_RATE_HIGH` |
| Ransom extension | New file with `.locked` / `.enc` / `.wncry` / 30+ others | 0.90 | `RANSOM_EXT_RENAME` |
| Crypto DLL load | `bcrypt.dll` / `rsaenh.dll` / `ncrypt.dll` loaded ≥2× in 10 s | 0.60 | `CRYPTO_DLL_LOAD` |

Falls back silently if not running as admin.

---

### Layer 3 — Crypto API Monitor

**File:** `Monitoring/CryptoApiMonitor.cs`

**Layer A — Signal correlation (always active):**
Subscribes to `EtwMonitor.OnSignal`. Maintains a 30-second per-process sliding window.
Fires a higher-confidence signal when correlated patterns appear from the *same PID*:

| Pattern | Raw Score | Indicator |
|---------|-----------|-----------|
| `RANSOM_EXT_RENAME` seen | 0.92 | `RANSOM_EXT_CORRELATED` |
| `CRYPTO_DLL_LOAD` ×2 + `FILE_RATE_HIGH` | 0.82 | `CRYPTO_LOAD_AND_FILE_BURST` |
| `CRYPTO_DLL_LOAD` ×4 in 30 s alone | 0.65 | `HIGH_FREQ_CRYPTO_DLL` |

**Layer B — BCrypt ETW provider (admin, best-effort):**
Subscribes to the `Microsoft-Windows-Crypto-BCrypt` provider
(GUID `A74EFE00-14BE-4EF9-9DA2-1E9A0E2B92F2`). If BCrypt events arrive from a
non-system process at >20 events / 5 seconds, a `BCRYPT_API_BURST` signal (0.75) fires.
Falls back silently if unavailable.

---

### Layer 4 — Process Behaviour Scorer

**File:** `Monitoring/ProcessBehaviorScorer.cs`

Polls `Win32_Process` via WMI every **2 seconds** using a single batch query. Tracks three
independent behavioural signals:

**I/O write rate** (`WriteTransferCount` delta since last poll):

| Rate | Raw Score | Source Weight |
|------|-----------|---------------|
| > 5 MB/s | 0.60 | EtwFileRate (0.20) |
| > 20 MB/s | 0.85 | EtwFileRate (0.20) |

**Handle storm** (handles acquired per poll interval):

| Delta | Raw Score |
|-------|-----------|
| +500 handles/2 s | 0.65 |

**Parent → child anomaly** (Living-off-the-Land pivot detection):

| Parent | Suspicious children | Raw Score |
|--------|--------------------|----|
| `winword`, `excel`, `outlook`, `powerpnt` | `cmd`, `powershell`, `pwsh`, `wscript`, `cscript`, `mshta`, `certutil` | 0.70 |
| `explorer` | `certutil`, `regsvr32`, `mshta`, `wscript`, `cscript` | 0.70 |
| `svchost` | `powershell`, `cmd`, `wscript`, `certutil`, `mshta` | 0.70 |

**Suspicious launch location** (checked once per PID on first spawn):

| Condition | Raw Score | Indicator |
|-----------|-----------|-----------|
| Executable in `%TEMP%`, `%TMP%`, `%AppData%`, or `%LocalAppData%` | 0.65 | `PROC_SUSPICIOUS_LOCATION` |

Falls back to `System.Diagnostics.Process` handle-count-only mode when WMI is unavailable.

---

### Layer 5 — Network Monitor

**File:** `Monitoring/NetworkMonitor.cs`

Polls TCP connections every **2 seconds** via `IPGlobalProperties.GetActiveTcpConnections()`.
Uses `GetExtendedTcpTable` (iphlpapi.dll P/Invoke) only for PID attribution on suspicious
connections — all connection enumeration goes through the managed API.

**Detection rules:**

| Rule | Raw Score | Detail |
|------|-----------|--------|
| `TOR_EXIT_NODE` | 0.90 | Connection to one of 20 hardcoded high-bandwidth Tor exit IPs |
| `SUSPICIOUS_PORT` | 0.55 | Outbound to 4444, 1337, 31337, 6667, 9001, 8888, 8443 |
| `HIGH_CONN_RATE` | 0.65 | >30 new distinct remote IPs within 10 seconds |
| `EXFIL_DURING_FILE_ACTIVITY` | 0.70 | New external connection within 30 s of a honeytoken/burst event |

**Hardcoded Tor exit nodes** (top-20 high-bandwidth exits, update periodically):
```
185.220.101.1-6  |  23.129.64.131-135  |  199.249.230.68-70
104.244.73.201-202  |  193.218.118.173-174  |  45.148.10.23  |  192.42.116.176
```

**File-activity correlation:**
`DeceptionEngine` calls `NetworkMonitor.NotifyFileActivity()` whenever a honeytoken alert
or burst event fires. Any new external TCP connection within the following 30 seconds is
flagged as a potential exfiltration channel.

---

### Layer 6 — VSS / Shadow Copy Watcher

**File:** `Analysis/VssWatcher.cs`
**Requires:** Administrator

Uses a WMI `__InstanceCreationEvent` subscription (1-second polling interval) to intercept
every new process creation system-wide and inspect its command line against 7 patterns:

| Pattern matched | Indicator | Risk Score |
|----------------|-----------|-----------|
| `vssadmin` / `delete shadows` / `shadowcopy delete` | `SHADOW_COPY_DELETION_ATTEMPT` | 100 / CRITICAL |
| `wbadmin` / `delete catalog` | `BACKUP_CATALOG_DELETED` | 100 / CRITICAL |
| `bcdedit` / `recoveryenabled no` | `BOOT_RECOVERY_DISABLED` | 100 / CRITICAL |

Virtually all known ransomware families run these commands before encryption to destroy
Windows restore points. A match fires a CRITICAL `HoneytokenAlert` immediately through
`AlertManager`, bypassing the fusion threshold.

---

### Layer 7 — Burst Detector

**File:** `Analysis/BurstDetector.cs`

Maintains a sliding **3-second window** queue of all `FileSystemWatcher` events across every
monitored directory (not just honeytoken hits). Fires a `BurstEvent` when:

```
event_count_in_window > 10
  AND
( average_entropy_of_recent_writes > 7.0  OR  no entropy data yet )
```

Entropy data is fed back from honeytoken write-alerts via `RecordEntropyScore()`, making the
detector progressively smarter as encryption events accumulate. A **15-second cooldown**
prevents alert storms. The "no entropy data" branch fires conservatively — rapid renames with
no write data (e.g. a pure rename wave) still trigger the detector.

---

## Signal Fusion Engine

**Files:** `Alerting/SignalFusion.cs`, `Alerting/ThreatSignal.cs`

Every detection layer emits a `ThreatSignal`:

```csharp
class ThreatSignal {
    SignalSource Source;     // Honeytoken | CryptoApi | EtwFileRate | Network | Signature
    int          ProcessId;
    string       ProcessName;
    double       RawScore;   // 0.0 to 1.0  (normalised confidence)
    List<string> Indicators; // e.g. ["RANSOM_EXT_RENAME", "EXT:.locked"]
}
```

SignalFusion keeps a **per-process** list of signals with a **2-minute decay window**.
On each new signal it computes:

```
FusedScore = round( SUM( weight[source] * max(RawScore[source]) ) * 100 )
```

Signal weights:

| Source | Weight | Rationale |
|--------|--------|-----------|
| Honeytoken | **0.35** | Strongest signal — no legitimate process ever touches decoy files |
| CryptoApi | **0.25** | Bulk crypto operations are rare outside ransomware |
| EtwFileRate | **0.20** | Mass file I/O is the physical signature of bulk encryption |
| Network | **0.12** | C2 / exfiltration is indicative but less specific |
| Signature | **0.08** | Process anomalies are supporting evidence |

When `FusedScore >= 70`, a `FusedThreat` is emitted via `OnFusedThreat` with a
**30-second per-process cooldown** to prevent alert flooding.

---

## Automatic Containment

**File:** `Containment/ContainmentEngine.cs`

Triggered by either:
- `HoneytokenAlert.RiskScore >= 70` (direct FSW path, fast)
- `FusedThreat.FusedScore >= 70` (multi-signal fusion path)

**Step 1 — Suspend** (`NtSuspendProcess` P/Invoke into `ntdll.dll`):
Freezes every thread of the target process atomically in ~1 ms.
Stops file encryption cold while we still hold a valid process handle.

**Step 2 — Kill** (`Process.Kill(entireProcessTree: true)`):
Terminates the process and all its children (e.g. `vssadmin` or `wbadmin` spawned
as child processes to delete shadow copies).

**Step 3 — Block execution path** (only when binary path starts with `Temp`/`AppData`/`LocalAppData`):
```
icacls.exe "<path>" /deny "Everyone:(X)"        <- prevents re-launch
MpCmdRun.exe -Scan -ScanType 3 -File "<path>"   <- queues Defender scan / quarantine
```

All containment actions are logged to `rdrs_containment.json`.

---

## Alert Format

**Honeytoken alert (console):**

```
  +==================================================================+
  |  ⚠  HONEYTOKEN ALERT [B4B6598D]  --  CRITICAL (Score: 100/100)  |
  +==================================================================+
  Time      : 2026-03-17 02:41:53.155
  Event     : Renamed
  Token     : _AAAA_resume_final.docx
  Directory : C:\Users\User\Desktop
  Renamed-> : C:\Users\User\Desktop\_AAAA_resume_final.docx.locked
  Process   : cmd (PID: 41920) [UNSIGNED]
  Parent    : explorer (PID: 12044)
  Proc path : C:\WINDOWS\system32\cmd.exe
  Entropy   : 7.9821 bits/byte  [HIGH_ENTROPY_WRITE]
  Indicators: HIGH_ENTROPY_WRITE, RENAMED_UNKNOWN_EXT
  -----------------------------------------------------------------
```

**Multi-signal fusion alert (console):**

```
  +==================================================================+
  |  ⚡  MULTI-SIGNAL THREAT [A1C3F7E2]  --  CRITICAL (87/100)       |
  +==================================================================+
  Time      : 2026-03-17 02:41:54.210
  Process   : evil.exe (PID: 9812)
  Sources   : Honeytoken, CryptoApi, EtwFileRate
    [Honeytoken    ] score=0.95  HIGH_ENTROPY_WRITE, RENAMED_UNKNOWN_EXT
    [CryptoApi     ] score=0.82  CRYPTO_LOAD_AND_FILE_BURST  DLL_LOADS:3
    [EtwFileRate   ] score=0.73  FILE_RATE_HIGH  FILES:67_IN_5s
  -----------------------------------------------------------------
```

---

## Project Structure

```
RDRS/
|
+-- Program.cs                    Entry point — CancellationToken + DeceptionEngine
+-- DeceptionEngine.cs            Orchestrator — starts all monitors, wires callbacks
+-- HoneytokenFile.cs             Data model for a single planted decoy file
+-- HoneytokenPlanter.cs          Creates valid decoy files + configures ACLs/MIL
+-- WatcherManager.cs             FileSystemWatcher per directory + shell-process hint
+-- AlertBuilder.cs               Builds HoneytokenAlert (process attr + entropy + risk)
+-- AlertManager.cs               Thread-safe alert dispatcher + JSON append-logger
+-- ConsoleUI.cs                  Live status board + coloured alert rendering
|
+-- Alerting/
|   +-- ThreatSignal.cs           ThreatSignal / FusedThreat models + SignalSource enum
|   +-- SignalFusion.cs           Weighted per-process fusion engine (2-min decay window)
|
+-- Analysis/
|   +-- EntropyAnalyzer.cs        Shannon entropy (0-8 bits/byte, FileShare.ReadWrite)
|   +-- BurstDetector.cs          Sliding-window file-event rate + entropy threshold
|   +-- VssWatcher.cs             WMI shadow-copy / backup-deletion process watcher
|
+-- Containment/
|   +-- ContainmentEngine.cs      Suspend -> Kill -> icacls block -> Defender scan
|
+-- Monitoring/
|   +-- EtwMonitor.cs             NT Kernel Logger — FileIO + ImageLoad ETW events
|   +-- CryptoApiMonitor.cs       BCrypt DLL-load frequency + cross-signal correlation
|   +-- ProcessBehaviorScorer.cs  WMI I/O rate + parent-child anomaly + launch path
|   +-- NetworkMonitor.cs         IPGlobalProperties + Tor exit IPs + exfil correlation
|
+-- HoneytokenWatcher.csproj      .NET 8 Windows x64
                                  System.Management 7.0.0
                                  Microsoft.Diagnostics.Tracing.TraceEvent 3.1.14
```

---

## Requirements

| Requirement | Detail |
|-------------|--------|
| **OS** | Windows 10 / 11 (x64) |
| **.NET SDK** | .NET 8.0 or later |
| **Privileges** | Standard user for core detection; **Administrator** for ETW, VSS watcher, process kill across users |
| **NuGet packages** | `System.Management 7.0.0` (WMI), `Microsoft.Diagnostics.Tracing.TraceEvent 3.1.14` (ETW) |

Features available **without** admin:

- Honeytoken planting and FileSystemWatcher monitoring
- Shannon entropy analysis on writes
- File burst detection
- Process attribution (Restart Manager + snapshot)
- CryptoApiMonitor correlation layer
- ProcessBehaviorScorer (WMI works for same-user processes)
- NetworkMonitor (TCP connection polling)
- Containment of same-user processes

Features requiring **Administrator**:

- ETW kernel session (FileIOInit / FileIO / ImageLoad)
- VSS/shadow-copy watcher (WMI system-wide process creation events)
- BCrypt ETW provider
- Killing elevated/system processes
- `icacls` execution-path block

---

## Installation & Build

```bash
# 1. Clone the repository
git clone https://github.com/Naks-bro/pbl-rans.git
cd pbl-rans

# 2. Restore NuGet packages
dotnet restore

# 3. Build Release (x64)
dotnet build -c Release

# Binary: bin\Release\net8.0-windows\HoneytokenWatcher.exe
```

---

## Running the Tool

**Recommended: run as Administrator** to unlock ETW and VSS layers.

```powershell
# From an elevated PowerShell prompt:
.\bin\Release\net8.0-windows\HoneytokenWatcher.exe
```

**Startup sequence printed to console:**

```
  [*] Alert log -> D:\...\rdrs_alerts.json
  [*] Planting honeytokens...
  [*] Planted 8 honeytokens across monitored directories.
  [*] Starting FileSystemWatchers...
  [*] All watchers active. Deception layer is live.
  [*] VSS/Shadow-copy watcher active.
  [*] ETW kernel file-monitor active.
  [*] Crypto-API monitor active (ETW correlation + BCrypt provider).
  [*] Process behaviour scorer active (I/O rate + parent-child anomaly).
  [*] Network monitor active (TCP connections + hardcoded Tor exits).
```

A live **status board** then appears, refreshing every 500 ms, showing the state of each
honeytoken (`WATCHING`, `HIT!!`, `CONTAINED`) and total alert count.

Press **`Ctrl+C`** to stop. All honeytoken files are deleted automatically on shutdown.

---

## Testing Detection

### Test 1 — Rename to ransomware extension (simulates encryption rename)

```powershell
$src = "$env:USERPROFILE\Desktop\_AAAA_resume_final.docx"
attrib -H -S $src
Rename-Item $src "$env:USERPROFILE\Desktop\_AAAA_resume_final.docx.locked"
```

**Expected output:** CRITICAL alert (100/100) + Containment fires against the PowerShell
process within ~330 ms.

---

### Test 2 — High-entropy write (simulates AES-256 encryption output)

```powershell
$target = "$env:USERPROFILE\Documents\_AAAA_family_vacation.jpg"
attrib -H -S $target
$bytes = New-Object byte[] 4096
[System.Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
[System.IO.File]::WriteAllBytes($target, $bytes)
```

**Expected output:** CRITICAL alert with `HIGH_ENTROPY_WRITE` indicator (~7.98 bits/byte).

---

### Test 3 — Shadow copy deletion (simulates ransomware pre-encryption step)

```powershell
# Must run as admin — command is detected and alerted, NOT actually executed by RDRS
vssadmin delete shadows /all /quiet
```

**Expected output:** CRITICAL alert (100/100), `SHADOW_COPY_DELETION_ATTEMPT` indicator.

---

### Test 4 — Burst wave (simulates mass file encryption)

```powershell
$dir = "$env:USERPROFILE\Documents"
1..15 | ForEach-Object {
    $b = New-Object byte[] 1024
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($b)
    [System.IO.File]::WriteAllBytes("$dir\enc_$_.tmp", $b)
}
```

**Expected output:** `⚡ ENCRYPTION WAVE DETECTED — CRITICAL (Score: 95/100)` burst alert.

---

## Output Files

| File | Contents |
|------|----------|
| `rdrs_alerts.json` | JSON array of `HoneytokenAlert` objects, appended on every detection |
| `rdrs_containment.json` | JSON array of `ContainmentRecord` objects (action taken per alert) |

Example alert entry:

```json
{
  "AlertId": "B4B6598D",
  "Timestamp": "2026-03-17T02:41:53.1550000",
  "TokenPath": "C:\\Users\\User\\Desktop\\_AAAA_resume_final.docx",
  "TokenFileName": "_AAAA_resume_final.docx",
  "TokenDirectory": "C:\\Users\\User\\Desktop",
  "EventType": "Renamed",
  "NewPath": "C:\\Users\\User\\Desktop\\_AAAA_resume_final.docx.locked",
  "ProcessName": "powershell",
  "ProcessId": 9812,
  "ProcessPath": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
  "ParentProcessName": "explorer",
  "ParentProcessId": 12044,
  "IsSigned": true,
  "EntropyScore": -1.0,
  "RiskScore": 100,
  "RiskLabel": "CRITICAL",
  "Indicators": ["RENAMED_UNKNOWN_EXT"]
}
```

---

## Design Decisions & Limitations

**Why honeytokens as the primary signal (weight 0.35)?**
Ransomware *must* touch files. A perfectly hidden decoy that no legitimate software ever opens
provides a near-zero-false-positive signal. Any access = malicious intent.

**Why Shannon entropy?**
AES-256 and ChaCha20 ciphertext is statistically indistinguishable from random noise —
entropy ≈ 7.95–8.0 bits/byte. Plain text sits at 4.5–5.5 bits/byte. The 7.2 threshold
catches ransomware output while tolerating normal ZIP/JPEG content (~7.0–7.5 bits/byte).

**Why `NtSuspendProcess` before `Kill`?**
`Kill()` is not instantaneous — the OS schedules termination over several scheduler ticks.
During those milliseconds the ransomware continues encrypting files. `NtSuspendProcess`
freezes all threads atomically in ~1 ms, stopping I/O cold, then `Kill` terminates cleanly.

**Why a weighted fusion score instead of any-signal-fires?**
Individual signals have high false-positive rates. Bcrypt.dll is loaded by browsers and
system services. File bursts happen during antivirus scans. Only the *combination* from the
same PID in a short window is conclusive.

**Known limitations:**

- ETW and VSS watcher require **admin privileges**. Without them the honeytoken FSW layer
  still works and catches most real-world ransomware.
- The Tor exit-node list is **hardcoded** and will become stale. In production, refresh it
  periodically from the Tor Project's exit-list endpoint.
- Process attribution via Restart Manager only works when the attacker holds a file handle
  open. One-shot commands (e.g. PowerShell `Set-Content`) close the handle immediately;
  the FSW-time shell-process hint catches these cases instead.
- The tool does **not** prevent ransomware from encrypting files it opens *before* any
  honeytoken is touched. Planting tokens in the directories containing the most sensitive
  files minimises this detection window.
- WMI polling adds ~50–200 ms latency to I/O-rate signals. The FSW path has <5 ms end-to-end
  latency from file event to alert.

---

## Academic Context

This project was built as part of a **Problem-Based Learning (PBL)** assignment in applied
cybersecurity. The goal was to go beyond theory and implement a working detection-and-response
tool from scratch, integrating:

- **Windows internals** — ETW, WMI, P/Invoke (ntdll, rstrtmgr, iphlpapi), Mandatory
  Integrity Control, FileSystemWatcher, Restart Manager
- **Deception-based security** — honeypots / honeytokens as zero-false-positive tripwires
- **Signal correlation and weighted scoring** — multi-sensor fusion for low false-positive rate
- **Automatic incident response** — process suspension, kill, execution path blocking
- **Forensic logging** — structured JSON audit trails for post-incident analysis

---

*Press `Ctrl+C` to stop. Honeytoken files are always cleaned up on exit.*
