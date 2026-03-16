using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Management;
using System.Threading;
using HoneytokenWatcher.Alerting;

namespace HoneytokenWatcher.Monitoring
{
    /// <summary>
    /// Process behaviour scorer — WMI-based continuous process monitor.
    ///
    /// Polls Win32_Process every second and computes a per-process anomaly score
    /// from three independent signals:
    ///
    ///   1. I/O RATE — WriteTransferCount delta (bytes written per second).
    ///      Ransomware reading all user files and writing encrypted versions
    ///      produces very high sustained write rates (often >5 MB/s).
    ///      Threshold: > 5 MB/s write rate → signal score 0.60; > 20 MB/s → 0.85.
    ///
    ///   2. PARENT–CHILD ANOMALY — detects living-off-the-land pivots:
    ///      e.g. winword / excel / powerpnt spawning cmd / powershell,
    ///      or explorer spawning certutil / regsvr32 / mshta.
    ///      Each matched pair fires score 0.70 (Signature source, weight 0.08).
    ///
    ///   3. HANDLE STORM — a process opening > 500 handles in 5 seconds
    ///      (rapid concurrent file-handle acquisition before encryption).
    ///      Threshold: handleDelta > 500/s → score 0.65.
    ///
    /// All signals go into <see cref="SignalFusion"/> via <see cref="Submit"/>.
    /// Requires admin for WMI I/O counters; gracefully falls back to handle-count
    /// monitoring using System.Diagnostics when WMI is unavailable.
    /// </summary>
    public class ProcessBehaviorScorer : IDisposable
    {
        // ── Parent-child anomaly table ────────────────────────────────────────
        // If a parent-name process spawns any child-name process → suspicious
        private static readonly Dictionary<string, HashSet<string>> ParentChildRules =
            new(StringComparer.OrdinalIgnoreCase)
            {
                ["winword"]   = new(StringComparer.OrdinalIgnoreCase) { "cmd", "powershell", "pwsh", "wscript", "cscript", "mshta", "certutil" },
                ["excel"]     = new(StringComparer.OrdinalIgnoreCase) { "cmd", "powershell", "pwsh", "wscript", "cscript", "mshta", "certutil" },
                ["powerpnt"]  = new(StringComparer.OrdinalIgnoreCase) { "cmd", "powershell", "pwsh", "wscript", "cscript" },
                ["outlook"]   = new(StringComparer.OrdinalIgnoreCase) { "cmd", "powershell", "pwsh", "wscript", "cscript", "mshta" },
                ["explorer"]  = new(StringComparer.OrdinalIgnoreCase) { "certutil", "regsvr32", "mshta", "wscript", "cscript" },
                ["svchost"]   = new(StringComparer.OrdinalIgnoreCase) { "powershell", "cmd", "wscript", "certutil", "mshta" },
            };

        // Processes we never want to score (system noise)
        private static readonly HashSet<string> IgnoredProcesses =
            new(StringComparer.OrdinalIgnoreCase)
            {
                "System", "Registry", "smss", "csrss", "wininit", "services",
                "lsass", "winlogon", "svchost", "dwm", "conhost",
                "SearchIndexer", "MsMpEng", "HoneytokenWatcher",
                "taskhostw", "sihost", "fontdrvhost",
            };

        // ── I/O rate thresholds ───────────────────────────────────────────────
        private const long   IoRateLowBytes  =  5 * 1024 * 1024;   //  5 MB/s → 0.60
        private const long   IoRateHighBytes = 20 * 1024 * 1024;   // 20 MB/s → 0.85
        private const int    HandleDeltaHigh = 500;                 // handles opened/s → 0.65
        private const int    PollIntervalMs  = 2000;                // 2-second poll interval
        private const int    CooldownSeconds = 30;

        // Directories that a legitimate process should NOT live in
        private static readonly string[] SuspiciousDirs =
        {
            Environment.GetEnvironmentVariable("TEMP")        ?? "",
            Environment.GetEnvironmentVariable("TMP")         ?? "",
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        };

        // ── Per-process snapshot for delta computation ────────────────────────
        private class ProcSnapshot
        {
            public ulong WriteBytes   { get; set; }
            public int   HandleCount  { get; set; }
            public int   ParentPid    { get; set; }
            public string Name        { get; set; } = "";
            public string ExePath     { get; set; } = "";
        }

        private readonly ConcurrentDictionary<int, ProcSnapshot>   _prev      = new();
        private readonly ConcurrentDictionary<string, DateTime>    _cooldowns = new();

        private readonly SignalFusion _fusion;
        private          Thread?      _pollThread;
        private volatile bool         _running;

        // Set of PIDs whose parent has already been checked to avoid re-firing
        private readonly ConcurrentDictionary<int, bool> _parentChecked = new();

        public ProcessBehaviorScorer(SignalFusion fusion)
        {
            _fusion = fusion;
        }

        // ── Lifecycle ─────────────────────────────────────────────────────────

        public void Start()
        {
            if (_running) return;
            _running = true;

            _pollThread = new Thread(PollLoop)
            {
                IsBackground = true,
                Name = "RDRS-ProcScorer"
            };
            _pollThread.Start();
        }

        public void Stop()  { _running = false; }
        public void Dispose() => Stop();

        // ── Main poll loop ────────────────────────────────────────────────────

        private void PollLoop()
        {
            // Give the rest of startup a moment to settle before the first WMI poll
            Thread.Sleep(2000);

            while (_running)
            {
                try  { Poll(); }
                catch { /* poll failures are non-fatal */ }

                Thread.Sleep(PollIntervalMs);
            }
        }

        private void Poll()
        {
            // Batch WMI query: one round-trip for all processes
            var current = QueryWmi();

            foreach (var (pid, snap) in current)
            {
                if (!_running) return;
                if (IgnoredProcesses.Contains(snap.Name)) continue;

                // ── I/O rate check ────────────────────────────────────────────
                if (_prev.TryGetValue(pid, out var prev))
                {
                    long writeDelta = (long)snap.WriteBytes - (long)prev.WriteBytes;
                    int  hdlDelta   = snap.HandleCount - prev.HandleCount;

                    if (writeDelta > IoRateHighBytes)
                        FireSignal(pid, snap, 0.85, SignalSource.EtwFileRate,
                            new[] { "HIGH_WRITE_RATE", $"BYTES/S:{writeDelta:N0}" });

                    else if (writeDelta > IoRateLowBytes)
                        FireSignal(pid, snap, 0.60, SignalSource.EtwFileRate,
                            new[] { "ELEVATED_WRITE_RATE", $"BYTES/S:{writeDelta:N0}" });

                    if (hdlDelta > HandleDeltaHigh)
                        FireSignal(pid, snap, 0.65, SignalSource.Signature,
                            new[] { "HANDLE_STORM", $"HANDLES/S:{hdlDelta}" });
                }

                // ── Parent-child anomaly (check once per PID) ─────────────────
                if (!_parentChecked.ContainsKey(pid) && snap.ParentPid > 0)
                {
                    _parentChecked[pid] = true;
                    CheckParentChild(pid, snap, current);

                    // ── Suspicious launch location ─────────────────────────────
                    // A process spawned from Temp / AppData is a strong malware
                    // indicator — legitimate software is never installed there.
                    if (snap.ExePath != "unknown" && IsFromSuspiciousDir(snap.ExePath))
                    {
                        FireSignal(pid, snap, 0.65, SignalSource.Signature,
                            new[] { "PROC_SUSPICIOUS_LOCATION",
                                    $"PATH:{snap.ExePath}" });
                    }
                }
            }

            // Update snapshots
            foreach (var (pid, snap) in current)
                _prev[pid] = snap;

            // Remove stale PIDs that have exited
            foreach (var pid in _prev.Keys.Except(current.Keys).ToList())
            {
                _prev.TryRemove(pid, out _);
                _parentChecked.TryRemove(pid, out _);
            }
        }

        // ── WMI batch query ───────────────────────────────────────────────────

        private static Dictionary<int, ProcSnapshot> QueryWmi()
        {
            var result = new Dictionary<int, ProcSnapshot>();
            try
            {
                using var searcher = new ManagementObjectSearcher(
                    "SELECT ProcessId, Name, ExecutablePath, ParentProcessId, " +
                    "WriteTransferCount, HandleCount FROM Win32_Process");

                foreach (ManagementObject obj in searcher.Get())
                {
                    try
                    {
                        int    pid    = Convert.ToInt32(obj["ProcessId"]);
                        string name   = obj["Name"]?.ToString()           ?? "";
                        string path   = obj["ExecutablePath"]?.ToString() ?? "unknown";
                        int    ppid   = Convert.ToInt32(obj["ParentProcessId"]);
                        ulong  writes = Convert.ToUInt64(obj["WriteTransferCount"]);
                        int    hdl    = Convert.ToInt32(obj["HandleCount"]);

                        if (pid > 0)
                            result[pid] = new ProcSnapshot
                            {
                                Name        = System.IO.Path.GetFileNameWithoutExtension(name),
                                ExePath     = path,
                                ParentPid   = ppid,
                                WriteBytes  = writes,
                                HandleCount = hdl,
                            };
                    }
                    catch { /* skip individual entry failures */ }
                }
            }
            catch
            {
                // WMI unavailable — fall back to System.Diagnostics for handle counts
                foreach (var p in Process.GetProcesses())
                {
                    try
                    {
                        result[p.Id] = new ProcSnapshot
                        {
                            Name        = p.ProcessName,
                            HandleCount = p.HandleCount,
                            WriteBytes  = 0,
                            ParentPid   = 0,
                        };
                    }
                    catch { }
                }
            }

            return result;
        }

        // ── Parent-child anomaly check ────────────────────────────────────────

        private void CheckParentChild(int childPid, ProcSnapshot child,
            Dictionary<int, ProcSnapshot> all)
        {
            if (!all.TryGetValue(child.ParentPid, out var parent)) return;

            if (!ParentChildRules.TryGetValue(parent.Name, out var suspiciousChildren))
                return;

            if (!suspiciousChildren.Contains(child.Name)) return;

            // e.g. winword → powershell is a classic macro-dropper pivot
            FireSignal(childPid, child, 0.70, SignalSource.Signature,
                new[] { "PARENT_CHILD_ANOMALY",
                        $"PARENT:{parent.Name}(PID:{child.ParentPid})",
                        $"CHILD:{child.Name}(PID:{childPid})" });
        }

        // ── Helpers ───────────────────────────────────────────────────────────

        private static bool IsFromSuspiciousDir(string path)
        {
            foreach (var dir in SuspiciousDirs)
                if (!string.IsNullOrEmpty(dir) &&
                    path.StartsWith(dir, StringComparison.OrdinalIgnoreCase))
                    return true;
            return false;
        }

        // ── Signal emission ───────────────────────────────────────────────────

        private void FireSignal(int pid, ProcSnapshot snap, double rawScore,
            SignalSource source, string[] indicators)
        {
            // Per-process per-indicator cooldown
            var key = $"{pid}:{indicators[0]}";
            if (_cooldowns.TryGetValue(key, out var last) &&
                (DateTime.Now - last).TotalSeconds < CooldownSeconds)
                return;

            _cooldowns[key] = DateTime.Now;

            var signal = new ThreatSignal
            {
                Source      = source,
                ProcessId   = pid,
                ProcessName = snap.Name,
                ProcessPath = snap.ExePath,
                RawScore    = rawScore,
                Indicators  = new List<string>(indicators),
            };

            ThreadPool.QueueUserWorkItem(_ =>
            {
                try { _fusion.Submit(signal); } catch { }
            });
        }
    }
}
