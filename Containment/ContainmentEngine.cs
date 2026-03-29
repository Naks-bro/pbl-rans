using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Text.Json.Serialization;
using HoneytokenWatcher.Alerting;
using HoneytokenWatcher.Config;

namespace HoneytokenWatcher.Containment
{
    public enum ContainmentAction { None, Suspended, Killed }

    public class ContainmentRecord
    {
        public string AlertId     { get; set; } = "";
        public DateTime Timestamp { get; set; }
        public int ProcessId      { get; set; }
        public string ProcessName { get; set; } = "";
        public string ProcessPath { get; set; } = "";
        public ContainmentAction Action { get; set; } = ContainmentAction.None;
        public bool PathBlocked   { get; set; }
        public string Summary     { get; set; } = "";
    }

    /// <summary>
    /// Automatic containment layer.
    ///
    /// When a honeytoken alert has RiskScore >= 70 and a real process is attributed:
    ///   Step 2.2 — NtSuspendProcess (instantly freezes encryption, reversible)
    ///   Step 2.1 — Process.Kill      (irreversible termination, kills child tree)
    ///   Step 2.3 — Block execution path if binary lives in TEMP / APPDATA / LOCALAPPDATA
    ///              via icacls deny + Windows Defender on-demand scan
    /// </summary>
    public class ContainmentEngine
    {
        // ── P/Invoke ─────────────────────────────────────────────────────────

        /// <summary>
        /// Step 2.2 — Suspend every thread in the target process.
        /// Undocumented but stable NT kernel export; returns STATUS_SUCCESS (0) on success.
        /// </summary>
        [DllImport("ntdll.dll")]
        private static extern int NtSuspendProcess(IntPtr processHandle);

        // ── Suspicious origin directories (Step 2.3) ─────────────────────────

        private static readonly string[] SuspiciousDirs =
        {
            Environment.GetEnvironmentVariable("TEMP")        ?? "",
            Environment.GetEnvironmentVariable("TMP")         ?? "",
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        };

        // ── State ─────────────────────────────────────────────────────────────

        private readonly string _logPath;
        private readonly object _lock = new();

        private static readonly JsonSerializerOptions _jsonOpts = new()
        {
            WriteIndented = true,
            Converters    = { new JsonStringEnumConverter() }
        };

        public event Action<ContainmentRecord>? OnContainment;

        /// <summary>Controls how aggressively the engine responds to a threat.</summary>
        public ContainmentMode Mode { get; set; } = ContainmentMode.KillAndSuspend;

        public ContainmentEngine(string logPath = "rdrs_containment.json")
        {
            _logPath = logPath;
        }

        // ── Public API ────────────────────────────────────────────────────────

        /// <summary>
        /// Evaluate the alert and apply containment when risk score >= 70.
        /// Safe to call from a thread-pool callback — all sub-steps swallow exceptions.
        /// </summary>
        public ContainmentRecord Respond(HoneytokenAlert alert)
        {
            var record = new ContainmentRecord
            {
                AlertId     = alert.AlertId,
                Timestamp   = DateTime.Now,
                ProcessId   = alert.ProcessId,
                ProcessName = alert.ProcessName,
                ProcessPath = alert.ProcessPath,
            };

            // Only act when risk is high and we have a real attributed process
            if (alert.RiskScore < 70 || alert.ProcessId <= 0 || alert.ProcessName == "unknown")
            {
                record.Summary = $"No action — risk {alert.RiskScore}/100 below threshold or process unknown.";
                return record;
            }

            // ── Step 2.2 then 2.1 (skipped in AlertOnly mode) ───────────────
            if (Mode != ContainmentMode.AlertOnly)
            {
                try
                {
                    var proc = Process.GetProcessById(alert.ProcessId);

                    // Suspend first: freezes all threads immediately, stopping encryption
                    // cold while we still hold the process reference.
                    if (TrySuspend(proc))
                        record.Action = ContainmentAction.Suspended;

                    // Kill: terminates the process and its entire child tree.
                    // Skipped in SuspendOnly mode — process stays frozen instead.
                    if (Mode == ContainmentMode.KillAndSuspend && TryKill(proc))
                        record.Action = ContainmentAction.Killed;
                }
                catch { /* process may have already exited — not an error */ }
            }

            // ── Step 2.3 ─────────────────────────────────────────────────────
            if (!string.IsNullOrEmpty(alert.ProcessPath)
                && alert.ProcessPath != "unknown"
                && IsFromSuspiciousDir(alert.ProcessPath))
            {
                BlockExecutionPath(alert.ProcessPath);
                record.PathBlocked = true;
            }

            record.Summary = BuildSummary(record);
            LogRecord(record);

            // Fire event on thread pool so callers are never blocked
            System.Threading.ThreadPool.QueueUserWorkItem(_ => OnContainment?.Invoke(record));

            return record;
        }

        /// <summary>
        /// Convenience overload — responds to a fused multi-signal threat by
        /// converting it to a synthetic HoneytokenAlert and calling Respond().
        /// </summary>
        public ContainmentRecord Respond(FusedThreat threat)
        {
            var synth = new HoneytokenAlert
            {
                AlertId      = threat.ThreatId,
                Timestamp    = threat.Timestamp,
                ProcessId    = threat.ProcessId,
                ProcessName  = threat.ProcessName,
                ProcessPath  = threat.ProcessPath,
                RiskScore    = threat.FusedScore,
                RiskLabel    = threat.RiskLabel,
                EventType    = "FusedThreat",
                TokenPath    = "",
                EntropyScore = -1.0,
                Indicators   = threat.ContributingSignals
                                     .SelectMany(s => s.Indicators)
                                     .Distinct()
                                     .ToList(),
            };
            return Respond(synth);
        }

        // ── Step 2.2 — Suspend ───────────────────────────────────────────────

        private static bool TrySuspend(Process proc)
        {
            try
            {
                // NtSuspendProcess suspends every thread atomically.
                // STATUS_SUCCESS == 0; any other value = failure.
                int status = NtSuspendProcess(proc.Handle);
                return status == 0;
            }
            catch { return false; }
        }

        // ── Step 2.1 — Kill ──────────────────────────────────────────────────

        private static bool TryKill(Process proc)
        {
            try
            {
                if (!proc.HasExited)
                {
                    // entireProcessTree: true also terminates child processes spawned
                    // by the ransomware (e.g. vssadmin, wbadmin for shadow deletion).
                    proc.Kill(entireProcessTree: true);
                    proc.WaitForExit(3000);
                }
                return true;
            }
            catch { return false; }
        }

        // ── Step 2.3 — Block execution path ──────────────────────────────────

        private static bool IsFromSuspiciousDir(string path)
        {
            foreach (var dir in SuspiciousDirs)
            {
                if (!string.IsNullOrEmpty(dir)
                    && path.StartsWith(dir, StringComparison.OrdinalIgnoreCase))
                    return true;
            }
            return false;
        }

        /// <summary>
        /// Two-pronged execution block:
        ///   1. icacls — deny Everyone:Execute so the binary cannot be relaunched.
        ///   2. Windows Defender MpCmdRun — on-demand scan flags and quarantines the file.
        /// </summary>
        private static void BlockExecutionPath(string path)
        {
            // 1. Deny execute permission via icacls
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName        = "icacls.exe",
                    Arguments       = $"\"{path}\" /deny \"Everyone:(X)\"",
                    UseShellExecute = false,
                    CreateNoWindow  = true,
                };
                Process.Start(psi)?.WaitForExit(5000);
            }
            catch { }

            // 2. Queue an on-demand Windows Defender scan of the specific file.
            //    If Defender recognises it as malware it will quarantine/delete it.
            try
            {
                var defenderExe = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                    @"Windows Defender\MpCmdRun.exe");

                if (File.Exists(defenderExe))
                {
                    var psi = new ProcessStartInfo
                    {
                        FileName        = defenderExe,
                        Arguments       = $"-Scan -ScanType 3 -File \"{path}\"",
                        UseShellExecute = false,
                        CreateNoWindow  = true,
                    };
                    Process.Start(psi)?.WaitForExit(15000);
                }
            }
            catch { }
        }

        // ── Helpers ───────────────────────────────────────────────────────────

        private static string BuildSummary(ContainmentRecord r)
        {
            var parts = new List<string>();

            if (r.Action == ContainmentAction.Suspended)
                parts.Add($"Suspended PID {r.ProcessId}");

            if (r.Action == ContainmentAction.Killed)
                parts.Add($"Killed PID {r.ProcessId} ({r.ProcessName})");

            if (r.PathBlocked)
                parts.Add($"Blocked execution path + triggered Defender scan");

            return parts.Count > 0
                ? string.Join("; ", parts)
                : "No action — process already gone.";
        }

        private void LogRecord(ContainmentRecord record)
        {
            lock (_lock)
            {
                try
                {
                    var existing = new List<ContainmentRecord>();
                    if (File.Exists(_logPath))
                    {
                        var raw = File.ReadAllText(_logPath);
                        existing = JsonSerializer.Deserialize<List<ContainmentRecord>>(raw, _jsonOpts)
                                   ?? new();
                    }
                    existing.Add(record);
                    File.WriteAllText(_logPath, JsonSerializer.Serialize(existing, _jsonOpts));
                }
                catch { /* log failure must not crash containment */ }
            }
        }
    }
}
