using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Runtime.InteropServices;
using HoneytokenWatcher.Analysis;
using HoneytokenWatcher.Honeytokens;

namespace HoneytokenWatcher.Alerting
{
    public static class AlertBuilder
    {
        public static HoneytokenAlert Build(HoneytokenFile token, string eventType,
            string? newPath = null, Process? processHint = null)
        {
            var alert = new HoneytokenAlert
            {
                AlertId       = Guid.NewGuid().ToString("N")[..8].ToUpper(),
                Timestamp     = DateTime.Now,
                TokenPath     = token.FullPath,
                TokenFileName = token.FileName,
                TokenDirectory = token.Directory,
                EventType     = eventType,
                NewPath       = newPath,
                TriggerCount  = token.TriggerCount,
            };

            var proc = GetAccessingProcess(token.FullPath, processHint);
            if (proc != null)
            {
                alert.ProcessName      = proc.ProcessName;
                alert.ProcessId        = proc.Id;
                alert.ProcessPath      = proc.MainModule?.FileName ?? "unknown";
                alert.ParentProcessId  = GetParentPid(proc.Id);
                alert.ParentProcessName = GetProcessNameById(alert.ParentProcessId);
                alert.IsSigned         = IsProcessSigned(alert.ProcessPath);
            }

            // Entropy analysis — only meaningful for write events
            if (eventType == "Changed" || eventType == "Created")
            {
                var entropy = EntropyAnalyzer.CalculateForFile(token.FullPath);
                alert.EntropyScore = entropy;
                if (entropy > 7.2)
                    alert.Indicators.Add("HIGH_ENTROPY_WRITE");
            }

            alert.RiskScore = CalculateRiskScore(alert);
            alert.RiskLabel = alert.RiskScore switch
            {
                >= 80 => "CRITICAL",
                >= 60 => "HIGH",
                >= 40 => "MEDIUM",
                _     => "LOW"
            };

            return alert;
        }

        // ── Restart Manager P/Invoke ──────────────────────────────────────────

        [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)]
        private static extern int RmStartSession(out uint pSessionHandle, int dwSessionFlags, string strSessionKey);

        [DllImport("rstrtmgr.dll")]
        private static extern int RmEndSession(uint pSessionHandle);

        [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)]
        private static extern int RmRegisterResources(
            uint pSessionHandle, uint nFiles, string[] rgsFilenames,
            uint nApplications, [In] RM_UNIQUE_PROCESS[] rgApplications,
            uint nServices, string[] rgsServiceNames);

        [DllImport("rstrtmgr.dll")]
        private static extern int RmGetList(
            uint dwSessionHandle, out uint pnProcInfoNeeded, ref uint pnProcInfo,
            [In, Out] RM_PROCESS_INFO[] rgAffectedApps, ref uint lpdwRebootReasons);

        [StructLayout(LayoutKind.Sequential)]
        private struct RM_UNIQUE_PROCESS
        {
            public int dwProcessId;
            public System.Runtime.InteropServices.ComTypes.FILETIME ProcessStartTime;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct RM_PROCESS_INFO
        {
            public RM_UNIQUE_PROCESS Process;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
            public string strAppName;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
            public string strServiceShortName;
            public int    ApplicationType;
            public uint   AppStatus;
            public uint   TSSessionId;
            [MarshalAs(UnmanagedType.Bool)]
            public bool   bRestartable;
        }

        // ── Process Attribution ───────────────────────────────────────────────

        /// <summary>
        /// Three-stage attribution:
        ///
        ///  1. Restart Manager — exact match when the handle is still open
        ///     (Word, Excel, any long-running app).
        ///
        ///  2. FSW-time hint — a shell/script process captured by WatcherManager
        ///     at the instant the FSW event fired, before any async latency.
        ///     Catches Add-Content, one-liner PS commands, cmd.exe scripts.
        ///
        ///  3. Process.GetProcesses() fallback — last resort scan of running
        ///     processes, ordered by handle count; works for anything still alive.
        /// </summary>
        private static Process? GetAccessingProcess(string filePath, Process? hint)
        {
            // Stage 1: RM (handle still open)
            var rmProc = GetProcessViaRestartManager(filePath);
            if (rmProc != null) return rmProc;

            // Stage 2: hint captured at FSW fire time
            if (hint != null)
            {
                try { if (!hint.HasExited) return hint; }
                catch { }
            }

            // Stage 3: live scan fallback
            return GetProcessFallback();
        }

        private static Process? GetProcessViaRestartManager(string filePath)
        {
            uint session = 0;
            try
            {
                if (RmStartSession(out session, 0, Guid.NewGuid().ToString("N")) != 0)
                    return null;
                if (RmRegisterResources(session, 1, new[] { filePath },
                    0, Array.Empty<RM_UNIQUE_PROCESS>(),
                    0, Array.Empty<string>()) != 0)
                    return null;

                uint needed = 0, rebootReasons = 0, count = 20;
                var infos = new RM_PROCESS_INFO[20];
                int rv = RmGetList(session, out needed, ref count, infos, ref rebootReasons);
                if (rv != 0 && rv != 234) return null;

                for (uint i = 0; i < count; i++)
                {
                    var pid  = infos[i].Process.dwProcessId;
                    var name = infos[i].strAppName ?? "";
                    if (pid == 0 || IsSystemProcess(name)) continue;
                    try { return Process.GetProcessById(pid); }
                    catch { }
                }
            }
            catch { }
            finally { if (session != 0) RmEndSession(session); }
            return null;
        }

        /// <summary>
        /// Last-resort live scan: prioritises shell/script processes,
        /// then highest handle-count non-system process.
        /// Uses the fast native Process API — no WMI overhead.
        /// </summary>
        private static Process? GetProcessFallback()
        {
            var shellNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
                { "powershell", "pwsh", "cmd", "wscript", "cscript", "mshta" };

            try
            {
                var all = Process.GetProcesses()
                    .Where(p => !IsSystemProcess(p.ProcessName + ".exe"))
                    .ToList();

                // Priority 1: a shell/script process
                var shell = all
                    .Where(p => shellNames.Contains(p.ProcessName))
                    .OrderByDescending(p => { try { return p.HandleCount; } catch { return 0; } })
                    .FirstOrDefault();
                if (shell != null) return shell;

                // Priority 2: highest handle-count non-system process
                return all
                    .OrderByDescending(p => { try { return p.HandleCount; } catch { return 0; } })
                    .FirstOrDefault();
            }
            catch { return null; }
        }

        private static bool IsSystemProcess(string name)
        {
            var sys = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "System", "smss.exe", "csrss.exe", "wininit.exe",
                "services.exe", "lsass.exe", "winlogon.exe", "svchost.exe",
                "dwm.exe", "conhost.exe", "HoneytokenWatcher.exe"
            };
            return sys.Contains(name);
        }

        private static int GetParentPid(int pid)
        {
            try
            {
                using var s = new ManagementObjectSearcher(
                    $"SELECT ParentProcessId FROM Win32_Process WHERE ProcessId = {pid}");
                var r = s.Get().Cast<ManagementObject>().FirstOrDefault();
                return r != null ? Convert.ToInt32(r["ParentProcessId"]) : -1;
            }
            catch { return -1; }
        }

        private static string GetProcessNameById(int pid)
        {
            if (pid < 0) return "unknown";
            try { return Process.GetProcessById(pid).ProcessName; }
            catch { return "unknown"; }
        }

        private static bool IsProcessSigned(string path)
        {
            if (string.IsNullOrEmpty(path) || !File.Exists(path)) return false;
            try
            {
                var cert = System.Security.Cryptography.X509Certificates
                    .X509Certificate.CreateFromSignedFile(path);
                return cert != null;
            }
            catch { return false; }
        }

        // ── Risk Scoring ─────────────────────────────────────────────────────

        private static int CalculateRiskScore(HoneytokenAlert alert)
        {
            int score = 55;

            score += alert.EventType switch
            {
                "Changed" => 15,
                "Renamed" => 20,
                "Deleted" => 10,
                "Created" => 5,
                _         => 5
            };

            if (alert.TriggerCount > 1) score += Math.Min(alert.TriggerCount * 3, 15);

            // Encrypted content written to a honeytoken = very strong ransomware signal
            if (alert.Indicators.Contains("HIGH_ENTROPY_WRITE")) score += 25;

            // Only apply process modifiers when we have a real attribution
            if (!string.IsNullOrEmpty(alert.ProcessName) && alert.ProcessName != "unknown")
            {
                var suspiciousProcs = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
                {
                    "powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe",
                    "mshta.exe", "regsvr32.exe", "rundll32.exe", "certutil.exe"
                };
                if (suspiciousProcs.Contains(alert.ProcessName + ".exe")) score += 10;
                if (!alert.IsSigned) score += 10;
                if (alert.ProcessPath.Contains("Temp",    StringComparison.OrdinalIgnoreCase) ||
                    alert.ProcessPath.Contains("AppData", StringComparison.OrdinalIgnoreCase))
                    score += 8;
            }

            if (alert.NewPath != null)
            {
                var oldExt = Path.GetExtension(alert.TokenFileName);
                var newExt = Path.GetExtension(alert.NewPath);
                if (!string.Equals(oldExt, newExt, StringComparison.OrdinalIgnoreCase))
                    score += 15;
            }

            return Math.Clamp(score, 0, 100);
        }
    }
}
