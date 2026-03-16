using System;
using System.Collections.Generic;
using System.Management;
using HoneytokenWatcher.Alerting;

namespace HoneytokenWatcher.Analysis
{
    /// <summary>
    /// Watches for shadow-copy / backup-deletion commands that virtually all
    /// ransomware families run immediately before or during encryption, to
    /// prevent the victim from recovering files via Windows restore points.
    ///
    /// Uses a WMI __InstanceCreationEvent subscription on Win32_Process so that
    /// every new process launch is inspected regardless of which user spawns it.
    ///
    /// Raises a RiskScore=100 CRITICAL alert through the shared AlertManager
    /// the instant a dangerous command-line is detected.
    /// </summary>
    public class VssWatcher : IDisposable
    {
        // ── Dangerous command fragments ───────────────────────────────────────
        // Each tuple: (lower-case fragment to match, indicator tag)
        private static readonly (string Fragment, string Indicator)[] Watchlist =
        {
            ("delete shadows",      "SHADOW_COPY_DELETION_ATTEMPT"),
            ("shadowcopy delete",   "SHADOW_COPY_DELETION_ATTEMPT"),
            ("vssadmin",            "SHADOW_COPY_DELETION_ATTEMPT"),
            ("delete catalog",      "BACKUP_CATALOG_DELETED"),
            ("wbadmin",             "BACKUP_CATALOG_DELETED"),
            ("recoveryenabled no",  "BOOT_RECOVERY_DISABLED"),
            ("bcdedit",             "BOOT_RECOVERY_DISABLED"),
        };

        private readonly AlertManager          _alertManager;
        private          ManagementEventWatcher? _watcher;

        public VssWatcher(AlertManager alertManager)
        {
            _alertManager = alertManager;
        }

        // ── Lifecycle ─────────────────────────────────────────────────────────

        public void Start()
        {
            try
            {
                // Poll every 1 second for new Win32_Process instances.
                // The WITHIN clause sets the polling interval (seconds).
                var query = new WqlEventQuery(
                    "__InstanceCreationEvent",
                    new TimeSpan(0, 0, 1),
                    "TargetInstance ISA 'Win32_Process'");

                _watcher = new ManagementEventWatcher(query);
                _watcher.EventArrived += OnProcessCreated;
                _watcher.Start();
            }
            catch
            {
                // WMI subscriptions require admin rights — fail silently
                // so the rest of the detector still starts.
                _watcher = null;
            }
        }

        public void Stop()
        {
            try
            {
                if (_watcher != null)
                {
                    _watcher.Stop();
                    _watcher.Dispose();
                    _watcher = null;
                }
            }
            catch { }
        }

        public void Dispose() => Stop();

        // ── WMI callback ──────────────────────────────────────────────────────

        private void OnProcessCreated(object sender, EventArrivedEventArgs e)
        {
            try
            {
                var proc    = (ManagementBaseObject)e.NewEvent["TargetInstance"];
                var name    = proc["Name"]?.ToString()        ?? "";
                var cmdLine = proc["CommandLine"]?.ToString() ?? "";
                var pidRaw  = proc["ProcessId"];
                var ppidRaw = proc["ParentProcessId"];
                int pid     = pidRaw  != null ? Convert.ToInt32(pidRaw)  : 0;
                int ppid    = ppidRaw != null ? Convert.ToInt32(ppidRaw) : 0;

                // Build a single string we can scan for all patterns at once
                var combined = (name + " " + cmdLine).ToLowerInvariant();

                foreach (var (fragment, indicator) in Watchlist)
                {
                    if (!combined.Contains(fragment)) continue;

                    var alert = new HoneytokenAlert
                    {
                        AlertId         = Guid.NewGuid().ToString("N")[..8].ToUpper(),
                        Timestamp       = DateTime.Now,
                        TokenPath       = "",
                        TokenFileName   = "[Shadow Copy / Backup System]",
                        TokenDirectory  = "[System]",
                        EventType       = "VssDeletion",
                        // Store the full command line so the analyst can see exactly
                        // what was run.
                        ProcessName     = name,
                        ProcessId       = pid,
                        ProcessPath     = cmdLine,
                        ParentProcessId = ppid,
                        ParentProcessName = GetParentName(ppid),
                        RiskScore       = 100,
                        RiskLabel       = "CRITICAL",
                        Indicators      = new List<string> { indicator },
                        EntropyScore    = -1.0,
                    };

                    _alertManager.Dispatch(alert);
                    break; // one alert per process-creation event is enough
                }
            }
            catch { /* WMI callback must never throw */ }
        }

        private static string GetParentName(int ppid)
        {
            if (ppid <= 0) return "unknown";
            try { return System.Diagnostics.Process.GetProcessById(ppid).ProcessName; }
            catch { return "unknown"; }
        }
    }
}
