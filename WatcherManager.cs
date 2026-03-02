using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using HoneytokenWatcher.Alerting;
using HoneytokenWatcher.Honeytokens;

namespace HoneytokenWatcher.Watchers
{
    public class WatcherManager
    {
        private readonly AlertManager _alertManager;
        private readonly List<FileSystemWatcher> _watchers = new();

        private Dictionary<string, HoneytokenFile> _tokenMap = new();

        // Shell/script process names that could be running ransomware or test commands
        private static readonly HashSet<string> ShellNames =
            new(StringComparer.OrdinalIgnoreCase)
            { "powershell", "pwsh", "cmd", "wscript", "cscript", "mshta" };

        public WatcherManager(AlertManager alertManager)
        {
            _alertManager = alertManager;
        }

        public void StartWatching(List<HoneytokenFile> tokens)
        {
            _tokenMap = tokens.ToDictionary(
                t => t.FullPath.ToLowerInvariant(),
                t => t);

            var byDir = tokens.GroupBy(t => t.Directory);

            foreach (var group in byDir)
            {
                if (!Directory.Exists(group.Key)) continue;

                var watcher = new FileSystemWatcher(group.Key)
                {
                    // LastAccess is disabled by default on Win10/11 (NtfsDisableLastAccessUpdate)
                    NotifyFilter = NotifyFilters.LastWrite
                                 | NotifyFilters.FileName
                                 | NotifyFilters.Size,
                    IncludeSubdirectories = false,
                    EnableRaisingEvents = true
                };

                watcher.Changed += OnFileEvent;
                watcher.Deleted += OnFileEvent;
                watcher.Renamed += OnRenameEvent;
                watcher.Created += OnFileEvent;

                _watchers.Add(watcher);
            }
        }

        private void OnFileEvent(object sender, FileSystemEventArgs e)
        {
            // Snapshot shell processes FIRST — before any async latency.
            // Add-Content and similar one-shot commands close their handle and exit
            // within milliseconds; capturing here maximises the chance of attribution.
            var hint = SnapshotShellProcess();

            var key = e.FullPath.ToLowerInvariant();
            if (!_tokenMap.TryGetValue(key, out var token)) return;

            HandleTrigger(token, e.ChangeType.ToString(), e.FullPath, null, hint);
        }

        private void OnRenameEvent(object sender, RenamedEventArgs e)
        {
            var hint = SnapshotShellProcess();

            var key = e.OldFullPath.ToLowerInvariant();
            if (!_tokenMap.TryGetValue(key, out var token)) return;

            HandleTrigger(token, "Renamed", e.OldFullPath, e.FullPath, hint);
        }

        private void HandleTrigger(HoneytokenFile token, string eventType,
            string path, string? newPath = null, Process? processHint = null)
        {
            token.Status = TokenStatus.Triggered;
            token.TriggeredAt = DateTime.Now;
            token.TriggerCount++;

            var alert = AlertBuilder.Build(token, eventType, newPath, processHint);
            _alertManager.Dispatch(alert);
        }

        /// <summary>
        /// Fast synchronous snapshot using Process.GetProcesses() — no WMI overhead.
        /// Returns the shell/script process with the highest handle count that is
        /// currently running at the exact moment the FSW event fires.
        /// </summary>
        private static Process? SnapshotShellProcess()
        {
            try
            {
                return Process.GetProcesses()
                    .Where(p => ShellNames.Contains(p.ProcessName))
                    .OrderByDescending(p =>
                    {
                        try { return p.HandleCount; }
                        catch { return 0; }
                    })
                    .FirstOrDefault();
            }
            catch { return null; }
        }

        public void StopAll()
        {
            foreach (var w in _watchers)
            {
                w.EnableRaisingEvents = false;
                w.Dispose();
            }
        }
    }
}
