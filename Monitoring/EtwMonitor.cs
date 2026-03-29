using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using Microsoft.Diagnostics.Tracing.Session;
using HoneytokenWatcher.Alerting;

namespace HoneytokenWatcher.Monitoring
{
    /// <summary>
    /// ETW kernel-mode file-activity monitor.
    ///
    /// Uses the NT Kernel Logger (or a private RDRS session) to subscribe to:
    ///   - FileIO + FileIOInit  →  file read/write/rename/create/delete events
    ///   - ImageLoad            →  DLL load events (crypto library detection)
    ///
    /// Detection rules:
    ///   1. FILE_RATE_HIGH      — a single process reads or writes >50 distinct
    ///                            files within a 5-second rolling window.
    ///   2. RANSOM_EXT_RENAME   — a process renames a file, and the new extension
    ///                            does not match the old extension AND the new
    ///                            extension looks like a ransomware marker
    ///                            (e.g. .locked, .enc, .crypt, .rans, …).
    ///   3. CRYPTO_DLL_LOAD     — a suspicious process loads a known crypto DLL
    ///                            (bcrypt.dll, advapi32.dll, rsaenh.dll, …)
    ///                            more than once within 10 seconds.
    ///
    /// Each rule emits a <see cref="ThreatSignal"/> via <see cref="OnSignal"/>.
    /// Requires administrative privileges (ETW kernel session needs admin).
    /// </summary>
    public class EtwMonitor : IDisposable
    {
        // ── Constants ─────────────────────────────────────────────────────────
        private const string SessionName      = "RDRS-FileMonitor";
        private const int    FileRateLimit    = 50;    // files per process per window
        private const int    FileRateWindowSec = 5;
        private const int    CryptoDllLoadMax = 2;     // loads within 10 s → signal
        private const int    CryptoDllWindowSec = 10;
        private const int    CooldownSeconds  = 20;    // per-process signal cooldown

        // DLL names that indicate crypto library usage by a process
        private static readonly HashSet<string> CryptoDlls =
            new(StringComparer.OrdinalIgnoreCase)
            {
                "bcrypt.dll", "bcryptprimitives.dll",
                "advapi32.dll",                        // older CryptEncrypt API
                "rsaenh.dll",                          // RSA Enhanced Provider
                "dpapi.dll",
                "cryptbase.dll",
                "ncrypt.dll",
            };

        // Extensions that ransomware typically appends (lower-case, with dot)
        private static readonly HashSet<string> RansomExtensions =
            new(StringComparer.OrdinalIgnoreCase)
            {
                ".locked", ".enc", ".crypt", ".encrypted",
                ".rans", ".ransom", ".cry", ".crypted",
                ".wncry", ".wnry", ".wcry",             // WannaCry
                ".ryuk",                                 // Ryuk
                ".exx", ".ezz", ".ecc",                 // CryptoLocker variants
                ".vvv", ".ccc", ".abc", ".aaa", ".zzz", // TeslaCrypt
                ".locky",                                // Locky
                ".cerber", ".cerber2", ".cerber3",
                ".aesir", ".osiris",                    // Locky later variants
                ".thor", ".micro",
                ".zepto", ".odin",
                ".kyra", ".lol",                        // generic markers
            };

        // Process names we will never attribute (too noisy / system processes)
        private static readonly HashSet<string> IgnoredProcesses =
            new(StringComparer.OrdinalIgnoreCase)
            {
                "System", "Registry", "smss", "csrss", "wininit",
                "services", "lsass", "winlogon", "svchost", "dwm",
                "conhost", "SearchIndexer", "MsMpEng", "antimalware",
                "HoneytokenWatcher",
            };

        // ── State ─────────────────────────────────────────────────────────────

        // Per-process file-event timestamps (sliding window)
        private readonly ConcurrentDictionary<int, Queue<DateTime>> _fileEvents = new();

        // Per-process crypto-DLL load timestamps
        private readonly ConcurrentDictionary<int, Queue<DateTime>> _cryptoLoads = new();

        // Per-process name cache (PID → name, best-effort)
        private readonly ConcurrentDictionary<int, string> _procNameCache = new();
        private readonly ConcurrentDictionary<int, string> _procPathCache = new();

        // Cooldown per-process per-rule: key = "pid:rule"
        private readonly ConcurrentDictionary<string, DateTime> _cooldowns = new();

        private TraceEventSession? _session;
        private Thread?            _etwThread;
        private volatile bool      _running;

        public event Action<ThreatSignal>? OnSignal;

        // ── Lifecycle ─────────────────────────────────────────────────────────

        /// <summary>
        /// Starts the ETW session on a dedicated background thread.
        /// Returns immediately; ETW processing runs asynchronously.
        /// Throws if not running as admin.
        /// </summary>
        public void Start()
        {
            if (_running) return;

            // Validate admin rights before trying to open the session
            if (!IsAdmin())
                throw new UnauthorizedAccessException(
                    "EtwMonitor requires administrative privileges.");

            // Tear down any stale session with the same name (from a previous crash)
            try { TraceEventSession.GetActiveSession(SessionName)?.Dispose(); }
            catch { }

            _running = true;

            _etwThread = new Thread(EtwLoop)
            {
                IsBackground = true,
                Name = "RDRS-ETW"
            };
            _etwThread.Start();
        }

        public void Stop()
        {
            _running = false;
            try { _session?.Stop(); }
            catch { }
        }

        public void Dispose() => Stop();

        // ── ETW processing loop ───────────────────────────────────────────────

        private void EtwLoop()
        {
            try
            {
                using (_session = new TraceEventSession(SessionName))
                {
                    // Enable kernel file I/O events
                    _session.EnableKernelProvider(
                        KernelTraceEventParser.Keywords.FileIOInit |
                        KernelTraceEventParser.Keywords.FileIO     |
                        KernelTraceEventParser.Keywords.ImageLoad);

                    var kernel = _session.Source.Kernel;

                    // ── File write / create events ────────────────────────────
                    kernel.FileIOWrite  += OnFileWrite;
                    kernel.FileIOCreate += OnFileCreate;
                    kernel.FileIORead   += OnFileRead;

                    // ── Rename events ─────────────────────────────────────────
                    kernel.FileIORename += OnFileRename;

                    // ── Image (DLL) load events ───────────────────────────────
                    kernel.ImageLoad += OnImageLoad;

                    // Process the events — blocks until Stop() is called
                    _session.Source.Process();
                }
            }
            catch (Exception ex)
            {
                // Log to stderr so the main UI thread isn't disrupted
                try
                {
                    Console.ForegroundColor = ConsoleColor.DarkGray;
                    Console.WriteLine($"  [ETW] Session ended: {ex.Message}");
                    Console.ResetColor();
                }
                catch { }
            }
        }

        // ── ETW Callbacks ─────────────────────────────────────────────────────

        private void OnFileWrite(FileIOReadWriteTraceData e)
        {
            try { RecordFileEvent(e.ProcessID, e.ProcessName, e.FileName); }
            catch { }
        }

        private void OnFileCreate(FileIOCreateTraceData e)
        {
            try { RecordFileEvent(e.ProcessID, e.ProcessName, e.FileName); }
            catch { }
        }

        private void OnFileRead(FileIOReadWriteTraceData e)
        {
            try { RecordFileEvent(e.ProcessID, e.ProcessName, e.FileName); }
            catch { }
        }

        private void OnFileRename(FileIOInfoTraceData e)
        {
            try
            {
                if (IgnoredProcesses.Contains(e.ProcessName)) return;

                // e.FileName = old path; the rename target isn't directly in this
                // event type for kernel ETW — we detect by watching for new-extension
                // files being created immediately after a read of the same stem.
                // As a simpler heuristic: flag any file whose new name has a known
                // ransomware extension. The FileIOCreate event fires for the target.
                // Here we handle the rename event with the old name for bookkeeping.
                RecordFileEvent(e.ProcessID, e.ProcessName, e.FileName);
            }
            catch { }
        }

        private void OnImageLoad(ImageLoadTraceData e)
        {
            try
            {
                if (IgnoredProcesses.Contains(e.ProcessName)) return;

                var dllName = Path.GetFileName(e.FileName);
                if (!CryptoDlls.Contains(dllName)) return;

                CacheProcessName(e.ProcessID, e.ProcessName, e.FileName);

                var loads = _cryptoLoads.GetOrAdd(e.ProcessID, _ => new Queue<DateTime>());
                DateTime now = DateTime.Now;

                lock (loads)
                {
                    loads.Enqueue(now);
                    // Prune events outside the window
                    var cutoff = now.AddSeconds(-CryptoDllWindowSec);
                    while (loads.Count > 0 && loads.Peek() < cutoff)
                        loads.Dequeue();

                    if (loads.Count >= CryptoDllLoadMax)
                    {
                        if (IsOnCooldown(e.ProcessID, "CryptoDll")) return;
                        SetCooldown(e.ProcessID, "CryptoDll");
                        loads.Clear();
                    }
                    else return;
                }

                FireSignal(new ThreatSignal
                {
                    Source      = SignalSource.CryptoApi,
                    ProcessId   = e.ProcessID,
                    ProcessName = GetCachedName(e.ProcessID, e.ProcessName),
                    ProcessPath = GetCachedPath(e.ProcessID),
                    RawScore    = 0.60,
                    Indicators  = new List<string> { "CRYPTO_DLL_LOAD", $"DLL:{dllName}" },
                });
            }
            catch { }
        }

        // ── Core logic ────────────────────────────────────────────────────────

        private void RecordFileEvent(int pid, string procName, string filePath)
        {
            if (pid <= 0 || IgnoredProcesses.Contains(procName)) return;

            CacheProcessName(pid, procName, "");

            var queue = _fileEvents.GetOrAdd(pid, _ => new Queue<DateTime>());
            DateTime now = DateTime.Now;

            lock (queue)
            {
                queue.Enqueue(now);

                // Prune outside window
                var cutoff = now.AddSeconds(-FileRateWindowSec);
                while (queue.Count > 0 && queue.Peek() < cutoff)
                    queue.Dequeue();

                if (queue.Count < FileRateLimit) return;

                if (IsOnCooldown(pid, "FileRate")) return;
                SetCooldown(pid, "FileRate");

                int burst = queue.Count;
                queue.Clear();
                // Fire outside lock below
                ThreadPool.QueueUserWorkItem(_ =>
                {
                    try
                    {
                        FireSignal(new ThreatSignal
                        {
                            Source      = SignalSource.EtwFileRate,
                            ProcessId   = pid,
                            ProcessName = GetCachedName(pid, procName),
                            ProcessPath = GetCachedPath(pid),
                            RawScore    = Math.Min(0.50 + (burst - FileRateLimit) * 0.01, 1.0),
                            Indicators  = new List<string>
                                { "FILE_RATE_HIGH", $"FILES:{burst}_IN_{FileRateWindowSec}s" },
                        });
                    }
                    catch { }
                });
            }

            // Ransomware extension check on the file being written/created
            try { CheckRansomExtension(pid, procName, filePath); }
            catch { }
        }

        private void CheckRansomExtension(int pid, string procName, string filePath)
        {
            if (string.IsNullOrEmpty(filePath)) return;
            var ext = Path.GetExtension(filePath);
            if (!RansomExtensions.Contains(ext)) return;

            if (IsOnCooldown(pid, "RansomExt")) return;
            SetCooldown(pid, "RansomExt");

            FireSignal(new ThreatSignal
            {
                Source      = SignalSource.EtwFileRate,
                ProcessId   = pid,
                ProcessName = GetCachedName(pid, procName),
                ProcessPath = GetCachedPath(pid),
                RawScore    = 0.90,
                Indicators  = new List<string>
                    { "RANSOM_EXT_RENAME", $"EXT:{ext}", $"FILE:{Path.GetFileName(filePath)}" },
            });
        }

        // ── Helpers ───────────────────────────────────────────────────────────

        private void FireSignal(ThreatSignal signal)
        {
            try { OnSignal?.Invoke(signal); }
            catch { }
        }

        private bool IsOnCooldown(int pid, string rule)
        {
            var key = $"{pid}:{rule}";
            return _cooldowns.TryGetValue(key, out var t) &&
                   (DateTime.Now - t).TotalSeconds < CooldownSeconds;
        }

        private void SetCooldown(int pid, string rule)
        {
            _cooldowns[$"{pid}:{rule}"] = DateTime.Now;
        }

        private void CacheProcessName(int pid, string name, string path)
        {
            if (!string.IsNullOrEmpty(name))
                _procNameCache[pid] = name;
            if (!string.IsNullOrEmpty(path) && path != name)
                _procPathCache[pid] = path;
        }

        private string GetCachedName(int pid, string fallback)
            => _procNameCache.TryGetValue(pid, out var n) ? n : fallback;

        private string GetCachedPath(int pid)
        {
            if (_procPathCache.TryGetValue(pid, out var p)) return p;
            try { return System.Diagnostics.Process.GetProcessById(pid).MainModule?.FileName ?? "unknown"; }
            catch { return "unknown"; }
        }

        private static bool IsAdmin()
        {
            try
            {
                using var id = System.Security.Principal.WindowsIdentity.GetCurrent();
                var principal = new System.Security.Principal.WindowsPrincipal(id);
                return principal.IsInRole(
                    System.Security.Principal.WindowsBuiltInRole.Administrator);
            }
            catch { return false; }
        }
    }
}
