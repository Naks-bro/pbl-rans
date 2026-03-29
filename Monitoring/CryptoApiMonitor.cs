using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Session;
using HoneytokenWatcher.Alerting;

namespace HoneytokenWatcher.Monitoring
{
    /// <summary>
    /// Crypto-API activity monitor — two-layer approach:
    ///
    /// Layer 1 — EtwMonitor signal correlation (always active):
    ///   Subscribes to <see cref="EtwMonitor.OnSignal"/> and keeps a per-process
    ///   activity record. When the same process generates both a CRYPTO_DLL_LOAD
    ///   and a FILE_RATE_HIGH (or RANSOM_EXT_RENAME) signal within 30 seconds,
    ///   it fires a high-confidence <see cref="ThreatSignal"/> with Source=CryptoApi.
    ///
    /// Layer 2 — BCrypt ETW provider (best-effort, admin required):
    ///   Tries to subscribe to the Microsoft-Windows-Crypto-BCrypt ETW provider.
    ///   If BCrypt events arrive from a user-land process at a rate > 20/5 s
    ///   (indicating a bulk-encryption loop), a CryptoApi signal is fired.
    ///   Falls back silently if the provider is unavailable or access is denied.
    ///
    /// All signals are submitted to the shared <see cref="SignalFusion"/> instance.
    /// </summary>
    public class CryptoApiMonitor : IDisposable
    {
        // ── BCrypt ETW provider ───────────────────────────────────────────────
        private static readonly Guid BCryptProviderGuid =
            new("A74EFE00-14BE-4EF9-9DA2-1E9A0E2B92F2");

        private const string BCryptSessionName   = "RDRS-CryptoApi";
        private const int    BCryptRateLimit     = 20;   // events per process per window
        private const int    BCryptWindowSec     = 5;

        // ── Correlation constants ─────────────────────────────────────────────
        private const int CorrelationWindowSec  = 30;   // look-back for cross-signal correlation
        private const int CooldownSeconds       = 25;

        // ── Correlation state — per-process recent signal types ───────────────

        private class ProcRecord
        {
            public string       ProcessName = "unknown";
            public string       ProcessPath = "unknown";
            public List<(DateTime When, string Tag)> Events = new();
        }

        private readonly ConcurrentDictionary<int, ProcRecord>   _state     = new();
        private readonly ConcurrentDictionary<int, Queue<DateTime>> _bcryptEvents = new();
        private readonly ConcurrentDictionary<string, DateTime>   _cooldowns = new();

        private readonly SignalFusion  _fusion;
        private          TraceEventSession? _bcryptSession;
        private          Thread?        _bcryptThread;
        private volatile bool           _running;

        public CryptoApiMonitor(SignalFusion fusion)
        {
            _fusion = fusion;
        }

        // ── Lifecycle ─────────────────────────────────────────────────────────

        /// <summary>
        /// Hooks into <paramref name="etwMonitor"/>'s signal stream (Layer 1).
        /// Optionally starts the BCrypt ETW session (Layer 2) — non-fatal if unavailable.
        /// </summary>
        public void Start(EtwMonitor etwMonitor)
        {
            if (_running) return;
            _running = true;

            // Layer 1: subscribe to EtwMonitor signal stream
            etwMonitor.OnSignal += ReceiveEtwSignal;

            // Layer 2: BCrypt ETW session on a background thread
            _bcryptThread = new Thread(BcryptLoop)
            {
                IsBackground = true,
                Name = "RDRS-CryptoApi"
            };
            _bcryptThread.Start();
        }

        public void Stop()
        {
            _running = false;
            try { _bcryptSession?.Stop(); } catch { }
        }

        public void Dispose() => Stop();

        // ── Layer 1 — EtwMonitor correlation ─────────────────────────────────

        private void ReceiveEtwSignal(ThreatSignal sig)
        {
            try
            {
                bool relevant = sig.Source == SignalSource.CryptoApi ||
                                sig.Source == SignalSource.EtwFileRate;
                if (!relevant || sig.ProcessId <= 0) return;

                var rec = _state.GetOrAdd(sig.ProcessId, _ => new ProcRecord());
                var now = DateTime.Now;

                lock (rec)
                {
                    if (sig.ProcessName != "unknown") rec.ProcessName = sig.ProcessName;
                    if (sig.ProcessPath != "unknown") rec.ProcessPath = sig.ProcessPath;

                    foreach (var ind in sig.Indicators)
                        rec.Events.Add((now, ind));

                    // Prune outside correlation window
                    var cutoff = now.AddSeconds(-CorrelationWindowSec);
                    rec.Events.RemoveAll(e => e.When < cutoff);

                    // Count crypto DLL load events explicitly — frequency is the signal
                    int cryptoDllCount = rec.Events.Count(
                        e => e.Tag.StartsWith("CRYPTO_DLL_LOAD", StringComparison.OrdinalIgnoreCase) ||
                             e.Tag.StartsWith("DLL:",           StringComparison.OrdinalIgnoreCase));

                    var tags = rec.Events.Select(e => e.Tag)
                                         .ToHashSet(StringComparer.OrdinalIgnoreCase);
                    bool hasFileRate  = tags.Contains("FILE_RATE_HIGH");
                    bool hasRansomExt = tags.Contains("RANSOM_EXT_RENAME");

                    if (hasRansomExt)
                    {
                        TryFireCorrelated(sig.ProcessId, rec, 0.92,
                            $"RANSOM_EXT_CORRELATED  CRYPTO_DLL_LOADS:{cryptoDllCount}");
                    }
                    else if (cryptoDllCount >= 2 && hasFileRate)
                    {
                        // Two or more distinct crypto DLL loads + burst I/O = bulk encryption loop
                        TryFireCorrelated(sig.ProcessId, rec, 0.82,
                            $"CRYPTO_LOAD_AND_FILE_BURST  DLL_LOADS:{cryptoDllCount}");
                    }
                    else if (cryptoDllCount >= 4)
                    {
                        // Repeated crypto DLL activity alone without file burst still suspicious
                        TryFireCorrelated(sig.ProcessId, rec, 0.65,
                            $"HIGH_FREQ_CRYPTO_DLL  LOADS:{cryptoDllCount}_IN_{CorrelationWindowSec}s");
                    }
                }
            }
            catch { /* signal correlation must never throw */ }
        }

        private void TryFireCorrelated(int pid, ProcRecord rec, double rawScore, string indicator)
        {
            var key = $"{pid}:corr";
            if (_cooldowns.TryGetValue(key, out var t) &&
                (DateTime.Now - t).TotalSeconds < CooldownSeconds)
                return;

            _cooldowns[key] = DateTime.Now;

            var signal = new ThreatSignal
            {
                Source      = SignalSource.CryptoApi,
                ProcessId   = pid,
                ProcessName = rec.ProcessName,
                ProcessPath = rec.ProcessPath,
                RawScore    = rawScore,
                Indicators  = new List<string> { indicator },
            };

            ThreadPool.QueueUserWorkItem(_ =>
            {
                try { _fusion.Submit(signal); } catch { }
            });
        }

        // ── Layer 2 — BCrypt ETW ──────────────────────────────────────────────

        private void BcryptLoop()
        {
            try
            {
                // Tear down any stale session
                try { TraceEventSession.GetActiveSession(BCryptSessionName)?.Dispose(); }
                catch { }

                using (_bcryptSession = new TraceEventSession(BCryptSessionName))
                {
                    // Enable the BCrypt provider — best-effort
                    _bcryptSession.EnableProvider(BCryptProviderGuid);

                    // Parse all events from this provider via the dynamic parser
                    _bcryptSession.Source.Dynamic.All += OnBcryptEvent;

                    // Blocks until Stop() is called
                    _bcryptSession.Source.Process();
                }
            }
            catch
            {
                // Provider unavailable, insufficient rights, or session error — silent fallback
            }
        }

        private void OnBcryptEvent(TraceEvent e)
        {
            try
            {
                if (!_running) return;
                int pid = e.ProcessID;
                if (pid <= 0) return;

                var queue = _bcryptEvents.GetOrAdd(pid, _ => new Queue<DateTime>());
                DateTime now = DateTime.Now;

                lock (queue)
                {
                    queue.Enqueue(now);
                    var cutoff = now.AddSeconds(-BCryptWindowSec);
                    while (queue.Count > 0 && queue.Peek() < cutoff)
                        queue.Dequeue();

                    if (queue.Count < BCryptRateLimit) return;

                    var key = $"{pid}:bcrypt";
                    if (_cooldowns.TryGetValue(key, out var last) &&
                        (now - last).TotalSeconds < CooldownSeconds)
                        return;

                    _cooldowns[key] = now;
                    int burst = queue.Count;
                    queue.Clear();
                }

                string procName;
                try { procName = System.Diagnostics.Process.GetProcessById(pid).ProcessName; }
                catch { procName = e.ProcessName; }

                var signal = new ThreatSignal
                {
                    Source      = SignalSource.CryptoApi,
                    ProcessId   = pid,
                    ProcessName = procName,
                    RawScore    = 0.75,
                    Indicators  = new List<string> { "BCRYPT_API_BURST" },
                };

                ThreadPool.QueueUserWorkItem(_ =>
                {
                    try { _fusion.Submit(signal); } catch { }
                });
            }
            catch { }
        }
    }
}
