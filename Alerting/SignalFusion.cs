using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading;

namespace HoneytokenWatcher.Alerting
{
    /// <summary>
    /// Weighted multi-signal fusion engine.
    ///
    /// Each monitoring component calls <see cref="Submit"/> whenever it
    /// detects a suspicious condition. SignalFusion maintains a per-process
    /// score that decays over time and fires <see cref="OnFusedThreat"/> when
    /// the weighted composite reaches or exceeds <see cref="TriggerThreshold"/>.
    ///
    /// Weights (must sum to 1.0):
    ///   Honeytoken   = 0.35
    ///   CryptoApi    = 0.25
    ///   EtwFileRate  = 0.20
    ///   Network      = 0.12
    ///   Signature    = 0.08
    ///
    /// A 30-second per-process cooldown prevents alert flooding.
    /// Signals older than 2 minutes are automatically pruned.
    /// </summary>
    public class SignalFusion : IDisposable
    {
        // ── Weights ───────────────────────────────────────────────────────────
        private static readonly Dictionary<SignalSource, double> Weights =
            new()
            {
                [SignalSource.Honeytoken]   = 0.35,
                [SignalSource.CryptoApi]    = 0.25,
                [SignalSource.EtwFileRate]  = 0.20,
                [SignalSource.Network]      = 0.12,
                [SignalSource.Signature]    = 0.08,
            };

        public const int    TriggerThreshold = 70;   // 0–100 fused score
        private const int   SignalDecayMinutes = 2;  // signals older than this are pruned
        private const int   CooldownSeconds    = 30; // minimum time between FusedThreat alerts per process

        // ── State ─────────────────────────────────────────────────────────────
        // Key = ProcessId; Value = list of recent signals for that process
        private readonly ConcurrentDictionary<int, List<ThreatSignal>> _signals = new();
        private readonly ConcurrentDictionary<int, DateTime>           _lastFired = new();
        private readonly object _lock = new();

        // Maintenance timer to prune stale entries
        private readonly Timer _pruneTimer;

        public event Action<FusedThreat>? OnFusedThreat;

        public SignalFusion()
        {
            // Prune dead entries every 60 seconds
            _pruneTimer = new Timer(_ => Prune(), null,
                TimeSpan.FromSeconds(60), TimeSpan.FromSeconds(60));
        }

        // ── Public API ────────────────────────────────────────────────────────

        /// <summary>
        /// Accepts a new detection signal, recomputes the per-process fused
        /// score, and fires OnFusedThreat if the threshold is crossed.
        /// Safe to call from any thread.
        /// </summary>
        public void Submit(ThreatSignal signal)
        {
            if (signal.ProcessId <= 0) return;

            lock (_lock)
            {
                var list = _signals.GetOrAdd(signal.ProcessId, _ => new List<ThreatSignal>());
                list.Add(signal);
            }

            Evaluate(signal.ProcessId);
        }

        // ── Evaluation ────────────────────────────────────────────────────────

        private void Evaluate(int pid)
        {
            FusedThreat? threat = null;

            lock (_lock)
            {
                if (!_signals.TryGetValue(pid, out var list)) return;

                // Prune signals older than decay window
                var cutoff = DateTime.Now.AddMinutes(-SignalDecayMinutes);
                list.RemoveAll(s => s.Timestamp < cutoff);
                if (list.Count == 0) return;

                // Check cooldown
                if (_lastFired.TryGetValue(pid, out var lastTime) &&
                    (DateTime.Now - lastTime).TotalSeconds < CooldownSeconds)
                    return;

                // Compute weighted score: for each source, take max RawScore
                // (the strongest signal wins for that source type)
                double weightedSum = 0.0;
                var bestPerSource = new Dictionary<SignalSource, ThreatSignal>();

                foreach (var sig in list)
                {
                    if (!bestPerSource.TryGetValue(sig.Source, out var existing) ||
                        sig.RawScore > existing.RawScore)
                        bestPerSource[sig.Source] = sig;
                }

                foreach (var (source, sig) in bestPerSource)
                {
                    weightedSum += Weights[source] * sig.RawScore;
                }

                // weightedSum is 0.0–1.0; scale to 0–100
                int fusedScore = (int)Math.Round(weightedSum * 100.0);
                if (fusedScore < TriggerThreshold) return;

                // Record cooldown timestamp
                _lastFired[pid] = DateTime.Now;

                // Build the most recent signal for process identity
                var latest = list.OrderByDescending(s => s.Timestamp).First();

                threat = new FusedThreat
                {
                    ProcessId          = pid,
                    ProcessName        = latest.ProcessName,
                    ProcessPath        = latest.ProcessPath,
                    FusedScore         = Math.Min(fusedScore, 100),
                    ContributingSignals = new List<ThreatSignal>(bestPerSource.Values),
                };
            }

            // Fire outside the lock on a thread-pool thread
            if (threat != null)
                ThreadPool.QueueUserWorkItem(_ => OnFusedThreat?.Invoke(threat));
        }

        // ── Housekeeping ──────────────────────────────────────────────────────

        private void Prune()
        {
            try
            {
                var cutoff = DateTime.Now.AddMinutes(-SignalDecayMinutes);
                lock (_lock)
                {
                    foreach (var kvp in _signals)
                    {
                        kvp.Value.RemoveAll(s => s.Timestamp < cutoff);
                    }

                    // Also prune cooldown entries for dead processes
                    var deadCooldowns = _lastFired
                        .Where(kv => (DateTime.Now - kv.Value).TotalMinutes > 5)
                        .Select(kv => kv.Key)
                        .ToList();
                    foreach (var pid in deadCooldowns)
                        _lastFired.TryRemove(pid, out _);
                }
            }
            catch { /* prune failures are non-fatal */ }
        }

        public void Dispose()
        {
            try { _pruneTimer.Dispose(); } catch { }
        }
    }
}
