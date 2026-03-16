using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;

namespace HoneytokenWatcher.Analysis
{
    public class BurstEvent
    {
        public DateTime Timestamp     { get; set; }
        public int      EventCount    { get; set; }
        public int      WindowSeconds { get; set; }
        public string   ProcessName   { get; set; } = "unknown";
        public int      ProcessId     { get; set; }
        public double   AverageEntropy { get; set; } = -1.0;
        public bool     IsHighEntropy  => AverageEntropy > 7.0;
        public int      RiskScore      { get; set; } = 95;
    }

    /// <summary>
    /// Detects ransomware encryption waves by watching the rate of file-change
    /// events across ALL files in the monitored directories (not just honeytokens).
    ///
    /// Trigger: > 10 file-system events within a 3-second sliding window
    ///          AND average entropy of recent writes > 7.0 bits/byte
    ///          (or no entropy data yet — conservative: fire on count alone).
    ///
    /// A 15-second cooldown prevents alert storms after the first detection.
    /// </summary>
    public class BurstDetector
    {
        // ── Tuneable constants ────────────────────────────────────────────────
        private const    int      BurstThreshold   = 10;
        private static readonly TimeSpan Window    = TimeSpan.FromSeconds(3);
        private static readonly TimeSpan Cooldown  = TimeSpan.FromSeconds(15);

        // ── State ─────────────────────────────────────────────────────────────
        private readonly Queue<DateTime> _eventTimes     = new();
        private readonly Queue<double>   _recentEntropy  = new();
        private readonly object          _lock           = new();
        private DateTime                 _lastBurstUtc   = DateTime.MinValue;

        // Best-attribution snapshot across events in the current window
        private string _latestProcessName = "unknown";
        private int    _latestPid         = 0;

        public event Action<BurstEvent>? OnBurst;

        // ── Public API ────────────────────────────────────────────────────────

        /// <summary>
        /// Record one raw file-system event (Changed / Created / Renamed / Deleted).
        /// Call this for EVERY FSW event in the monitored directories — including
        /// events that are not honeytoken hits — to get an accurate rate reading.
        /// </summary>
        public void RecordFileEvent(string processName, int pid)
        {
            var now = DateTime.UtcNow;
            BurstEvent? fire = null;

            lock (_lock)
            {
                // Update latest attribution if we have something real
                if (!string.IsNullOrEmpty(processName) && processName != "unknown")
                {
                    _latestProcessName = processName;
                    _latestPid         = pid;
                }

                // Slide the window — evict events older than 3 seconds
                while (_eventTimes.Count > 0 && now - _eventTimes.Peek() > Window)
                    _eventTimes.Dequeue();

                _eventTimes.Enqueue(now);

                // Check threshold with cooldown guard
                if (_eventTimes.Count > BurstThreshold
                    && now - _lastBurstUtc > Cooldown)
                {
                    var avgEntropy = _recentEntropy.Count > 0
                        ? _recentEntropy.Average()
                        : -1.0;

                    // Fire when entropy is high, OR when we have no entropy data yet
                    // (entropy is only measured on Changed/Created events; Deleted and
                    //  Renamed events do not write bytes, so entropy stays at -1 but
                    //  the rapid rename pattern is itself a ransomware signal).
                    if (avgEntropy < 0 || avgEntropy > 7.0)
                    {
                        _lastBurstUtc = now;
                        fire = new BurstEvent
                        {
                            Timestamp      = DateTime.Now,
                            EventCount     = _eventTimes.Count,
                            WindowSeconds  = (int)Window.TotalSeconds,
                            ProcessName    = _latestProcessName,
                            ProcessId      = _latestPid,
                            AverageEntropy = avgEntropy >= 0 ? Math.Round(avgEntropy, 4) : -1.0,
                            RiskScore      = 95,
                        };
                    }
                }
            }

            // Fire outside the lock to avoid deadlocks in subscribers
            if (fire != null)
                ThreadPool.QueueUserWorkItem(_ => OnBurst?.Invoke(fire));
        }

        /// <summary>
        /// Feed entropy scores from honeytoken write-alerts so the burst decision
        /// becomes entropy-aware as data accumulates.
        /// </summary>
        public void RecordEntropyScore(double entropy)
        {
            if (entropy < 0) return;

            lock (_lock)
            {
                _recentEntropy.Enqueue(entropy);
                // Keep a rolling window of the last 20 readings
                while (_recentEntropy.Count > 20)
                    _recentEntropy.Dequeue();
            }
        }
    }
}
