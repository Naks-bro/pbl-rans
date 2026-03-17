using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace HoneytokenWatcher.Alerting
{
    // ── Alert Model ──────────────────────────────────────────────────────────

    public class HoneytokenAlert
    {
        public string AlertId { get; set; } = "";
        public DateTime Timestamp { get; set; }
        public string TokenPath { get; set; } = "";
        public string TokenFileName { get; set; } = "";
        public string TokenDirectory { get; set; } = "";
        public string EventType { get; set; } = "";
        public string? NewPath { get; set; }
        public int TriggerCount { get; set; }

        // Process attribution
        public string ProcessName { get; set; } = "unknown";
        public int ProcessId { get; set; }
        public string ProcessPath { get; set; } = "unknown";
        public int ParentProcessId { get; set; }
        public string ParentProcessName { get; set; } = "unknown";
        public bool IsSigned { get; set; }

        // Entropy analysis
        public double EntropyScore { get; set; } = -1.0;  // -1 = not analysed

        // Risk
        public int RiskScore { get; set; }
        public string RiskLabel { get; set; } = "";
        public List<string> Indicators { get; set; } = new();
    }

    // ── Alert Manager ────────────────────────────────────────────────────────

    public class AlertManager
    {
        private readonly string _logPath;
        private readonly object _lock = new();
        private readonly List<HoneytokenAlert> _alerts = new();

        public event Action<HoneytokenAlert>? OnAlert;
        public int TotalAlerts => _alerts.Count;

        /// <summary>Returns the last <paramref name="n"/> alerts (thread-safe copy).</summary>
        public List<HoneytokenAlert> GetRecent(int n)
        {
            lock (_lock)
            {
                if (_alerts.Count == 0) return new List<HoneytokenAlert>();
                int count = Math.Min(n, _alerts.Count);
                return _alerts.GetRange(_alerts.Count - count, count);
            }
        }

        private static readonly JsonSerializerOptions _jsonOpts = new()
        {
            WriteIndented = true,
            Converters = { new JsonStringEnumConverter() }
        };

        public AlertManager(string logPath)
        {
            _logPath = logPath;
        }

        public void Dispatch(HoneytokenAlert alert)
        {
            lock (_lock)
            {
                _alerts.Add(alert);
                AppendToLog(alert);
            }

            // Fire event on thread pool (don't block the FSW callback)
            System.Threading.ThreadPool.QueueUserWorkItem(_ => OnAlert?.Invoke(alert));
        }

        private void AppendToLog(HoneytokenAlert alert)
        {
            try
            {
                // Read existing, append, write back
                List<HoneytokenAlert> existing = new();
                if (File.Exists(_logPath))
                {
                    var raw = File.ReadAllText(_logPath);
                    existing = JsonSerializer.Deserialize<List<HoneytokenAlert>>(raw, _jsonOpts)
                               ?? new();
                }
                existing.Add(alert);
                File.WriteAllText(_logPath,
                    JsonSerializer.Serialize(existing, _jsonOpts));
            }
            catch { /* don't crash on log failure */ }
        }
    }
}
