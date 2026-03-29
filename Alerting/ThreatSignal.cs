using System;
using System.Collections.Generic;

namespace HoneytokenWatcher.Alerting
{
    /// <summary>
    /// Identifies which sub-system produced a signal.
    /// Used for weighted fusion and UI labelling.
    /// </summary>
    public enum SignalSource
    {
        Honeytoken,      // Deception layer (FileSystemWatcher honeytoken hit)
        CryptoApi,       // BCrypt / CryptEncrypt DLL usage pattern
        EtwFileRate,     // ETW kernel: >N files/5 s from one process
        Network,         // Suspicious outbound connection / Tor exit node
        Signature,       // Unsigned binary from suspicious location
    }

    /// <summary>
    /// A single detection signal emitted by one monitoring component.
    /// RawScore is normalised 0.0–1.0; fusion converts it to a weighted 0–100 int.
    /// </summary>
    public class ThreatSignal
    {
        public SignalSource Source      { get; set; }
        public int          ProcessId   { get; set; }
        public string       ProcessName { get; set; } = "unknown";
        public string       ProcessPath { get; set; } = "unknown";

        /// <summary>Normalised confidence: 0.0 (low) to 1.0 (certain).</summary>
        public double       RawScore    { get; set; }

        public DateTime     Timestamp   { get; set; } = DateTime.Now;
        public List<string> Indicators  { get; set; } = new();
    }

    /// <summary>
    /// Result produced by SignalFusion once per-process weighted score ≥ threshold.
    /// FusedScore 0–100 drives ContainmentEngine.
    /// </summary>
    public class FusedThreat
    {
        public string       ThreatId           { get; set; } = Guid.NewGuid().ToString("N")[..8].ToUpper();
        public DateTime     Timestamp          { get; set; } = DateTime.Now;

        public int          ProcessId          { get; set; }
        public string       ProcessName        { get; set; } = "unknown";
        public string       ProcessPath        { get; set; } = "unknown";

        /// <summary>0–100 weighted composite score.</summary>
        public int          FusedScore         { get; set; }

        public string       RiskLabel          => FusedScore switch
        {
            >= 80 => "CRITICAL",
            >= 60 => "HIGH",
            >= 40 => "MEDIUM",
            _     => "LOW"
        };

        public List<ThreatSignal> ContributingSignals { get; set; } = new();

        /// <summary>Human-readable summary of active signal sources.</summary>
        public string ActiveSources =>
            string.Join(", ", ContributingSignals.ConvertAll(s => s.Source.ToString()));
    }
}
