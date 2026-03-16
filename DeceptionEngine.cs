using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using HoneytokenWatcher.Alerting;
using HoneytokenWatcher.Analysis;
using HoneytokenWatcher.Containment;
using HoneytokenWatcher.Honeytokens;
using HoneytokenWatcher.Monitoring;
using HoneytokenWatcher.UI;
using HoneytokenWatcher.Watchers;

namespace HoneytokenWatcher.Core
{
    public class DeceptionEngine
    {
        private readonly HoneytokenPlanter  _planter;
        private readonly WatcherManager     _watcherManager;
        private readonly AlertManager       _alertManager;
        private readonly ContainmentEngine  _containmentEngine;
        private readonly BurstDetector      _burstDetector;
        private readonly VssWatcher         _vssWatcher;
        private readonly EtwMonitor             _etwMonitor;
        private readonly CryptoApiMonitor       _cryptoMonitor;
        private readonly ProcessBehaviorScorer  _procScorer;
        private readonly NetworkMonitor         _networkMonitor;
        private readonly SignalFusion           _signalFusion;
        private readonly ConsoleUI              _ui;
        private readonly List<HoneytokenFile> _deployedTokens = new();

        public DeceptionEngine()
        {
            _alertManager      = new AlertManager("rdrs_alerts.json");
            _burstDetector     = new BurstDetector();
            _planter           = new HoneytokenPlanter();
            _watcherManager    = new WatcherManager(_alertManager, _burstDetector);
            _containmentEngine = new ContainmentEngine("rdrs_containment.json");
            _vssWatcher        = new VssWatcher(_alertManager);
            _etwMonitor        = new EtwMonitor();
            _signalFusion      = new SignalFusion();
            _cryptoMonitor     = new CryptoApiMonitor(_signalFusion);
            _procScorer        = new ProcessBehaviorScorer(_signalFusion);
            _networkMonitor    = new NetworkMonitor(_signalFusion);
            _ui                = new ConsoleUI();
        }

        public void Run(CancellationToken ct)
        {
            _ui.DrawBanner();
            _ui.Status($"Alert log → {Path.GetFullPath("rdrs_alerts.json")}");

            // 1. Plant honeytokens
            try
            {
                _ui.Status("Planting honeytokens...");
                _deployedTokens.AddRange(_planter.PlantAll());
                _ui.Status($"Planted {_deployedTokens.Count} honeytokens across monitored directories.");
            }
            catch (Exception ex)
            {
                _ui.Warn($"Honeytoken planting error: {ex.Message}");
            }

            if (_deployedTokens.Count == 0)
            {
                _ui.Warn("No honeytokens could be planted — nothing to watch. Exiting.");
                return;
            }

            // 2. Start watchers + VSS watcher
            try
            {
                _ui.Status("Starting FileSystemWatchers...");
                _watcherManager.StartWatching(_deployedTokens);
                _ui.Status("All watchers active. Deception layer is live.");
            }
            catch (Exception ex)
            {
                _ui.Warn($"Watcher startup failed: {ex.Message}");
                _planter.RemoveAll(_deployedTokens);
                return;
            }

            try
            {
                _vssWatcher.Start();
                _ui.Status("VSS/Shadow-copy watcher active.\n");
            }
            catch (Exception ex)
            {
                _ui.Warn($"VSS watcher failed to start (non-fatal): {ex.Message}");
            }

            // 3a. Start ETW monitor — feeds signals into SignalFusion
            try
            {
                _etwMonitor.OnSignal += (sig) =>
                {
                    try { _signalFusion.Submit(sig); }
                    catch { }
                };
                _etwMonitor.Start();
                _ui.Status("ETW kernel file-monitor active.");
            }
            catch (UnauthorizedAccessException)
            {
                _ui.Warn("ETW monitor requires admin rights — skipping (non-fatal).");
            }
            catch (Exception ex)
            {
                _ui.Warn($"ETW monitor failed to start (non-fatal): {ex.Message}");
            }

            // 3b. CryptoApiMonitor — correlates ETW crypto signals + optional BCrypt ETW
            try
            {
                _cryptoMonitor.Start(_etwMonitor);
                _ui.Status("Crypto-API monitor active (ETW correlation + BCrypt provider).");
            }
            catch (Exception ex)
            {
                _ui.Warn($"CryptoApiMonitor failed to start (non-fatal): {ex.Message}");
            }

            // 3c. ProcessBehaviorScorer — WMI I/O rate + parent-child anomaly detection
            try
            {
                _procScorer.Start();
                _ui.Status("Process behaviour scorer active (I/O rate + parent-child anomaly).");
            }
            catch (Exception ex)
            {
                _ui.Warn($"ProcessBehaviorScorer failed to start (non-fatal): {ex.Message}");
            }

            // 3d. NetworkMonitor — TCP connection tracking + Tor DNSBL
            try
            {
                _networkMonitor.Start();
                _ui.Status("Network monitor active (TCP connections + hardcoded Tor exits).");
            }
            catch (Exception ex)
            {
                _ui.Warn($"NetworkMonitor failed to start (non-fatal): {ex.Message}");
            }

            // SignalFusion callback — FusedThreat drives containment independently of FSW
            _signalFusion.OnFusedThreat += (threat) =>
            {
                try { _ui.DrawFusedThreat(threat); }
                catch { }

                try
                {
                    var record = _containmentEngine.Respond(threat);
                    if (record.Action != ContainmentAction.None || record.PathBlocked)
                    {
                        try { _ui.DrawContainment(record); }
                        catch { }
                    }
                }
                catch { }
            };

            // 3. Initialize alert manager — register callbacks
            _alertManager.OnAlert += (alert) =>
            {
                // Draw alert first so the user sees it immediately
                try { _ui.DrawAlert(alert); }
                catch { /* UI failure must not crash the alert pipeline */ }

                // Notify network monitor — a honeytoken hit is a file-activity event;
                // any new external TCP connection within 30 s is flagged as exfiltration.
                try { _networkMonitor.NotifyFileActivity(); } catch { }

                // Feed honeytoken hit into signal fusion so multi-sensor
                // scores can combine with ETW / crypto signals from the same PID.
                try
                {
                    if (alert.ProcessId > 0 && alert.ProcessName != "unknown")
                    {
                        _signalFusion.Submit(new ThreatSignal
                        {
                            Source      = SignalSource.Honeytoken,
                            ProcessId   = alert.ProcessId,
                            ProcessName = alert.ProcessName,
                            ProcessPath = alert.ProcessPath,
                            RawScore    = Math.Clamp(alert.RiskScore / 100.0, 0.0, 1.0),
                            Indicators  = new System.Collections.Generic.List<string>(alert.Indicators),
                            Timestamp   = alert.Timestamp,
                        });
                    }
                }
                catch { }

                // Feed entropy back to the burst detector so its threshold
                // becomes entropy-aware as write-events accumulate.
                try
                {
                    if (alert.EntropyScore >= 0)
                        _burstDetector.RecordEntropyScore(alert.EntropyScore);
                }
                catch { }

                // Automatic containment: suspend → kill → block path (risk >= 70)
                try
                {
                    var record = _containmentEngine.Respond(alert);

                    if (record.Action != ContainmentAction.None || record.PathBlocked)
                    {
                        // Mark the token as contained on the status board
                        var token = _deployedTokens.Find(t => t.FullPath == alert.TokenPath);
                        if (token != null)
                            token.Status = TokenStatus.Contained;

                        try { _ui.DrawContainment(record); }
                        catch { /* UI failure must not crash containment */ }
                    }
                }
                catch { /* containment failure must not crash the alert pipeline */ }
            };

            // Burst detection callback
            _burstDetector.OnBurst += (burst) =>
            {
                try { _ui.DrawBurstAlert(burst); }
                catch { }
                // Burst = mass file activity — notify network monitor for exfil correlation
                try { _networkMonitor.NotifyFileActivity(); } catch { }
            };

            // 4. Start console UI — draw live status board
            try
            {
                _ui.DrawStatusBoard(_deployedTokens);
            }
            catch { /* non-fatal — terminal may not support all cursor operations */ }

            // 5. Wait for Ctrl+C
            try
            {
                while (!ct.IsCancellationRequested)
                {
                    try { _ui.RefreshBoard(_deployedTokens, _alertManager.TotalAlerts); }
                    catch { /* non-fatal board refresh error */ }
                    Thread.Sleep(500);
                }
            }
            finally
            {
                // 6. Cleanup tokens — always runs, even if the loop throws
                try
                {
                    _ui.Status("\nShutting down — removing honeytokens...");
                    _watcherManager.StopAll();
                    _vssWatcher.Stop();
                    _etwMonitor.Stop();
                    _cryptoMonitor.Stop();
                    _procScorer.Stop();
                    _networkMonitor.Stop();
                    _signalFusion.Dispose();
                    _planter.RemoveAll(_deployedTokens);
                    _ui.Status("Cleanup complete. Exiting.");
                }
                catch (Exception ex)
                {
                    _ui.Warn($"Cleanup error: {ex.Message}");
                }
            }
        }
    }
}
