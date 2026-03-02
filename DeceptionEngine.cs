using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using HoneytokenWatcher.Honeytokens;
using HoneytokenWatcher.Watchers;
using HoneytokenWatcher.Alerting;
using HoneytokenWatcher.UI;

namespace HoneytokenWatcher.Core
{
    public class DeceptionEngine
    {
        private readonly HoneytokenPlanter _planter;
        private readonly WatcherManager _watcherManager;
        private readonly AlertManager _alertManager;
        private readonly ConsoleUI _ui;
        private readonly List<HoneytokenFile> _deployedTokens = new();

        public DeceptionEngine()
        {
            _alertManager = new AlertManager("rdrs_alerts.json");
            _planter = new HoneytokenPlanter();
            _watcherManager = new WatcherManager(_alertManager);
            _ui = new ConsoleUI();
        }

        public void Run(CancellationToken ct)
        {
            _ui.DrawBanner();

            // 1. Plant honeytokens
            _ui.Status($"Alert log → {Path.GetFullPath("rdrs_alerts.json")}");
            _ui.Status("Planting honeytokens...");
            _deployedTokens.AddRange(_planter.PlantAll());
            _ui.Status($"Planted {_deployedTokens.Count} honeytokens across monitored directories.");

            // 2. Start watchers
            _ui.Status("Starting FileSystemWatchers...");
            _watcherManager.StartWatching(_deployedTokens);
            _ui.Status("All watchers active. Deception layer is live.\n");

            // 3. Register alert callback for UI
            _alertManager.OnAlert += (alert) =>
            {
                _ui.DrawAlert(alert);
            };

            // 4. Draw live status board
            _ui.DrawStatusBoard(_deployedTokens);

            // 5. Block until Ctrl+C
            while (!ct.IsCancellationRequested)
            {
                _ui.RefreshBoard(_deployedTokens, _alertManager.TotalAlerts);
                Thread.Sleep(500);
            }

            // 6. Cleanup on exit
            _ui.Status("\nShutting down — removing honeytokens...");
            _watcherManager.StopAll();
            _planter.RemoveAll(_deployedTokens);
            _ui.Status("Cleanup complete. Exiting.");
        }
    }
}
