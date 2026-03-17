using System;
using System.Diagnostics;
using System.IO;
using System.Threading;
using System.Windows.Forms;
using HoneytokenWatcher.Alerting;
using HoneytokenWatcher.Config;
using HoneytokenWatcher.Core;
using Microsoft.Win32;

namespace HoneytokenWatcher.UI
{
    /// <summary>
    /// Windows tray application context.  Runs the DeceptionEngine on a background
    /// thread and surfaces notifications, status, and control via a NotifyIcon.
    /// </summary>
    public class TrayApplication : ApplicationContext
    {
        private readonly RdrsConfig                    _config;
        private readonly DeceptionEngine               _engine;
        private readonly NotifyIcon                    _trayIcon;
        private readonly ToolStripMenuItem             _statusItem;
        private readonly ToolStripMenuItem             _pauseItem;
        private readonly System.Windows.Forms.Timer   _statusTimer;
        private readonly CancellationTokenSource       _cts = new();
        private          DashboardForm?                _dashboard;

        // ── Constructor ───────────────────────────────────────────────────────

        public TrayApplication(RdrsConfig config)
        {
            _config = config;
            _engine = new DeceptionEngine(config);

            // ── Context menu ─────────────────────────────────────────────────
            _statusItem = new ToolStripMenuItem("RDRS Starting…") { Enabled = false };
            _pauseItem  = new ToolStripMenuItem("Pause Protection (30s)", null, OnPauseToggle);

            var menu = new ContextMenuStrip();
            menu.Items.Add(_statusItem);
            menu.Items.Add(new ToolStripSeparator());
            menu.Items.Add("Open Dashboard",   null, OnShowDashboard);
            menu.Items.Add("View Last Alert",  null, OnViewLastAlert);
            menu.Items.Add("Open Alert Log",   null, OnOpenAlertLog);
            menu.Items.Add(_pauseItem);
            menu.Items.Add(new ToolStripSeparator());
            menu.Items.Add("Exit", null, OnExit);

            // ── Tray icon ─────────────────────────────────────────────────────
            _trayIcon = new NotifyIcon
            {
                Icon             = ShieldIcon.Create(),
                Text             = "RDRS — Ransomware Detection",
                ContextMenuStrip = menu,
                Visible          = true,
            };
            // Double-click tray icon → show/raise dashboard
            _trayIcon.DoubleClick += OnShowDashboard;

            // ── Status refresh (fires on UI thread via WinForms message loop) ─
            _statusTimer = new System.Windows.Forms.Timer { Interval = 2000 };
            _statusTimer.Tick += (_, _) => UpdateStatus();
            _statusTimer.Start();

            // ── Register autostart + desktop shortcut (first-run / normal launch) ─
            var cmdArgs = Environment.GetCommandLineArgs();
            if (!Array.Exists(cmdArgs, a =>
                    a.Equals("--startup", StringComparison.OrdinalIgnoreCase)))
            {
                RegisterAutostart();
                CreateDesktopShortcut();
            }

            // ── Subscribe to alert events (fires on thread-pool thread) ───────
            _engine.OnAlert += OnEngineAlert;

            // ── Start engine on a dedicated background thread ─────────────────
            var engineThread = new Thread(() =>
            {
                try { _engine.Run(_cts.Token); }
                catch { /* fatal engine error — tray icon stays visible */ }
            })
            {
                IsBackground = true,
                Name         = "RDRS-Engine",
            };
            engineThread.Start();
        }

        // ── Alert notification ────────────────────────────────────────────────

        private void OnEngineAlert(HoneytokenAlert alert)
        {
            // OnAlert fires from a thread-pool callback.
            // NotifyIcon.ShowBalloonTip is safe to call from any thread because
            // it goes through Shell_NotifyIcon (Win32), not a WndProc marshal.
            bool shouldNotify = _config.NotificationLevel switch
            {
                NotificationLevel.Critical => alert.RiskLabel == "CRITICAL",
                NotificationLevel.High     => alert.RiskLabel is "CRITICAL" or "HIGH",
                _                          => true,
            };

            if (shouldNotify && alert.RiskScore >= 70)
            {
                _trayIcon.BalloonTipTitle = "⚠ RDRS: Ransomware detected";
                _trayIcon.BalloonTipText  =
                    $"{alert.ProcessName} contained — {alert.RiskLabel} (Score: {alert.RiskScore}/100)";
                _trayIcon.BalloonTipIcon  = ToolTipIcon.Warning;
                _trayIcon.ShowBalloonTip(5000);
            }
        }

        // ── Periodic status update (UI thread) ────────────────────────────────

        private void UpdateStatus()
        {
            if (_engine.IsPaused)
            {
                _statusItem.Text  = "RDRS Paused — resuming soon";
                _trayIcon.Text    = "RDRS — Paused";
                _pauseItem.Text   = "Resume Protection";
            }
            else
            {
                var n = _engine.TokenCount;
                _statusItem.Text  = $"RDRS Active — {n} honeytokens watching";
                _trayIcon.Text    = $"RDRS — {n} tokens watching";
                _pauseItem.Text   = "Pause Protection (30s)";
            }
        }

        // ── Menu handlers (all on UI thread) ─────────────────────────────────

        private void OnViewLastAlert(object? sender, EventArgs e)
        {
            var last = _engine.LastAlert;
            if (last == null)
            {
                MessageBox.Show(
                    "No alerts recorded yet.",
                    "RDRS",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Information);
                return;
            }

            MessageBox.Show(
                $"Alert ID  : {last.AlertId}\n" +
                $"Time      : {last.Timestamp:yyyy-MM-dd HH:mm:ss}\n" +
                $"Event     : {last.EventType}\n" +
                $"Token     : {last.TokenFileName}\n" +
                $"Directory : {last.TokenDirectory}\n" +
                $"Process   : {last.ProcessName} (PID: {last.ProcessId})\n" +
                $"Risk      : {last.RiskLabel} ({last.RiskScore}/100)\n" +
                $"Indicators: {string.Join(", ", last.Indicators)}",
                "RDRS — Last Alert",
                MessageBoxButtons.OK,
                MessageBoxIcon.Warning);
        }

        private void OnOpenAlertLog(object? sender, EventArgs e)
        {
            var logPath = Path.GetFullPath("rdrs_alerts.json");
            if (!File.Exists(logPath))
            {
                MessageBox.Show(
                    "No alert log found yet.",
                    "RDRS",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Information);
                return;
            }

            try
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName        = "notepad.exe",
                    Arguments       = $"\"{logPath}\"",
                    UseShellExecute = true,
                });
            }
            catch (Exception ex)
            {
                MessageBox.Show(
                    $"Could not open log: {ex.Message}",
                    "RDRS",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Error);
            }
        }

        private void OnPauseToggle(object? sender, EventArgs e)
        {
            if (_engine.IsPaused)
                _engine.Resume();
            else
                _engine.Pause(30);

            UpdateStatus();
        }

        private void OnShowDashboard(object? sender, EventArgs e)
        {
            if (_dashboard == null || _dashboard.IsDisposed)
                _dashboard = new DashboardForm(_engine);

            if (!_dashboard.Visible)
                _dashboard.Show();

            _dashboard.BringToFront();
            _dashboard.Activate();
        }

        private void OnExit(object? sender, EventArgs e)
        {
            _statusTimer.Stop();
            _trayIcon.Visible = false;
            try { _dashboard?.Dispose(); } catch { }
            _cts.Cancel();

            // Give the engine thread a moment to clean up honeytokens
            Thread.Sleep(1500);
            ExitThread();
        }

        // ── Desktop shortcut ─────────────────────────────────────────────────

        private static void CreateDesktopShortcut()
        {
            try
            {
                var exePath = Process.GetCurrentProcess().MainModule?.FileName
                    ?? System.Reflection.Assembly.GetExecutingAssembly().Location;

                var desktop = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
                var lnkPath = Path.Combine(desktop, "RDRS.lnk");

                // Save the RDRS icon as a proper .ico so the shortcut uses it
                var iconDir = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "RDRS");
                Directory.CreateDirectory(iconDir);
                var icoPath = Path.Combine(iconDir, "rdrs.ico");
                ShieldIcon.SaveIco(icoPath, 48);

                // Use WScript.Shell COM to write the .lnk file (no extra packages needed)
                var shellType = Type.GetTypeFromProgID("WScript.Shell");
                if (shellType == null) return;
                dynamic shell    = Activator.CreateInstance(shellType)!;
                dynamic shortcut = shell.CreateShortcut(lnkPath);
                shortcut.TargetPath       = exePath;
                shortcut.WorkingDirectory = Path.GetDirectoryName(exePath) ?? "";
                shortcut.Description      = "RDRS — Ransomware Detection & Response Service";
                shortcut.IconLocation     = $"{icoPath},0";
                shortcut.Save();
            }
            catch { /* non-fatal */ }
        }

        // ── Auto-start registry ───────────────────────────────────────────────

        private static void RegisterAutostart()
        {
            try
            {
                var exePath = Process.GetCurrentProcess().MainModule?.FileName
                    ?? System.Reflection.Assembly.GetExecutingAssembly().Location;

                using var key = Registry.CurrentUser.OpenSubKey(
                    @"Software\Microsoft\Windows\CurrentVersion\Run",
                    writable: true);

                key?.SetValue("RDRS", $"\"{exePath}\" --startup");
            }
            catch { /* non-fatal — user can add manually */ }
        }

        // ── Dispose ───────────────────────────────────────────────────────────

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _statusTimer?.Dispose();
                _trayIcon?.Dispose();
                _dashboard?.Dispose();
                _cts?.Dispose();
            }
            base.Dispose(disposing);
        }
    }
}
