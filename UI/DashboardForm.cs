using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.IO;
using System.Linq;
using System.Windows.Forms;
using HoneytokenWatcher.Containment;
using HoneytokenWatcher.Core;

namespace HoneytokenWatcher.UI
{
    /// <summary>
    /// Live WinForms dashboard — shows alert feed, event-type bar chart,
    /// severity breakdown and last containment action.  Auto-refreshes every 2s.
    /// Hides (rather than closes) when the user clicks X so the tray keeps running.
    /// </summary>
    public class DashboardForm : Form
    {
        private readonly DeceptionEngine              _engine;
        private readonly System.Windows.Forms.Timer  _refreshTimer;

        // ── UI elements ───────────────────────────────────────────────────────
        private readonly Label        _statusLabel;
        private readonly DataGridView _grid;
        private readonly Panel        _chartPanel;
        private readonly Label        _statsText;

        // ── Local chart state (updated on UI thread) ──────────────────────────
        private readonly Dictionary<string, int> _eventCounts = new();
        private int _lastTotalAlerts = -1;

        // ── Constructor ───────────────────────────────────────────────────────

        public DashboardForm(DeceptionEngine engine)
        {
            _engine = engine;

            // Form
            Text          = "RDRS — Ransomware Detection & Response Service";
            Size          = new Size(1120, 700);
            MinimumSize   = new Size(900, 560);
            BackColor     = Color.FromArgb(18, 18, 30);
            ForeColor     = Color.White;
            StartPosition = FormStartPosition.CenterScreen;
            Font          = new Font("Segoe UI", 9f);
            try { Icon = ShieldIcon.CreateAppIcon(); } catch { }

            // ── Status bar (top 40 px) ─────────────────────────────────────────
            var statusBar = new Panel
            {
                Dock = DockStyle.Top, Height = 40,
                BackColor = Color.FromArgb(26, 26, 44),
                Padding   = new Padding(0),
            };
            _statusLabel = new Label
            {
                Dock      = DockStyle.Fill,
                TextAlign = ContentAlignment.MiddleLeft,
                Padding   = new Padding(14, 0, 0, 0),
                ForeColor = Color.FromArgb(80, 220, 80),
                Font      = new Font("Segoe UI", 10f, FontStyle.Bold),
            };
            statusBar.Controls.Add(_statusLabel);

            // ── Toolbar (bottom 46 px) ─────────────────────────────────────────
            var toolbar = new Panel
            {
                Dock = DockStyle.Bottom, Height = 46,
                BackColor = Color.FromArgb(26, 26, 44),
                Padding   = new Padding(8, 7, 8, 7),
            };
            var flow = new FlowLayoutPanel
            {
                Dock = DockStyle.Fill, FlowDirection = FlowDirection.LeftToRight,
                WrapContents = false,
            };
            flow.Controls.Add(Btn("⏸  Pause 30s",    (_, _) => { _engine.Pause(30);  RefreshStatusBar(); }));
            flow.Controls.Add(Btn("▶  Resume",        (_, _) => { _engine.Resume();   RefreshStatusBar(); }));
            flow.Controls.Add(Btn("⌫  Clear View",    OnClearView));
            flow.Controls.Add(Btn("📄  Open Log File", (_, _) => OpenLog()));
            var closeBtn = Btn("✕  Close", (_, _) => Hide());
            closeBtn.BackColor = Color.FromArgb(100, 28, 28);
            flow.Controls.Add(closeBtn);
            toolbar.Controls.Add(flow);

            // ── Main splitter ──────────────────────────────────────────────────
            // Panel1MinSize / Panel2MinSize must NOT be set while the SplitContainer
            // has no real width (object-initializer time) — doing so calls
            // ApplyPanel2MinSize → set_SplitterDistance on a zero-width control
            // and throws InvalidOperationException.  Defer everything to Shown.
            var split = new SplitContainer
            {
                Dock      = DockStyle.Fill,
                BackColor = Color.FromArgb(18, 18, 30),
            };
            Shown += (_, _) =>
            {
                try
                {
                    split.Panel1MinSize    = 300;
                    split.Panel2MinSize    = 260;
                    split.SplitterDistance = (int)(split.Width * 0.57);
                }
                catch { /* ignore if form is too narrow */ }
            };

            // LEFT — live alert feed
            _grid = BuildGrid();
            var leftTitle = PanelTitle("  ⬡  LIVE ALERT FEED  —  last 50");
            split.Panel1.Controls.Add(_grid);       // Fill  (add first → processed last)
            split.Panel1.Controls.Add(leftTitle);   // Top   (add last  → processed first)

            // RIGHT — stats
            _chartPanel = new Panel
            {
                Dock = DockStyle.Top, Height = 198,
                BackColor = Color.FromArgb(22, 22, 38),
            };
            _chartPanel.Paint += OnChartPaint;

            _statsText = new Label
            {
                Dock      = DockStyle.Fill,
                ForeColor = Color.FromArgb(185, 185, 215),
                Font      = new Font("Consolas", 8.8f),
                TextAlign = ContentAlignment.TopLeft,
                Padding   = new Padding(12, 10, 8, 0),
            };

            var statsContent = new Panel { Dock = DockStyle.Fill, BackColor = Color.FromArgb(22, 22, 38) };
            statsContent.Controls.Add(_statsText);   // Fill  (first)
            statsContent.Controls.Add(_chartPanel);  // Top   (last)

            var rightTitle = PanelTitle("  ◈  DETECTION STATS");
            split.Panel2.Controls.Add(statsContent); // Fill  (first)
            split.Panel2.Controls.Add(rightTitle);   // Top   (last)

            // ── Assemble (order = last added → positioned first) ───────────────
            Controls.Add(split);      // Fill   (first → processed last)
            Controls.Add(toolbar);    // Bottom (second)
            Controls.Add(statusBar);  // Top    (last  → processed first)

            // ── Refresh timer ─────────────────────────────────────────────────
            _refreshTimer = new System.Windows.Forms.Timer { Interval = 2000 };
            _refreshTimer.Tick += (_, _) => RefreshAll();
            _refreshTimer.Start();

            RefreshAll();
        }

        // ── Grid builder ──────────────────────────────────────────────────────

        private static DataGridView BuildGrid()
        {
            var g = new DataGridView
            {
                Dock                  = DockStyle.Fill,
                BackgroundColor       = Color.FromArgb(22, 22, 38),
                GridColor             = Color.FromArgb(42, 42, 62),
                BorderStyle           = BorderStyle.None,
                RowHeadersVisible     = false,
                AllowUserToAddRows    = false,
                AllowUserToDeleteRows = false,
                ReadOnly              = true,
                SelectionMode         = DataGridViewSelectionMode.FullRowSelect,
                AutoSizeColumnsMode   = DataGridViewAutoSizeColumnsMode.Fill,
                ColumnHeadersHeight   = 28,
                RowTemplate           = { Height = 22 },
                EnableHeadersVisualStyles   = false,
                ColumnHeadersBorderStyle    = DataGridViewHeaderBorderStyle.Single,
            };

            var cellStyle = new DataGridViewCellStyle
            {
                BackColor          = Color.FromArgb(28, 28, 46),
                ForeColor          = Color.FromArgb(205, 205, 230),
                SelectionBackColor = Color.FromArgb(55, 55, 95),
                SelectionForeColor = Color.White,
                Font               = new Font("Consolas", 8.5f),
            };
            var hdrStyle = new DataGridViewCellStyle
            {
                BackColor          = Color.FromArgb(32, 32, 54),
                ForeColor          = Color.FromArgb(135, 170, 255),
                SelectionBackColor = Color.FromArgb(32, 32, 54),
                Font               = new Font("Segoe UI", 8.5f, FontStyle.Bold),
            };
            g.DefaultCellStyle            = cellStyle;
            g.ColumnHeadersDefaultCellStyle = hdrStyle;

            g.Columns.Add(new DataGridViewTextBoxColumn { Name = "time",    HeaderText = "Time",    FillWeight = 13 });
            g.Columns.Add(new DataGridViewTextBoxColumn { Name = "token",   HeaderText = "Token",   FillWeight = 25 });
            g.Columns.Add(new DataGridViewTextBoxColumn { Name = "event",   HeaderText = "Event",   FillWeight = 14 });
            g.Columns.Add(new DataGridViewTextBoxColumn { Name = "risk",    HeaderText = "Risk",    FillWeight = 11 });
            g.Columns.Add(new DataGridViewTextBoxColumn { Name = "score",   HeaderText = "Score",   FillWeight = 10 });
            g.Columns.Add(new DataGridViewTextBoxColumn { Name = "process", HeaderText = "Process", FillWeight = 27 });
            return g;
        }

        // ── Refresh pipeline ──────────────────────────────────────────────────

        private void RefreshAll()
        {
            if (!IsHandleCreated || IsDisposed) return;
            if (InvokeRequired) { BeginInvoke(new Action(RefreshAll)); return; }

            RefreshStatusBar();
            RefreshGrid();
            RefreshStats();
        }

        private void RefreshStatusBar()
        {
            var uptime = _engine.StartedAt == default
                ? TimeSpan.Zero
                : DateTime.Now - _engine.StartedAt;

            if (_engine.IsPaused)
            {
                _statusLabel.Text     = $"  ⏸  PAUSED  |  {_engine.TokenCount} honeytokens  |  {_engine.TotalAlerts} alerts total  |  Uptime {uptime:hh\\:mm\\:ss}";
                _statusLabel.ForeColor = Color.Orange;
            }
            else
            {
                _statusLabel.Text     = $"  ●  PROTECTED  |  {_engine.TokenCount} honeytokens watching  |  {_engine.TotalAlerts} alerts total  |  Uptime {uptime:hh\\:mm\\:ss}";
                _statusLabel.ForeColor = Color.FromArgb(80, 225, 80);
            }
        }

        private void RefreshGrid()
        {
            // Only repopulate when new alerts have arrived
            if (_engine.TotalAlerts == _lastTotalAlerts) return;
            _lastTotalAlerts = _engine.TotalAlerts;

            var alerts = _engine.GetRecentAlerts(50);

            _grid.SuspendLayout();
            _grid.Rows.Clear();
            _eventCounts.Clear();

            foreach (var a in alerts)
            {
                var name = a.TokenFileName ?? "";
                if (name.Length > 24) name = name[..21] + "…";

                _grid.Rows.Add(
                    a.Timestamp.ToString("HH:mm:ss"),
                    name,
                    a.EventType,
                    a.RiskLabel,
                    $"{a.RiskScore}/100",
                    $"{a.ProcessName} ({a.ProcessId})");

                // Row colouring by risk level
                var row = _grid.Rows[_grid.RowCount - 1];
                (row.DefaultCellStyle.BackColor, row.DefaultCellStyle.ForeColor) =
                    a.RiskLabel switch
                    {
                        "CRITICAL" => (Color.FromArgb(82, 22, 22),  Color.FromArgb(255, 110, 110)),
                        "HIGH"     => (Color.FromArgb(72, 42, 14),  Color.FromArgb(255, 170, 60)),
                        "MEDIUM"   => (Color.FromArgb(62, 58, 14),  Color.FromArgb(235, 215, 60)),
                        _          => (Color.FromArgb(28, 28, 46),  Color.FromArgb(200, 200, 225)),
                    };

                // Accumulate event-type counts for the chart
                var et = a.EventType ?? "Unknown";
                _eventCounts[et] = _eventCounts.GetValueOrDefault(et, 0) + 1;
            }

            if (_grid.RowCount > 0)
                _grid.FirstDisplayedScrollingRowIndex = _grid.RowCount - 1;

            _grid.ResumeLayout();
            _chartPanel.Invalidate();   // redraw bar chart
        }

        private void RefreshStats()
        {
            var alerts = _engine.GetRecentAlerts(200);
            int critical = alerts.Count(a => a.RiskLabel == "CRITICAL");
            int high     = alerts.Count(a => a.RiskLabel == "HIGH");
            int medium   = alerts.Count(a => a.RiskLabel == "MEDIUM");

            var last = _engine.LastContainment;

            var sb = new System.Text.StringBuilder();
            sb.AppendLine("ALERTS BY SEVERITY:");
            sb.AppendLine($"  CRITICAL  :  {critical}");
            sb.AppendLine($"  HIGH      :  {high}");
            sb.AppendLine($"  MEDIUM    :  {medium}");
            sb.AppendLine($"  TOTAL     :  {alerts.Count}");
            sb.AppendLine();
            sb.AppendLine("LAST CONTAINMENT:");

            if (last != null && last.Action != ContainmentAction.None)
            {
                sb.AppendLine($"  Action    :  {last.Action}");
                sb.AppendLine($"  Process   :  {last.ProcessName} (PID {last.ProcessId})");
                sb.AppendLine($"  Time      :  {last.Timestamp:HH:mm:ss}");
                sb.AppendLine($"  Path      :  {(last.PathBlocked ? "BLOCKED ✓" : "not blocked")}");
                sb.AppendLine($"  Summary   :  {last.Summary}");
            }
            else
            {
                sb.AppendLine("  No containment actions yet.");
            }

            _statsText.Text = sb.ToString();
        }

        // ── Bar chart (GDI+) ─────────────────────────────────────────────────

        private void OnChartPaint(object? sender, PaintEventArgs e)
        {
            var g = e.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;
            var b = _chartPanel.ClientRectangle;
            g.Clear(Color.FromArgb(22, 22, 38));

            using var titleFont  = new Font("Segoe UI", 8.5f, FontStyle.Bold);
            using var titleBrush = new SolidBrush(Color.FromArgb(135, 170, 255));
            g.DrawString("EVENT TYPE BREAKDOWN", titleFont, titleBrush, 10, 8);

            if (_eventCounts.Count == 0)
            {
                using var dimBrush = new SolidBrush(Color.FromArgb(85, 85, 115));
                g.DrawString("No alerts yet — waiting for events…",
                    new Font("Segoe UI", 9f), dimBrush, 10, 38);
                return;
            }

            int maxVal    = _eventCounts.Values.Max();
            int barLeft   = 94;
            int barRight  = b.Width - 42;
            int barWidth  = barRight - barLeft;
            int y         = 32;
            const int barH = 22, gap = 6;

            var palette = new Dictionary<string, Color>(StringComparer.OrdinalIgnoreCase)
            {
                ["Renamed"]     = Color.FromArgb(220, 60,  60),
                ["Changed"]     = Color.FromArgb(220, 140, 40),
                ["Deleted"]     = Color.FromArgb(170, 55, 200),
                ["Created"]     = Color.FromArgb(55,  155, 220),
                ["VssDeletion"] = Color.FromArgb(200, 45,  45),
            };

            using var labelFont  = new Font("Consolas", 8f);
            using var labelBrush = new SolidBrush(Color.FromArgb(165, 165, 195));
            using var countBrush = new SolidBrush(Color.White);
            using var bgBrush    = new SolidBrush(Color.FromArgb(32, 32, 52));

            foreach (var kv in _eventCounts.OrderByDescending(x => x.Value))
            {
                if (y + barH > b.Height - 6) break;

                var label = (kv.Key.Length > 11 ? kv.Key[..11] : kv.Key).PadRight(11);
                g.DrawString(label, labelFont, labelBrush, 4, y + 3);

                // Empty background track
                g.FillRectangle(bgBrush, barLeft, y, barWidth, barH);

                // Filled bar with gradient
                int fill = maxVal > 0 ? (int)((double)kv.Value / maxVal * barWidth) : 0;
                fill = Math.Max(fill, 5);
                var baseColor = palette.TryGetValue(kv.Key, out var c) ? c : Color.FromArgb(95, 140, 220);
                var darkColor = Color.FromArgb(baseColor.R / 2, baseColor.G / 2, baseColor.B / 2);

                using var grad = new LinearGradientBrush(
                    new Rectangle(barLeft, y, fill, barH),
                    baseColor, darkColor, LinearGradientMode.Horizontal);
                g.FillRectangle(grad, barLeft, y, fill, barH);

                g.DrawString(kv.Value.ToString(), labelFont, countBrush,
                    barLeft + fill + 5, y + 3);

                y += barH + gap;
            }
        }

        // ── Button handlers ───────────────────────────────────────────────────

        private void OnClearView(object? sender, EventArgs e)
        {
            _grid.Rows.Clear();
            _eventCounts.Clear();
            _lastTotalAlerts = -1;   // force repopulate on next tick
            _statsText.Text  = "";
            _chartPanel.Invalidate();
        }

        private static void OpenLog()
        {
            var path = Path.GetFullPath("rdrs_alerts.json");
            if (!File.Exists(path))
            {
                MessageBox.Show("No alert log found yet.", "RDRS",
                    MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            try
            {
                System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
                {
                    FileName = "notepad.exe", Arguments = $"\"{path}\"",
                    UseShellExecute = true,
                });
            }
            catch { }
        }

        // ── Helpers ───────────────────────────────────────────────────────────

        private static Label PanelTitle(string text) => new Label
        {
            Text      = text,
            Dock      = DockStyle.Top,
            Height    = 28,
            ForeColor = Color.FromArgb(135, 170, 255),
            BackColor = Color.FromArgb(22, 22, 40),
            Font      = new Font("Segoe UI", 9f, FontStyle.Bold),
            TextAlign = ContentAlignment.MiddleLeft,
            Padding   = new Padding(5, 0, 0, 0),
        };

        private static Button Btn(string text, EventHandler onClick)
        {
            var b = new Button
            {
                Text      = text,
                Height    = 30,
                AutoSize  = true,
                Padding   = new Padding(10, 0, 10, 0),
                Margin    = new Padding(4, 0, 4, 0),
                BackColor = Color.FromArgb(38, 38, 62),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Cursor    = Cursors.Hand,
                Font      = new Font("Segoe UI", 8.5f),
            };
            b.FlatAppearance.BorderColor = Color.FromArgb(68, 68, 108);
            b.Click += onClick;
            return b;
        }

        // ── Close → hide so tray keeps running ────────────────────────────────

        protected override void OnFormClosing(FormClosingEventArgs e)
        {
            if (e.CloseReason == CloseReason.UserClosing)
            {
                e.Cancel = true;
                Hide();
                return;
            }
            base.OnFormClosing(e);
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing) _refreshTimer?.Dispose();
            base.Dispose(disposing);
        }
    }
}
