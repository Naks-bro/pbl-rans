using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.IO;
using System.Linq;
using System.Windows.Forms;
using HoneytokenWatcher.Alerting;
using HoneytokenWatcher.Containment;
using HoneytokenWatcher.Core;

// ─────────────────────────────────────────────────────────────────────────────
//  RDRS — Professional EDR Dashboard
//
//  Layout (top → bottom, left → right):
//    [STATUS BAR — full width, 56 px]
//    [ALERT FEED  |  TOP PROCESSES  ]  splitMain / splitTop
//    [PROCESS DETAILS | THREAT GRAPH]  splitMain / splitMiddle
//    [HONEYTOKENS | NETWORK | CONTAIN]  splitMain / splitBottom
//    [TOOLBAR — full width, 48 px]
//
//  Update strategy:
//    • _refreshTimer fires every 2 s on UI thread (RefreshAll)
//    • OnAlert / OnFusedThreat events captured on thread-pool,
//      marshalled via BeginInvoke — update in-memory state then
//      let next timer tick paint the result (no per-alert layout thrash)
//    • GDI+ panels use double-buffering + Invalidate() only when needed
// ─────────────────────────────────────────────────────────────────────────────

namespace HoneytokenWatcher.UI
{
    public sealed class DashboardForm : Form
    {
        // ── back-end reference ────────────────────────────────────────────────
        private readonly DeceptionEngine _engine;
        private readonly System.Windows.Forms.Timer _refreshTimer;

        // ── color palette ─────────────────────────────────────────────────────
        // Consistent dark-navy theme throughout; accent colors follow severity.
        private static readonly Color C_BgDeep    = Color.FromArgb(10,  14,  20);   // outer form
        private static readonly Color C_BgPanel   = Color.FromArgb(16,  21,  30);   // panel bg
        private static readonly Color C_BgHeader  = Color.FromArgb(22,  29,  40);   // section headers
        private static readonly Color C_BgCell    = Color.FromArgb(20,  26,  36);   // grid cells
        private static readonly Color C_BgHover   = Color.FromArgb(30,  38,  54);   // selected row
        private static readonly Color C_Border    = Color.FromArgb(40,  52,  70);   // borders / grid lines
        private static readonly Color C_TextHi    = Color.FromArgb(220, 232, 248);  // primary text
        private static readonly Color C_TextLo    = Color.FromArgb(110, 125, 148);  // secondary / dim
        private static readonly Color C_Accent    = Color.FromArgb(80,  160, 255);  // blue accent / headers
        private static readonly Color C_Green     = Color.FromArgb(56,  185, 90);   // safe / protected
        private static readonly Color C_Yellow    = Color.FromArgb(215, 160, 30);   // medium / warning
        private static readonly Color C_Orange    = Color.FromArgb(255, 140, 30);   // high
        private static readonly Color C_Red       = Color.FromArgb(230, 60,  60);   // critical
        private static readonly Color C_Purple    = Color.FromArgb(150, 100, 240);  // contained

        // ── status-bar labels ─────────────────────────────────────────────────
        private Label _lblProtection   = null!;
        private Label _lblThreatLevel  = null!;
        private Label _lblMonitors     = null!;
        private Label _lblProcessCount = null!;
        private Label _lblLastAlert    = null!;
        private Label _lblUptime       = null!;   // direct ref — avoids Controls.Find()

        // ── alert feed ────────────────────────────────────────────────────────
        private DataGridView _alertGrid = null!;
        private int _lastAlertCount = -1;

        // ── top suspicious processes ──────────────────────────────────────────
        private DataGridView _processGrid = null!;

        // ── process details panel ─────────────────────────────────────────────
        private Label _lblProcName    = null!;
        private Label _lblProcPid     = null!;
        private Label _lblProcPath    = null!;
        private Label _lblProcParent  = null!;
        private Label _lblProcSigned  = null!;
        private Label _lblProcScore   = null!;
        private ProgressBar _pbScore  = null!;
        private ListBox _lbSignals    = null!;

        // ── threat-score graph (GDI+) ─────────────────────────────────────────
        // Keyed by PID; each queue holds (timestamp, score) pairs for the last 5 min
        private readonly Dictionary<int, Queue<(DateTime t, int score)>> _scoreHistory = new();
        private readonly Dictionary<int, string> _pidNames = new();          // pid → display name
        private Panel _graphPanel = null!;

        // ── attack timeline ───────────────────────────────────────────────────
        private ListBox _lbTimeline = null!;
        // Ring-buffer of the 60 most recent timeline events
        private readonly List<(DateTime t, string msg, Color clr)> _timeline = new();

        // ── honeytoken status ─────────────────────────────────────────────────
        private DataGridView _tokenGrid = null!;

        // ── network activity ──────────────────────────────────────────────────
        private ListBox _lbNetwork = null!;
        private readonly List<(DateTime t, string proc, string tag, string detail)> _netEvents = new();

        // ── containment summary ───────────────────────────────────────────────
        private Label _lblLastContain  = null!;
        private Label _lblContainCount = null!;
        private ListBox _lbContainLog  = null!;
        private readonly List<string> _containLog = new();

        // ── signal breakdown paint panel ──────────────────────────────────────
        private Panel _sigBreakPanel = null!;
        // Accumulated per-source contribution from the last N fused threats
        private readonly Dictionary<string, double> _sigBreakdown = new()
        {
            ["Honeytoken"] = 0, ["CryptoApi"] = 0, ["ETW"] = 0,
            ["Network"] = 0, ["Behavioral"] = 0,
        };

        // ── selected process for detail panel ─────────────────────────────────
        private int _selectedPid = -1;

        // ─────────────────────────────────────────────────────────────────────
        //  Constructor
        // ─────────────────────────────────────────────────────────────────────

        public DashboardForm(DeceptionEngine engine)
        {
            _engine = engine;

            // Form properties
            Text          = "RDRS  ·  Ransomware Detection & Response Service";
            Size          = new Size(1440, 900);
            MinimumSize   = new Size(1100, 700);
            BackColor     = C_BgDeep;
            ForeColor     = C_TextHi;
            StartPosition = FormStartPosition.CenterScreen;
            Font          = new Font("Segoe UI", 9f);
            DoubleBuffered = true;
            try { Icon = ShieldIcon.CreateAppIcon(); } catch { }

            // Wire backend events — captured on thread-pool, marshalled to UI
            _engine.OnAlert += alert =>
            {
                if (!IsHandleCreated || IsDisposed) return;
                BeginInvoke(() => OnAlertReceived(alert));
            };
            _engine.OnFusedThreat += threat =>
            {
                if (!IsHandleCreated || IsDisposed) return;
                BeginInvoke(() => OnFusedThreatReceived(threat));
            };

            BuildUI();

            _refreshTimer = new System.Windows.Forms.Timer { Interval = 2000 };
            _refreshTimer.Tick += (_, _) => RefreshAll();
            _refreshTimer.Start();

            Shown += (_, _) => RefreshAll();
        }

        // ─────────────────────────────────────────────────────────────────────
        //  UI Construction
        // ─────────────────────────────────────────────────────────────────────

        private void BuildUI()
        {
            var statusBar = BuildStatusBar();   // anchors Top
            var toolbar   = BuildToolbar();     // anchors Bottom

            // ── outer vertical splitter (top area | bottom strip) ─────────────
            var splitOuter = new SplitContainer
            {
                Dock        = DockStyle.Fill,
                Orientation = Orientation.Horizontal,
                BackColor   = C_Border,
            };
            splitOuter.Panel1.BackColor = C_BgPanel;
            splitOuter.Panel2.BackColor = C_BgPanel;

            // ── top area: left (alerts) | right (processes + details) ─────────
            var splitTop = new SplitContainer
            {
                Dock        = DockStyle.Fill,
                Orientation = Orientation.Vertical,
                BackColor   = C_Border,
            };
            splitTop.Panel1.BackColor = C_BgPanel;
            splitTop.Panel2.BackColor = C_BgPanel;

            // LEFT: Alert Feed
            splitTop.Panel1.Controls.Add(BuildAlertFeed());
            splitTop.Panel1.Controls.Add(SectionTitle("  ⬡  LIVE ALERT FEED", true));

            // RIGHT: Top split — processes (top) | process details (bottom)
            var splitRight = new SplitContainer
            {
                Dock        = DockStyle.Fill,
                Orientation = Orientation.Horizontal,
                BackColor   = C_Border,
            };
            splitRight.Panel1.BackColor = C_BgPanel;
            splitRight.Panel2.BackColor = C_BgPanel;

            splitRight.Panel1.Controls.Add(BuildTopProcesses());
            splitRight.Panel1.Controls.Add(SectionTitle("  ◈  TOP SUSPICIOUS PROCESSES", false));
            splitRight.Panel2.Controls.Add(BuildProcessDetails());
            splitRight.Panel2.Controls.Add(SectionTitle("  ⬟  PROCESS DETAILS & SIGNAL BREAKDOWN", false));

            splitTop.Panel2.Controls.Add(splitRight);
            splitOuter.Panel1.Controls.Add(splitTop);

            // ── bottom strip: graph | timeline | tokens | network | containment ─
            splitOuter.Panel2.Controls.Add(BuildBottomStrip());

            Controls.Add(splitOuter);   // Fill (first → processed last)
            Controls.Add(toolbar);      // Bottom
            Controls.Add(statusBar);    // Top  (last → processed first)

            // Defer SplitterDistance so panel has real width
            Shown += (_, _) =>
            {
                try
                {
                    splitOuter.SplitterDistance = (int)(splitOuter.Height * 0.55);
                    splitTop.SplitterDistance   = (int)(splitTop.Width   * 0.52);
                    splitRight.SplitterDistance = (int)(splitRight.Height * 0.52);
                }
                catch { }
            };
        }

        // ── Status Bar ────────────────────────────────────────────────────────
        private Panel BuildStatusBar()
        {
            var bar = new Panel
            {
                Dock      = DockStyle.Top,
                Height    = 54,
                BackColor = Color.FromArgb(14, 18, 28),
                Padding   = new Padding(0),
            };

            // Vertical separator helper
            static Panel Sep() => new Panel
            {
                Width = 1, Dock = DockStyle.Left,
                BackColor = Color.FromArgb(40, 52, 70), Margin = new Padding(0),
            };

            static Label StatusLabel(string text, int minW, ContentAlignment align = ContentAlignment.MiddleCenter) =>
                new Label
                {
                    Text      = text,
                    Dock      = DockStyle.Left,
                    MinimumSize = new Size(minW, 0),
                    AutoSize  = false,
                    Width     = minW,
                    ForeColor = Color.FromArgb(110, 125, 148),
                    Font      = new Font("Segoe UI", 8f),
                    TextAlign = align,
                    Padding   = new Padding(4, 0, 4, 0),
                };

            // RDRS logo label (leftmost)
            var lblLogo = new Label
            {
                Text      = "  RDRS",
                Dock      = DockStyle.Left,
                Width     = 82,
                ForeColor = C_Accent,
                Font      = new Font("Segoe UI", 13f, FontStyle.Bold),
                TextAlign = ContentAlignment.MiddleLeft,
                Padding   = new Padding(6, 0, 0, 0),
            };

            _lblProtection = new Label
            {
                Text      = "● PROTECTED",
                Dock      = DockStyle.Left,
                Width     = 165,
                ForeColor = C_Green,
                Font      = new Font("Segoe UI", 10f, FontStyle.Bold),
                TextAlign = ContentAlignment.MiddleCenter,
            };

            var capThreat   = StatusLabel("THREAT LEVEL",    100);
            _lblThreatLevel = new Label { Dock = DockStyle.Left, Width = 90,
                Font = new Font("Segoe UI", 10f, FontStyle.Bold),
                TextAlign = ContentAlignment.MiddleCenter, ForeColor = C_Green };

            var capMon    = StatusLabel("MONITORS",    80);
            _lblMonitors  = new Label { Dock = DockStyle.Left, Width = 55,
                Font = new Font("Segoe UI", 10f, FontStyle.Bold),
                TextAlign = ContentAlignment.MiddleCenter, ForeColor = C_TextHi };

            var capProc       = StatusLabel("PROCESSES",    90);
            _lblProcessCount  = new Label { Dock = DockStyle.Left, Width = 55,
                Font = new Font("Segoe UI", 10f, FontStyle.Bold),
                TextAlign = ContentAlignment.MiddleCenter, ForeColor = C_TextHi };

            var capLast    = StatusLabel("LAST ALERT",   90);
            _lblLastAlert  = new Label { Dock = DockStyle.Left, Width = 80,
                Font = new Font("Segoe UI", 9.5f),
                TextAlign = ContentAlignment.MiddleCenter, ForeColor = C_TextLo };

            // Right-side uptime label — stored in _lblUptime field for direct access
            _lblUptime = new Label
            {
                Dock      = DockStyle.Right,
                Width     = 180,
                ForeColor = C_TextLo,
                Font      = new Font("Segoe UI", 8.5f),
                TextAlign = ContentAlignment.MiddleRight,
                Padding   = new Padding(0, 0, 16, 0),
            };

            // Add controls left-to-right (DockStyle.Left stacks them)
            bar.Controls.Add(_lblUptime);       // Right dock (must add first)
            bar.Controls.Add(_lblLastAlert);
            bar.Controls.Add(capLast);
            bar.Controls.Add(Sep());
            bar.Controls.Add(_lblProcessCount);
            bar.Controls.Add(capProc);
            bar.Controls.Add(Sep());
            bar.Controls.Add(_lblMonitors);
            bar.Controls.Add(capMon);
            bar.Controls.Add(Sep());
            bar.Controls.Add(_lblThreatLevel);
            bar.Controls.Add(capThreat);
            bar.Controls.Add(Sep());
            bar.Controls.Add(_lblProtection);
            bar.Controls.Add(Sep());
            bar.Controls.Add(lblLogo);

            return bar;
        }

        // ── Toolbar ───────────────────────────────────────────────────────────
        private Panel BuildToolbar()
        {
            var bar = new Panel
            {
                Dock      = DockStyle.Bottom,
                Height    = 48,
                BackColor = Color.FromArgb(14, 18, 28),
                Padding   = new Padding(10, 8, 10, 8),
            };
            var flow = new FlowLayoutPanel
            {
                Dock         = DockStyle.Fill,
                FlowDirection = FlowDirection.LeftToRight,
                WrapContents  = false,
            };

            flow.Controls.Add(Btn("⏸  Pause 30s",     (_, _) => { _engine.Pause(30); RefreshStatusBarNow(); }));
            flow.Controls.Add(Btn("▶  Resume",          (_, _) => { _engine.Resume(); RefreshStatusBarNow(); }));
            flow.Controls.Add(Btn("⌫  Clear View",      OnClearView));
            flow.Controls.Add(Btn("📄  Open Alert Log",  (_, _) => OpenLog("rdrs_alerts.json")));
            flow.Controls.Add(Btn("📋  Open Containment Log", (_, _) => OpenLog("rdrs_containment.json")));

            var closeBtn = Btn("✕  Close", (_, _) => Hide());
            closeBtn.BackColor = Color.FromArgb(80, 22, 22);
            closeBtn.FlatAppearance.BorderColor = Color.FromArgb(120, 40, 40);
            flow.Controls.Add(closeBtn);

            bar.Controls.Add(flow);
            return bar;
        }

        // ── Alert Feed ────────────────────────────────────────────────────────
        private Control BuildAlertFeed()
        {
            _alertGrid = MakeGrid();

            _alertGrid.Columns.Add(new DataGridViewTextBoxColumn { Name = "time",      HeaderText = "Time",      FillWeight = 10 });
            _alertGrid.Columns.Add(new DataGridViewTextBoxColumn { Name = "severity",  HeaderText = "Severity",  FillWeight = 10 });
            _alertGrid.Columns.Add(new DataGridViewTextBoxColumn { Name = "score",     HeaderText = "Score",     FillWeight = 8  });
            _alertGrid.Columns.Add(new DataGridViewTextBoxColumn { Name = "event",     HeaderText = "Event",     FillWeight = 11 });
            _alertGrid.Columns.Add(new DataGridViewTextBoxColumn { Name = "token",     HeaderText = "Token",     FillWeight = 22 });
            _alertGrid.Columns.Add(new DataGridViewTextBoxColumn { Name = "process",   HeaderText = "Process",   FillWeight = 18 });
            _alertGrid.Columns.Add(new DataGridViewTextBoxColumn { Name = "entropy",   HeaderText = "Entropy",   FillWeight = 9  });
            _alertGrid.Columns.Add(new DataGridViewTextBoxColumn { Name = "indicator", HeaderText = "Indicators",FillWeight = 22 });

            // Clicking a row selects its process in the detail panel
            _alertGrid.SelectionChanged += (_, _) =>
            {
                if (_alertGrid.SelectedRows.Count == 0) return;
                var row = _alertGrid.SelectedRows[0];
                if (row.Tag is HoneytokenAlert a) SelectProcess(a.ProcessId);
            };

            return _alertGrid;
        }

        // ── Top Suspicious Processes ──────────────────────────────────────────
        private Control BuildTopProcesses()
        {
            _processGrid = MakeGrid();
            _processGrid.RowTemplate.Height = 26;

            _processGrid.Columns.Add(new DataGridViewTextBoxColumn { Name = "pname",   HeaderText = "Process",  FillWeight = 24 });
            _processGrid.Columns.Add(new DataGridViewTextBoxColumn { Name = "ppid",    HeaderText = "PID",      FillWeight = 9  });
            _processGrid.Columns.Add(new DataGridViewTextBoxColumn { Name = "pscore",  HeaderText = "Score",    FillWeight = 10 });
            _processGrid.Columns.Add(new DataGridViewTextBoxColumn { Name = "psignals",HeaderText = "Signals",  FillWeight = 9  });
            _processGrid.Columns.Add(new DataGridViewTextBoxColumn { Name = "psources",HeaderText = "Sources",  FillWeight = 22 });
            _processGrid.Columns.Add(new DataGridViewTextBoxColumn { Name = "pstatus", HeaderText = "Status",   FillWeight = 16 });
            _processGrid.Columns.Add(new DataGridViewTextBoxColumn { Name = "plast",   HeaderText = "Last Seen",FillWeight = 12 });

            _processGrid.SelectionChanged += (_, _) =>
            {
                if (_processGrid.SelectedRows.Count == 0) return;
                var row = _processGrid.SelectedRows[0];
                if (row.Tag is ProcessScoreSnapshot snap) SelectProcess(snap.ProcessId);
            };

            return _processGrid;
        }

        // ── Process Details ───────────────────────────────────────────────────
        private Control BuildProcessDetails()
        {
            var outer = new Panel { Dock = DockStyle.Fill, BackColor = C_BgPanel, Padding = new Padding(6) };

            // Left: key/value fields
            var left = new Panel { Dock = DockStyle.Fill, BackColor = C_BgPanel };

            Label KV(string key) => new Label
            {
                AutoSize  = true,
                ForeColor = C_TextLo,
                Font      = new Font("Segoe UI", 8f),
                Text      = key + ":",
                Padding   = new Padding(2, 3, 0, 0),
            };

            _lblProcName   = DetailVal(); _lblProcPid    = DetailVal();
            _lblProcPath   = DetailVal(); _lblProcParent = DetailVal();
            _lblProcSigned = DetailVal(); _lblProcScore  = DetailVal();

            // Score progress bar
            _pbScore = new ProgressBar
            {
                Height    = 10,
                Minimum   = 0, Maximum = 100,
                BackColor = C_BgCell,
                ForeColor = C_Green,
                Style     = ProgressBarStyle.Continuous,
            };

            var tbl = new TableLayoutPanel
            {
                Dock        = DockStyle.Top,
                AutoSize    = true,
                ColumnCount = 4,
                RowCount    = 4,
                BackColor   = Color.Transparent,
                Padding     = new Padding(4),
            };
            tbl.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            tbl.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
            tbl.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            tbl.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));

            tbl.Controls.Add(KV("Process"),  0, 0); tbl.Controls.Add(_lblProcName,   1, 0);
            tbl.Controls.Add(KV("PID"),      2, 0); tbl.Controls.Add(_lblProcPid,    3, 0);
            tbl.Controls.Add(KV("Path"),     0, 1); tbl.Controls.Add(_lblProcPath,   1, 1);
            tbl.SetColumnSpan(_lblProcPath, 3);
            tbl.Controls.Add(KV("Parent"),   0, 2); tbl.Controls.Add(_lblProcParent, 1, 2);
            tbl.Controls.Add(KV("Signed"),   2, 2); tbl.Controls.Add(_lblProcSigned, 3, 2);
            tbl.Controls.Add(KV("Score"),    0, 3); tbl.Controls.Add(_lblProcScore,  1, 3);

            // Signals list
            var lbTitle = new Label
            {
                Text = "CONTRIBUTING SIGNALS",
                Dock = DockStyle.Top, Height = 20,
                ForeColor = C_Accent, Font = new Font("Segoe UI", 8f, FontStyle.Bold),
                Padding = new Padding(4, 4, 0, 0),
            };
            _lbSignals = new ListBox
            {
                Dock        = DockStyle.Fill,
                BackColor   = C_BgCell,
                ForeColor   = C_TextHi,
                BorderStyle = BorderStyle.None,
                Font        = new Font("Consolas", 8.5f),
            };

            var pbWrap = new Panel { Dock = DockStyle.Top, Height = 14, BackColor = Color.Transparent, Padding = new Padding(4, 2, 4, 0) };
            _pbScore.Dock = DockStyle.Fill;
            pbWrap.Controls.Add(_pbScore);

            left.Controls.Add(_lbSignals);    // Fill
            left.Controls.Add(lbTitle);       // Top
            left.Controls.Add(pbWrap);        // Top
            left.Controls.Add(tbl);           // Top

            outer.Controls.Add(left);
            return outer;
        }

        private static Label DetailVal() => new Label
        {
            AutoSize  = true,
            ForeColor = Color.FromArgb(220, 232, 248),
            Font      = new Font("Consolas", 8.5f),
            Padding   = new Padding(2, 3, 0, 0),
        };

        // ── Bottom Strip (3-column) ───────────────────────────────────────────
        private Control BuildBottomStrip()
        {
            var tbl = new TableLayoutPanel
            {
                Dock        = DockStyle.Fill,
                ColumnCount = 3,
                RowCount    = 1,
                BackColor   = C_Border,
            };
            tbl.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 34f));
            tbl.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 34f));
            tbl.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 32f));

            // Honeytoken status
            var tokenPanel = new Panel { Dock = DockStyle.Fill, BackColor = C_BgPanel, Margin = new Padding(0, 0, 1, 0) };
            _tokenGrid = MakeGrid();
            _tokenGrid.RowTemplate.Height = 22;
            _tokenGrid.Columns.Add(new DataGridViewTextBoxColumn { Name = "tname",  HeaderText = "Honeytoken File",FillWeight = 42 });
            _tokenGrid.Columns.Add(new DataGridViewTextBoxColumn { Name = "tstatus",HeaderText = "Status",         FillWeight = 20 });
            _tokenGrid.Columns.Add(new DataGridViewTextBoxColumn { Name = "tcount", HeaderText = "Hits",           FillWeight = 10 });
            _tokenGrid.Columns.Add(new DataGridViewTextBoxColumn { Name = "tlast",  HeaderText = "Last Trigger",   FillWeight = 28 });
            tokenPanel.Controls.Add(_tokenGrid);
            tokenPanel.Controls.Add(SectionTitle("  ⬡  HONEYTOKEN STATUS", false));
            tbl.Controls.Add(tokenPanel, 0, 0);

            // Network activity + Graph split
            var netGrpPanel = new Panel { Dock = DockStyle.Fill, BackColor = C_BgPanel, Margin = new Padding(1, 0, 1, 0) };
            var splitNG = new SplitContainer { Dock = DockStyle.Fill, Orientation = Orientation.Horizontal, BackColor = C_Border };
            splitNG.Panel1.BackColor = C_BgPanel;
            splitNG.Panel2.BackColor = C_BgPanel;

            _lbNetwork = new ListBox
            {
                Dock = DockStyle.Fill, BackColor = C_BgCell, ForeColor = C_TextHi,
                BorderStyle = BorderStyle.None, Font = new Font("Consolas", 8.2f),
            };
            splitNG.Panel1.Controls.Add(_lbNetwork);
            splitNG.Panel1.Controls.Add(SectionTitle("  ⬢  NETWORK ACTIVITY", false));

            // Threat graph in the right side of bottom-middle
            _graphPanel = new DoubleBufferedPanel { Dock = DockStyle.Fill, BackColor = C_BgCell };
            _graphPanel.Paint += OnThreatGraphPaint;
            splitNG.Panel2.Controls.Add(_graphPanel);
            splitNG.Panel2.Controls.Add(SectionTitle("  ▶  THREAT SCORE GRAPH", false));

            netGrpPanel.Controls.Add(splitNG);
            tbl.Controls.Add(netGrpPanel, 1, 0);

            // Containment + signal breakdown
            var contPanel = new Panel { Dock = DockStyle.Fill, BackColor = C_BgPanel, Margin = new Padding(1, 0, 0, 0) };
            var splitCS = new SplitContainer { Dock = DockStyle.Fill, Orientation = Orientation.Horizontal, BackColor = C_Border };
            splitCS.Panel1.BackColor = C_BgPanel;
            splitCS.Panel2.BackColor = C_BgPanel;

            // Containment summary
            var contInner = new Panel { Dock = DockStyle.Fill, BackColor = C_BgPanel, Padding = new Padding(6, 4, 6, 4) };
            _lblLastContain  = new Label { Dock = DockStyle.Top, Height = 18, ForeColor = C_TextHi, Font = new Font("Consolas", 8.5f) };
            _lblContainCount = new Label { Dock = DockStyle.Top, Height = 18, ForeColor = C_TextLo, Font = new Font("Segoe UI", 8f) };
            _lbContainLog    = new ListBox { Dock = DockStyle.Fill, BackColor = C_BgCell, ForeColor = C_TextHi, BorderStyle = BorderStyle.None, Font = new Font("Consolas", 8f) };
            contInner.Controls.Add(_lbContainLog);
            contInner.Controls.Add(_lblLastContain);
            contInner.Controls.Add(_lblContainCount);
            splitCS.Panel1.Controls.Add(contInner);
            splitCS.Panel1.Controls.Add(SectionTitle("  ⚡  CONTAINMENT SUMMARY", false));

            // Signal breakdown chart
            _sigBreakPanel = new DoubleBufferedPanel { Dock = DockStyle.Fill, BackColor = C_BgCell };
            _sigBreakPanel.Paint += OnSignalBreakdownPaint;
            splitCS.Panel2.Controls.Add(_sigBreakPanel);
            splitCS.Panel2.Controls.Add(SectionTitle("  ◑  SIGNAL BREAKDOWN", false));

            contPanel.Controls.Add(splitCS);
            tbl.Controls.Add(contPanel, 2, 0);

            // Attack timeline replaces old chart area — add to netGrpPanel split
            // (already handled above via splitNG)

            Shown += (_, _) =>
            {
                try { splitNG.SplitterDistance = (int)(splitNG.Height * 0.50); } catch { }
                try { splitCS.SplitterDistance = (int)(splitCS.Height * 0.55); } catch { }
            };

            return tbl;
        }

        // ─────────────────────────────────────────────────────────────────────
        //  Backend event handlers (run on UI thread via BeginInvoke)
        // ─────────────────────────────────────────────────────────────────────

        private void OnAlertReceived(HoneytokenAlert alert)
        {
            // Attack timeline entry
            var color = alert.RiskLabel switch
            {
                "CRITICAL" => C_Red,
                "HIGH"     => C_Orange,
                "MEDIUM"   => C_Yellow,
                _          => C_TextLo,
            };
            AddTimeline($"[{alert.Timestamp:HH:mm:ss}] {alert.EventType} ▸ {alert.TokenFileName} "
                       + $"({alert.ProcessName}/{alert.ProcessId}) — {alert.RiskLabel} {alert.RiskScore}/100", color);

            // Update score history for graph
            if (alert.ProcessId > 0)
            {
                _pidNames[alert.ProcessId] = alert.ProcessName;
                if (!_scoreHistory.TryGetValue(alert.ProcessId, out var q))
                    _scoreHistory[alert.ProcessId] = q = new Queue<(DateTime, int)>();
                q.Enqueue((alert.Timestamp, alert.RiskScore));
                PruneGraphHistory();
            }
        }

        private void OnFusedThreatReceived(FusedThreat threat)
        {
            // Update score history
            _pidNames[threat.ProcessId] = threat.ProcessName;
            if (!_scoreHistory.TryGetValue(threat.ProcessId, out var q))
                _scoreHistory[threat.ProcessId] = q = new Queue<(DateTime, int)>();
            q.Enqueue((threat.Timestamp, threat.FusedScore));
            PruneGraphHistory();

            // Attack timeline
            AddTimeline($"[{threat.Timestamp:HH:mm:ss}] FUSED THREAT ▸ {threat.ProcessName} "
                       + $"({threat.ProcessId}) Score={threat.FusedScore} [{threat.ActiveSources}]",
                       threat.FusedScore >= 80 ? C_Red : C_Orange);

            // Network events from contributing signals
            foreach (var sig in threat.ContributingSignals.Where(s => s.Source == SignalSource.Network))
            {
                foreach (var ind in sig.Indicators)
                {
                    AddNetEvent(threat.ProcessName, ind, $"PID {threat.ProcessId}");
                    // Containment log
                    AddTimeline($"[{sig.Timestamp:HH:mm:ss}] NETWORK ▸ {ind} — {threat.ProcessName}", C_Purple);
                }
            }

            // Update signal breakdown weights
            foreach (var sig in threat.ContributingSignals)
            {
                var key = sig.Source switch
                {
                    SignalSource.Honeytoken  => "Honeytoken",
                    SignalSource.CryptoApi   => "CryptoApi",
                    SignalSource.EtwFileRate => "ETW",
                    SignalSource.Network     => "Network",
                    _                        => "Behavioral",
                };
                _sigBreakdown[key] = _sigBreakdown.GetValueOrDefault(key) + sig.RawScore;
            }

            // Log containment for this fused threat
            AddContainLog($"[{threat.Timestamp:HH:mm:ss}] Score={threat.FusedScore} "
                        + $"{threat.ProcessName} ({threat.ProcessId}) — {threat.RiskLabel}");

            // Invalidate graph panels
            _graphPanel.Invalidate();
            _sigBreakPanel.Invalidate();
        }

        // ─────────────────────────────────────────────────────────────────────
        //  Periodic Refresh
        // ─────────────────────────────────────────────────────────────────────

        private void RefreshAll()
        {
            if (!IsHandleCreated || IsDisposed) return;
            if (InvokeRequired) { BeginInvoke(new Action(RefreshAll)); return; }

            RefreshStatusBarNow();
            RefreshAlertGrid();
            RefreshTopProcesses();
            RefreshHoneytokens();
            RefreshNetwork();
            RefreshContainment();
            if (_selectedPid > 0) RefreshProcessDetails(_selectedPid);
            _graphPanel.Invalidate();
        }

        // ── Status bar ────────────────────────────────────────────────────────
        private void RefreshStatusBarNow()
        {
            // Protection status
            if (_engine.IsPaused)
            {
                _lblProtection.Text      = "⏸ PAUSED";
                _lblProtection.ForeColor = C_Yellow;
            }
            else
            {
                _lblProtection.Text      = "● PROTECTED";
                _lblProtection.ForeColor = C_Green;
            }

            // Global threat level (based on last 10 alerts)
            var recent = _engine.GetRecentAlerts(10);
            int maxScore = recent.Count > 0 ? recent.Max(a => a.RiskScore) : 0;
            (_lblThreatLevel.Text, _lblThreatLevel.ForeColor) = maxScore switch
            {
                >= 80 => ("CRITICAL", C_Red),
                >= 60 => ("HIGH",     C_Orange),
                >= 40 => ("MEDIUM",   C_Yellow),
                _     => ("LOW",      C_Green),
            };

            // Active monitors (7 total)
            _lblMonitors.Text = "7 / 7";

            // Processes being tracked (non-zero score snapshots)
            var scores = _engine.GetProcessScores();
            _lblProcessCount.Text = scores.Count.ToString();

            // Last alert time
            var last = _engine.LastAlert;
            _lblLastAlert.Text = last != null ? last.Timestamp.ToString("HH:mm:ss") : "—";

            // Uptime — direct field reference, no string lookup needed
            var uptime = _engine.StartedAt == default ? TimeSpan.Zero : DateTime.Now - _engine.StartedAt;
            _lblUptime.Text = $"Uptime  {uptime:hh\\:mm\\:ss}  |  Alerts  {_engine.TotalAlerts}   ";
        }

        // ── Alert Grid ────────────────────────────────────────────────────────
        private void RefreshAlertGrid()
        {
            if (_engine.TotalAlerts == _lastAlertCount) return;
            _lastAlertCount = _engine.TotalAlerts;

            var alerts = _engine.GetRecentAlerts(60);
            _alertGrid.SuspendLayout();
            _alertGrid.Rows.Clear();

            foreach (var a in alerts)
            {
                var entStr = a.EntropyScore >= 0 ? $"{a.EntropyScore:F2}" : "—";
                var inds   = a.Indicators.Count > 0 ? string.Join(", ", a.Indicators) : "—";
                var token  = (a.TokenFileName?.Length > 22 ? a.TokenFileName[..20] + "…" : a.TokenFileName) ?? "";

                _alertGrid.Rows.Add(
                    a.Timestamp.ToString("HH:mm:ss"),
                    a.RiskLabel,
                    $"{a.RiskScore}/100",
                    a.EventType,
                    token,
                    $"{a.ProcessName} ({a.ProcessId})",
                    entStr,
                    inds);

                var row = _alertGrid.Rows[_alertGrid.RowCount - 1];
                row.Tag = a;  // store for click handler

                (row.DefaultCellStyle.BackColor, row.DefaultCellStyle.ForeColor) = a.RiskLabel switch
                {
                    "CRITICAL" => (Color.FromArgb(55, 18, 18), C_Red),
                    "HIGH"     => (Color.FromArgb(50, 32, 10), C_Orange),
                    "MEDIUM"   => (Color.FromArgb(42, 38, 10), C_Yellow),
                    _          => (C_BgCell,                   C_TextHi),
                };
            }

            if (_alertGrid.RowCount > 0)
                _alertGrid.FirstDisplayedScrollingRowIndex = _alertGrid.RowCount - 1;

            _alertGrid.ResumeLayout();
        }

        // ── Top Suspicious Processes ──────────────────────────────────────────
        private void RefreshTopProcesses()
        {
            var scores = _engine.GetProcessScores().Take(8).ToList();

            _processGrid.SuspendLayout();
            _processGrid.Rows.Clear();

            foreach (var p in scores)
            {
                var status = p.FusedScore >= 70 ? "CONTAINED/THREAT"
                           : p.FusedScore >= 40 ? "SUSPICIOUS"
                           : "MONITORING";
                var sources = string.Join(", ", p.Sources.Select(s => s.ToString()));
                var lastSeen = (DateTime.Now - p.LastSeen).TotalSeconds < 10
                    ? "Just now"
                    : p.LastSeen.ToString("HH:mm:ss");

                _processGrid.Rows.Add(
                    p.ProcessName,
                    p.ProcessId,
                    $"{p.FusedScore}/100",
                    p.SignalCount,
                    sources,
                    status,
                    lastSeen);

                var row = _processGrid.Rows[_processGrid.RowCount - 1];
                row.Tag = p;

                (row.DefaultCellStyle.BackColor, row.DefaultCellStyle.ForeColor) = p.FusedScore switch
                {
                    >= 70 => (Color.FromArgb(50, 16, 16), C_Red),
                    >= 40 => (Color.FromArgb(46, 30, 10), C_Orange),
                    >= 20 => (Color.FromArgb(40, 36, 10), C_Yellow),
                    _     => (C_BgCell,                   C_TextHi),
                };
            }

            _processGrid.ResumeLayout();
        }

        // ── Process Details ───────────────────────────────────────────────────
        private void SelectProcess(int pid)
        {
            _selectedPid = pid;
            RefreshProcessDetails(pid);
        }

        private void RefreshProcessDetails(int pid)
        {
            // Find best available data: prefer fused score snapshot, fall back to alert
            var snap  = _engine.GetProcessScores().FirstOrDefault(p => p.ProcessId == pid);
            var alert = _engine.GetRecentAlerts(200)
                               .LastOrDefault(a => a.ProcessId == pid);

            if (snap == null && alert == null)
            {
                _lblProcName.Text = $"PID {pid} — no current data";
                return;
            }

            string name   = snap?.ProcessName ?? alert?.ProcessName ?? "unknown";
            string path   = snap?.ProcessPath ?? alert?.ProcessPath ?? "unknown";
            string parent = alert?.ParentProcessName != null
                ? $"{alert.ParentProcessName} ({alert.ParentProcessId})" : "—";
            bool   signed = alert?.IsSigned ?? false;
            int    score  = snap?.FusedScore ?? alert?.RiskScore ?? 0;

            _lblProcName.Text   = name;
            _lblProcPid.Text    = pid.ToString();
            _lblProcPath.Text   = path.Length > 70 ? "…" + path[^68..] : path;
            _lblProcParent.Text = parent;
            _lblProcSigned.Text = signed ? "✓ Signed" : "✗ Unsigned";
            _lblProcSigned.ForeColor = signed ? C_Green : C_Red;
            _lblProcScore.Text  = $"{score} / 100";
            _lblProcScore.ForeColor = score >= 70 ? C_Red : score >= 40 ? C_Orange : C_Green;

            _pbScore.Value = Math.Min(score, 100);
            _pbScore.ForeColor = score >= 70 ? C_Red : score >= 40 ? C_Yellow : C_Green;

            // Contributing signals
            _lbSignals.Items.Clear();
            if (snap != null)
            {
                var weights = new Dictionary<SignalSource, double>
                {
                    [SignalSource.Honeytoken]  = 0.35,
                    [SignalSource.CryptoApi]   = 0.25,
                    [SignalSource.EtwFileRate] = 0.20,
                    [SignalSource.Network]     = 0.12,
                    [SignalSource.Signature]   = 0.08,
                };
                foreach (var sig in snap.BestSignals.OrderByDescending(s => s.RawScore))
                {
                    weights.TryGetValue(sig.Source, out double w);
                    int contribution = (int)Math.Round(w * sig.RawScore * 100);
                    var inds = sig.Indicators.Count > 0 ? string.Join(", ", sig.Indicators) : "—";
                    _lbSignals.Items.Add(
                        $"  {sig.Source,-14} raw={sig.RawScore:F2}  wt={w:F2}  contrib={contribution,3}pts  [{inds}]");
                }
            }
            else if (alert != null && alert.Indicators.Count > 0)
            {
                _lbSignals.Items.Add($"  Honeytoken     score={alert.RiskScore}");
                foreach (var ind in alert.Indicators)
                    _lbSignals.Items.Add($"    → {ind}");
            }
        }

        // ── Honeytoken Status ─────────────────────────────────────────────────
        private void RefreshHoneytokens()
        {
            var tokens = _engine.DeployedTokens;
            _tokenGrid.SuspendLayout();
            _tokenGrid.Rows.Clear();

            foreach (var t in tokens)
            {
                var lastTrig = t.TriggeredAt.HasValue ? t.TriggeredAt.Value.ToString("HH:mm:ss") : "—";
                _tokenGrid.Rows.Add(t.ShortName, t.Status.ToString(), t.TriggerCount, lastTrig);
                var row = _tokenGrid.Rows[_tokenGrid.RowCount - 1];

                (row.DefaultCellStyle.BackColor, row.DefaultCellStyle.ForeColor) = t.Status switch
                {
                    HoneytokenWatcher.Honeytokens.TokenStatus.Triggered  => (Color.FromArgb(50, 32, 10), C_Orange),
                    HoneytokenWatcher.Honeytokens.TokenStatus.Missing     => (Color.FromArgb(55, 18, 18), C_Red),
                    HoneytokenWatcher.Honeytokens.TokenStatus.Contained   => (Color.FromArgb(36, 16, 52), C_Purple),
                    _                                                      => (C_BgCell,                  C_Green),
                };
            }

            _tokenGrid.ResumeLayout();
        }

        // ── Network Activity ──────────────────────────────────────────────────
        private void RefreshNetwork()
        {
            _lbNetwork.Items.Clear();
            foreach (var (t, proc, tag, detail) in _netEvents.TakeLast(20))
                _lbNetwork.Items.Add($"[{t:HH:mm:ss}] {proc,-14} {tag,-22} {detail}");
        }

        // ── Containment Summary ───────────────────────────────────────────────
        private void RefreshContainment()
        {
            var c = _engine.LastContainment;
            if (c != null && c.Action != ContainmentAction.None)
            {
                _lblLastContain.Text      = $"{c.ProcessName} (PID {c.ProcessId})  →  {c.Action}  [{c.Timestamp:HH:mm:ss}]";
                _lblLastContain.ForeColor = C_Red;
            }
            else
            {
                _lblLastContain.Text      = "No containment actions yet.";
                _lblLastContain.ForeColor = C_TextLo;
            }

            var alerts = _engine.GetRecentAlerts(500);
            int contained = alerts.Count(a => a.RiskScore >= 70 && a.ProcessId > 0);
            _lblContainCount.Text = $"Total high-risk events: {contained}";

            _lbContainLog.Items.Clear();
            foreach (var entry in _containLog.TakeLast(20))
                _lbContainLog.Items.Add(entry);
        }

        // ─────────────────────────────────────────────────────────────────────
        //  GDI+ Threat Score Graph
        // ─────────────────────────────────────────────────────────────────────

        private void OnThreatGraphPaint(object? sender, PaintEventArgs e)
        {
            var g   = e.Graphics;
            var rc  = _graphPanel.ClientRectangle;
            g.SmoothingMode = SmoothingMode.AntiAlias;
            g.Clear(C_BgCell);

            using var titleF = new Font("Segoe UI", 8f, FontStyle.Bold);
            using var dimB   = new SolidBrush(C_TextLo);
            using var accB   = new SolidBrush(C_Accent);
            g.DrawString("THREAT SCORE  (last 5 min)", titleF, accB, 6, 4);

            int margin = 40;
            int gLeft  = margin + 10;
            int gRight = rc.Width - 12;
            int gTop   = 22;
            int gBot   = rc.Height - 24;
            int gW     = gRight - gLeft;
            int gH     = gBot - gTop;
            if (gW < 10 || gH < 10) return;

            var now    = DateTime.Now;
            var cutoff = now.AddMinutes(-5);

            // Grid lines at 25, 50, 70, 100
            using var gridP = new Pen(Color.FromArgb(35, 50, 70), 1) { DashStyle = DashStyle.Dot };
            using var gridF = new Font("Consolas", 7f);
            foreach (int val in new[] { 25, 50, 70, 100 })
            {
                int gy = gBot - (int)((double)val / 100 * gH);
                g.DrawLine(gridP, gLeft, gy, gRight, gy);
                g.DrawString(val.ToString(), gridF, dimB, 2, gy - 6);
                if (val == 70)
                {
                    using var threshP = new Pen(Color.FromArgb(160, C_Red.R, C_Red.G, C_Red.B), 1) { DashStyle = DashStyle.Dash };
                    g.DrawLine(threshP, gLeft, gy, gRight, gy);
                }
            }

            // Bottom axis label
            g.DrawString(cutoff.ToString("HH:mm"), gridF, dimB, gLeft, gBot + 4);
            g.DrawString(now.ToString("HH:mm"),    gridF, dimB, gRight - 26, gBot + 4);

            // Line colors per PID (cycle through palette)
            var palette = new[] { C_Accent, C_Orange, C_Green, C_Purple, C_Yellow };
            int colorIdx = 0;

            // Take top 4 processes by max score
            var activePids = _scoreHistory
                .Where(kv => kv.Value.Any(pt => pt.t >= cutoff))
                .OrderByDescending(kv => kv.Value.Where(pt => pt.t >= cutoff).Max(pt => pt.score))
                .Take(4)
                .ToList();

            int legendY = gTop;
            foreach (var kv in activePids)
            {
                var pts = kv.Value.Where(pt => pt.t >= cutoff).OrderBy(pt => pt.t).ToList();
                if (pts.Count < 1) { colorIdx++; continue; }

                var color = palette[colorIdx % palette.Length];
                colorIdx++;

                // Legend
                using var legendB = new SolidBrush(color);
                _pidNames.TryGetValue(kv.Key, out var pname);
                g.FillRectangle(legendB, gRight - 105, legendY + 2, 10, 10);
                g.DrawString($"{pname ?? kv.Key.ToString()} ({kv.Key})", gridF, legendB, gRight - 92, legendY);
                legendY += 14;

                // Draw line
                using var linePen = new Pen(color, 1.5f) { LineJoin = LineJoin.Round };
                var points = pts.Select(pt =>
                {
                    double tFrac = (pt.t - cutoff).TotalSeconds / 300.0;
                    float  x     = gLeft + (float)(tFrac * gW);
                    float  y     = gBot  - (float)(pt.score / 100.0 * gH);
                    return new PointF(x, y);
                }).ToArray();

                if (points.Length >= 2)
                    g.DrawLines(linePen, points);
                else if (points.Length == 1)
                {
                    using var dotB = new SolidBrush(color);
                    g.FillEllipse(dotB, points[0].X - 3, points[0].Y - 3, 6, 6);
                }

                // Latest score bubble
                var last = points.Last();
                if (pts.Last().score >= 40)
                {
                    using var bubbleB = new SolidBrush(Color.FromArgb(180, color));
                    g.FillEllipse(bubbleB, last.X - 4, last.Y - 4, 8, 8);
                    g.DrawString(pts.Last().score.ToString(), gridF, new SolidBrush(C_TextHi),
                        last.X + 5, last.Y - 6);
                }
            }

            if (!activePids.Any())
            {
                g.DrawString("No threat data yet — monitoring active…", gridF, dimB, gLeft + 10, gTop + gH / 2);
            }
        }

        // ─────────────────────────────────────────────────────────────────────
        //  GDI+ Signal Breakdown Bar Chart
        // ─────────────────────────────────────────────────────────────────────

        private void OnSignalBreakdownPaint(object? sender, PaintEventArgs e)
        {
            var g  = e.Graphics;
            var rc = _sigBreakPanel.ClientRectangle;
            g.Clear(C_BgCell);

            using var titleF  = new Font("Segoe UI", 8f, FontStyle.Bold);
            using var accB    = new SolidBrush(C_Accent);
            using var dimB    = new SolidBrush(C_TextLo);
            using var labelF  = new Font("Consolas", 7.5f);
            using var bgTrack = new SolidBrush(Color.FromArgb(30, 40, 55));

            double total = _sigBreakdown.Values.Sum();
            if (total <= 0)
            {
                g.DrawString("No signal data yet.", titleF, dimB, 8, rc.Height / 2 - 8);
                return;
            }

            var palette = new Dictionary<string, Color>
            {
                ["Honeytoken"] = C_Red,
                ["CryptoApi"]  = C_Orange,
                ["ETW"]        = C_Accent,
                ["Network"]    = C_Purple,
                ["Behavioral"] = C_Yellow,
            };

            int barLeft  = 72;
            int barRight = rc.Width - 36;
            int barWidth = barRight - barLeft;
            int y        = 8;
            const int barH = 16, gap = 5;

            foreach (var kv in _sigBreakdown.OrderByDescending(x => x.Value))
            {
                if (y + barH > rc.Height - 4) break;
                double frac  = kv.Value / total;
                int    fill  = (int)(frac * barWidth);
                var    color = palette.TryGetValue(kv.Key, out var c) ? c : C_TextHi;

                g.DrawString(kv.Key.PadRight(10), labelF, new SolidBrush(C_TextLo), 2, y + 2);
                g.FillRectangle(bgTrack, barLeft, y, barWidth, barH);

                if (fill > 0)
                {
                    var dark = Color.FromArgb(color.R / 2, color.G / 2, color.B / 2);
                    using var grad = new LinearGradientBrush(
                        new Rectangle(barLeft, y, Math.Max(fill, 1), barH),
                        color, dark, LinearGradientMode.Horizontal);
                    g.FillRectangle(grad, barLeft, y, fill, barH);
                }

                g.DrawString($"{frac * 100:F0}%", labelF, new SolidBrush(C_TextHi),
                    barLeft + fill + 4, y + 2);
                y += barH + gap;
            }
        }

        // ─────────────────────────────────────────────────────────────────────
        //  Button / View handlers
        // ─────────────────────────────────────────────────────────────────────

        private void OnClearView(object? sender, EventArgs e)
        {
            _alertGrid.Rows.Clear();
            _processGrid.Rows.Clear();
            _lbTimeline?.Items.Clear();
            _timeline.Clear();
            _lbNetwork.Items.Clear();
            _netEvents.Clear();
            _lbContainLog.Items.Clear();
            _containLog.Clear();
            _scoreHistory.Clear();
            _pidNames.Clear();
            foreach (var k in _sigBreakdown.Keys.ToList()) _sigBreakdown[k] = 0;
            _lastAlertCount = -1;
            _sigBreakPanel.Invalidate();
            _graphPanel.Invalidate();
        }

        private static void OpenLog(string name)
        {
            var path = Path.GetFullPath(name);
            if (!File.Exists(path))
            {
                MessageBox.Show($"Log file not found:\n{path}", "RDRS",
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

        // ─────────────────────────────────────────────────────────────────────
        //  Helpers
        // ─────────────────────────────────────────────────────────────────────

        private void AddTimeline(string msg, Color clr)
        {
            _timeline.Add((DateTime.Now, msg, clr));
            if (_timeline.Count > 80) _timeline.RemoveAt(0);
        }

        private void AddNetEvent(string proc, string tag, string detail)
        {
            _netEvents.Add((DateTime.Now, proc, tag, detail));
            if (_netEvents.Count > 40) _netEvents.RemoveAt(0);
        }

        private void AddContainLog(string entry)
        {
            _containLog.Add(entry);
            if (_containLog.Count > 30) _containLog.RemoveAt(0);
        }

        private void PruneGraphHistory()
        {
            var cutoff = DateTime.Now.AddMinutes(-6);
            foreach (var q in _scoreHistory.Values)
                while (q.Count > 0 && q.Peek().t < cutoff) q.Dequeue();
        }

        /// <summary>
        /// Standardised dark-theme DataGridView factory.
        /// </summary>
        private static DataGridView MakeGrid()
        {
            var g = new DataGridView
            {
                Dock                        = DockStyle.Fill,
                BackgroundColor             = C_BgCell,
                GridColor                   = C_Border,
                BorderStyle                 = BorderStyle.None,
                RowHeadersVisible           = false,
                AllowUserToAddRows          = false,
                AllowUserToDeleteRows       = false,
                ReadOnly                    = true,
                SelectionMode               = DataGridViewSelectionMode.FullRowSelect,
                AutoSizeColumnsMode         = DataGridViewAutoSizeColumnsMode.Fill,
                ColumnHeadersHeight         = 26,
                RowTemplate                 = { Height = 21 },
                EnableHeadersVisualStyles   = false,
                ColumnHeadersBorderStyle    = DataGridViewHeaderBorderStyle.Single,
            };
            g.DefaultCellStyle = new DataGridViewCellStyle
            {
                BackColor          = C_BgCell,
                ForeColor          = C_TextHi,
                SelectionBackColor = C_BgHover,
                SelectionForeColor = Color.White,
                Font               = new Font("Consolas", 8.2f),
            };
            g.ColumnHeadersDefaultCellStyle = new DataGridViewCellStyle
            {
                BackColor          = C_BgHeader,
                ForeColor          = C_Accent,
                SelectionBackColor = C_BgHeader,
                Font               = new Font("Segoe UI", 8.2f, FontStyle.Bold),
            };
            return g;
        }

        /// <summary>
        /// Section title label pinned to the top of a panel.
        /// </summary>
        private static Label SectionTitle(string text, bool large)
        {
            return new Label
            {
                Text      = text,
                Dock      = DockStyle.Top,
                Height    = large ? 26 : 22,
                ForeColor = C_Accent,
                BackColor = C_BgHeader,
                Font      = new Font("Segoe UI", large ? 9f : 8.5f, FontStyle.Bold),
                TextAlign = ContentAlignment.MiddleLeft,
                Padding   = new Padding(6, 0, 0, 0),
            };
        }

        /// <summary>
        /// Dark-theme toolbar button factory.
        /// </summary>
        private static Button Btn(string text, EventHandler onClick)
        {
            var b = new Button
            {
                Text      = text,
                Height    = 30,
                AutoSize  = true,
                Padding   = new Padding(10, 0, 10, 0),
                Margin    = new Padding(4, 0, 4, 0),
                BackColor = Color.FromArgb(30, 40, 58),
                ForeColor = C_TextHi,
                FlatStyle = FlatStyle.Flat,
                Cursor    = Cursors.Hand,
                Font      = new Font("Segoe UI", 8.5f),
            };
            b.FlatAppearance.BorderColor = C_Border;
            b.Click += onClick;
            return b;
        }

        // ─────────────────────────────────────────────────────────────────────
        //  Form lifecycle
        // ─────────────────────────────────────────────────────────────────────

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

    // ─────────────────────────────────────────────────────────────────────────
    //  Double-buffered panel (eliminates flicker on GDI+ redraws)
    // ─────────────────────────────────────────────────────────────────────────

    internal sealed class DoubleBufferedPanel : Panel
    {
        public DoubleBufferedPanel()
        {
            DoubleBuffered = true;
            SetStyle(ControlStyles.OptimizedDoubleBuffer |
                     ControlStyles.AllPaintingInWmPaint  |
                     ControlStyles.UserPaint, true);
        }
    }
}
