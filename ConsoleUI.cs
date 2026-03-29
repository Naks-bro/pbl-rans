using System;
using System.Collections.Generic;
using System.Linq;
using HoneytokenWatcher.Alerting;
using HoneytokenWatcher.Analysis;
using HoneytokenWatcher.Containment;
using HoneytokenWatcher.Honeytokens;

namespace HoneytokenWatcher.UI
{
    public class ConsoleUI
    {
        private int _boardStartRow = 0;
        private int _boardHeight = 0;
        private bool _boardDrawn = false;
        private readonly object _consoleLock = new();

        // ── Colors ───────────────────────────────────────────────────────────
        private static void Green(string s)   { Console.ForegroundColor = ConsoleColor.Green;   Console.Write(s); Console.ResetColor(); }
        private static void Red(string s)     { Console.ForegroundColor = ConsoleColor.Red;     Console.Write(s); Console.ResetColor(); }
        private static void Yellow(string s)  { Console.ForegroundColor = ConsoleColor.Yellow;  Console.Write(s); Console.ResetColor(); }
        private static void Cyan(string s)    { Console.ForegroundColor = ConsoleColor.Cyan;    Console.Write(s); Console.ResetColor(); }
        private static void Magenta(string s) { Console.ForegroundColor = ConsoleColor.Magenta; Console.Write(s); Console.ResetColor(); }
        private static void Dim(string s)     { Console.ForegroundColor = ConsoleColor.DarkGray; Console.Write(s); Console.ResetColor(); }
        private static void White(string s)   { Console.ForegroundColor = ConsoleColor.White;   Console.Write(s); Console.ResetColor(); }

        public void DrawBanner()
        {
            try { Console.Clear(); } catch { }
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine(@"
  ██████╗ ██████╗ ██████╗ ███████╗
  ██╔══██╗██╔══██╗██╔══██╗██╔════╝
  ██████╔╝██║  ██║██████╔╝███████╗
  ██╔══██╗██║  ██║██╔══██╗╚════██║
  ██║  ██║██████╔╝██║  ██║███████║
  ╚═╝  ╚═╝╚═════╝ ╚═╝  ╚═╝╚══════╝");
            Console.ResetColor();
            Dim("  Ransomware Detection & Response Service\n");
            Dim("  ─── Deception Layer : Honeytoken Watcher ───\n\n");
        }

        public void Status(string msg)
        {
            lock (_consoleLock)
            {
                Dim("  ["); Green("*"); Dim("] ");
                Console.WriteLine(msg);
            }
        }

        public void Warn(string msg)
        {
            lock (_consoleLock)
            {
                Dim("  ["); Yellow("!"); Dim("] ");
                Console.WriteLine(msg);
            }
        }

        public void DrawStatusBoard(List<HoneytokenFile> tokens)
        {
            lock (_consoleLock)
            {
                Console.WriteLine();
                _boardStartRow = Console.CursorTop;
                RenderBoard(tokens, 0);
                _boardDrawn = true;
            }
        }

        public void RefreshBoard(List<HoneytokenFile> tokens, int alertCount)
        {
            if (!_boardDrawn) return;
            lock (_consoleLock)
            {
                var savedRow = Console.CursorTop;
                Console.SetCursorPosition(0, _boardStartRow);
                RenderBoard(tokens, alertCount);
                // Restore cursor to the alerts section (below board), preserving scroll
                var belowBoard = _boardStartRow + _boardHeight;
                Console.SetCursorPosition(0, Math.Max(savedRow, belowBoard));
            }
        }

        private void RenderBoard(List<HoneytokenFile> tokens, int alertCount)
        {
            var renderStart = Console.CursorTop;

            // Erase the previous board area before rewriting to prevent ghost chars
            if (_boardHeight > 0)
            {
                try
                {
                    var width = Console.WindowWidth;
                    for (int i = 0; i < _boardHeight; i++)
                    {
                        Console.SetCursorPosition(0, renderStart + i);
                        Console.Write(new string(' ', width));
                    }
                    Console.SetCursorPosition(0, renderStart);
                }
                catch { }
            }

            var now = DateTime.Now.ToString("HH:mm:ss");
            var watching   = tokens.Count(t => t.Status == TokenStatus.Watching);
            var triggered  = tokens.Count(t => t.Status == TokenStatus.Triggered);
            var contained  = tokens.Count(t => t.Status == TokenStatus.Contained);

            // Header line
            Dim("  ┌─ HONEYTOKEN STATUS ");
            Dim(new string('─', 48));
            Dim("┐\n");

            // Summary row
            Dim("  │  ");
            Dim($"[{now}]  ");
            Green($"{watching} WATCHING");
            Dim("  ");
            if (triggered > 0) Red($"{triggered} TRIGGERED");
            else Dim("0 triggered");
            Dim("  ");
            if (contained > 0) Magenta($"{contained} CONTAINED");
            else Dim("0 contained");
            Dim($"   Alerts: ");
            if (alertCount > 0) Red(alertCount.ToString());
            else Green("0");
            Dim("".PadRight(Math.Max(0, 20 - alertCount.ToString().Length)));
            Dim("│\n");

            Dim("  ├─");
            Dim(new string('─', 68));
            Dim("┤\n");

            // Token rows
            foreach (var t in tokens)
            {
                Dim("  │  ");
                switch (t.Status)
                {
                    case TokenStatus.Watching:
                        Green("● WATCH");
                        break;
                    case TokenStatus.Triggered:
                        Red("⚠ HIT!!");
                        break;
                    case TokenStatus.Missing:
                        Yellow("? GONE ");
                        break;
                    case TokenStatus.Contained:
                        Magenta("✓ STOP!");
                        break;
                }
                Dim("  ");
                var name = t.ShortName.PadRight(32);
                if (t.Status == TokenStatus.Triggered)
                    Red(name);
                else if (t.Status == TokenStatus.Contained)
                    Magenta(name);
                else
                    White(name);

                Dim("  ");
                Dim(t.FileType.ToUpper().PadRight(5));

                if (t.Status == TokenStatus.Triggered)
                {
                    Dim("  ");
                    Red($"TRIGGERS: {t.TriggerCount}");
                    Dim("".PadRight(Math.Max(0, 5 - t.TriggerCount.ToString().Length)));
                }
                else if (t.Status == TokenStatus.Contained)
                {
                    Dim("  ");
                    Magenta("CONTAINED");
                    Dim("               ");
                }
                else
                {
                    Dim($"  dir: {ShortenPath(t.Directory, 18)}");
                }
                Dim("│\n");
            }

            Dim("  └─");
            Dim(new string('─', 68));
            Dim("┘\n");
            Dim("  Press Ctrl+C to stop and remove honeytokens.\n");
            _boardHeight = Console.CursorTop - renderStart;
        }

        public void DrawAlert(HoneytokenAlert alert)
        {
            lock (_consoleLock)
            {
                // Always print below the board — never inside it
                var belowBoard = _boardStartRow + _boardHeight;
                try { if (Console.CursorTop < belowBoard) Console.SetCursorPosition(0, belowBoard); }
                catch { /* CursorTop throws when stdout is redirected — safe to skip */ }
                Console.WriteLine();
                Console.WriteLine();

                var color = alert.RiskLabel switch
                {
                    "CRITICAL" => ConsoleColor.Red,
                    "HIGH"     => ConsoleColor.Red,
                    "MEDIUM"   => ConsoleColor.Yellow,
                    _          => ConsoleColor.Green
                };

                Console.ForegroundColor = color;
                Console.WriteLine($"  ╔══════════════════════════════════════════════════════════════════╗");
                Console.WriteLine($"  ║  ⚠  HONEYTOKEN ALERT [{alert.AlertId}]  —  {alert.RiskLabel} (Score: {alert.RiskScore}/100)  ");
                Console.WriteLine($"  ╚══════════════════════════════════════════════════════════════════╝");
                Console.ResetColor();

                Dim($"  Time      : "); White(alert.Timestamp.ToString("yyyy-MM-dd HH:mm:ss.fff")); Console.WriteLine();
                Dim($"  Event     : "); Yellow(alert.EventType); Console.WriteLine();
                Dim($"  Token     : "); White(alert.TokenFileName); Console.WriteLine();
                Dim($"  Directory : "); White(alert.TokenDirectory); Console.WriteLine();

                if (alert.NewPath != null)
                {
                    Dim($"  Renamed→  : "); Red(alert.NewPath); Console.WriteLine();
                }

                Dim($"  Process   : ");
                if (alert.ProcessName != "unknown")
                {
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.Write($"{alert.ProcessName} (PID: {alert.ProcessId})");
                    Console.ResetColor();
                    if (!alert.IsSigned)
                    {
                        Dim(" ["); Red("UNSIGNED"); Dim("]");
                    }
                    else
                    {
                        Dim(" ["); Green("SIGNED"); Dim("]");
                    }
                }
                else
                {
                    Dim("unknown");
                }
                Console.WriteLine();

                Dim($"  Parent    : "); White($"{alert.ParentProcessName} (PID: {alert.ParentProcessId})"); Console.WriteLine();
                Dim($"  Proc path : "); White(alert.ProcessPath); Console.WriteLine();

                if (alert.EntropyScore >= 0)
                {
                    Dim($"  Entropy   : ");
                    var entropyStr = $"{alert.EntropyScore:F4} bits/byte";
                    if (alert.Indicators.Contains("HIGH_ENTROPY_WRITE"))
                    {
                        Red(entropyStr); Dim("  ["); Red("HIGH_ENTROPY_WRITE"); Dim("]");
                    }
                    else
                    {
                        Green(entropyStr);
                    }
                    Console.WriteLine();
                }

                if (alert.Indicators.Count > 0)
                {
                    Dim($"  Indicators: "); Yellow(string.Join(", ", alert.Indicators)); Console.WriteLine();
                }

                Console.ForegroundColor = color;
                Console.WriteLine($"  ─────────────────────────────────────────────────────────────────");
                Console.ResetColor();
                Console.WriteLine();
            }
        }

        public void DrawBurstAlert(BurstEvent burst)
        {
            lock (_consoleLock)
            {
                var belowBoard = _boardStartRow + _boardHeight;
                try { if (Console.CursorTop < belowBoard) Console.SetCursorPosition(0, belowBoard); }
                catch { /* CursorTop throws when stdout is redirected — safe to skip */ }
                Console.WriteLine();
                Console.WriteLine();

                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("  ╔══════════════════════════════════════════════════════════════════╗");
                Console.WriteLine("  ║  ⚡  ENCRYPTION WAVE DETECTED  —  CRITICAL (Score: 95/100)       ║");
                Console.WriteLine("  ╚══════════════════════════════════════════════════════════════════╝");
                Console.ResetColor();

                Dim("  Time       : "); White(burst.Timestamp.ToString("yyyy-MM-dd HH:mm:ss.fff")); Console.WriteLine();
                Dim("  Events     : "); Red($"{burst.EventCount} file changes"); Dim($" in {burst.WindowSeconds}s window"); Console.WriteLine();
                Dim("  Process    : ");
                if (burst.ProcessName != "unknown")
                    Yellow($"{burst.ProcessName} (PID: {burst.ProcessId})");
                else
                    Dim("unknown");
                Console.WriteLine();

                Dim("  Entropy    : ");
                if (burst.AverageEntropy >= 0)
                {
                    var eStr = $"{burst.AverageEntropy:F4} bits/byte (avg)";
                    if (burst.IsHighEntropy) Red(eStr);
                    else Green(eStr);
                }
                else
                {
                    Dim("not yet measured (rename/delete wave)");
                }
                Console.WriteLine();

                Dim("  Indicator  : "); Yellow("FILE_BURST_ENCRYPTION_WAVE"); Console.WriteLine();

                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("  ─────────────────────────────────────────────────────────────────");
                Console.ResetColor();
                Console.WriteLine();
            }
        }

        public void DrawContainment(ContainmentRecord record)
        {
            lock (_consoleLock)
            {
                var belowBoard = _boardStartRow + _boardHeight;
                try { if (Console.CursorTop < belowBoard) Console.SetCursorPosition(0, belowBoard); }
                catch { /* CursorTop throws when stdout is redirected — safe to skip */ }
                Console.WriteLine();

                Console.ForegroundColor = ConsoleColor.Magenta;
                Console.WriteLine("  ╔══════════════════════════════════════════════════════════════════╗");
                Console.WriteLine($"  ║  ✓  CONTAINMENT APPLIED [{record.AlertId}]  —  {record.Action.ToString().ToUpper().PadRight(10)}              ║");
                Console.WriteLine("  ╚══════════════════════════════════════════════════════════════════╝");
                Console.ResetColor();

                Dim("  Time    : "); White(record.Timestamp.ToString("yyyy-MM-dd HH:mm:ss.fff")); Console.WriteLine();
                Dim("  Action  : ");
                if (record.Action == ContainmentAction.Killed)
                    Red($"Process killed (PID {record.ProcessId} — {record.ProcessName})");
                else if (record.Action == ContainmentAction.Suspended)
                    Yellow($"Process suspended (PID {record.ProcessId} — {record.ProcessName})");
                else
                    Dim("None (process already gone)");
                Console.WriteLine();

                if (record.PathBlocked)
                {
                    Dim("  Path    : "); Magenta(record.ProcessPath); Console.WriteLine();
                    Dim("  Blocked : "); Green("icacls execute deny + Windows Defender scan queued"); Console.WriteLine();
                }

                Dim("  Summary : "); White(record.Summary); Console.WriteLine();

                Console.ForegroundColor = ConsoleColor.Magenta;
                Console.WriteLine("  ─────────────────────────────────────────────────────────────────");
                Console.ResetColor();
                Console.WriteLine();
            }
        }

        public void DrawFusedThreat(FusedThreat threat)
        {
            lock (_consoleLock)
            {
                var belowBoard = _boardStartRow + _boardHeight;
                try { if (Console.CursorTop < belowBoard) Console.SetCursorPosition(0, belowBoard); }
                catch { /* CursorTop throws when stdout is redirected — safe to skip */ }
                Console.WriteLine();
                Console.WriteLine();

                var color = threat.RiskLabel switch
                {
                    "CRITICAL" => ConsoleColor.Red,
                    "HIGH"     => ConsoleColor.Red,
                    "MEDIUM"   => ConsoleColor.Yellow,
                    _          => ConsoleColor.Green
                };

                Console.ForegroundColor = color;
                Console.WriteLine($"  ╔══════════════════════════════════════════════════════════════════╗");
                Console.WriteLine($"  ║  ⚡  MULTI-SIGNAL THREAT [{threat.ThreatId}]  —  {threat.RiskLabel} ({threat.FusedScore}/100)  ");
                Console.WriteLine($"  ╚══════════════════════════════════════════════════════════════════╝");
                Console.ResetColor();

                Dim($"  Time      : "); White(threat.Timestamp.ToString("yyyy-MM-dd HH:mm:ss.fff")); Console.WriteLine();
                Dim($"  Process   : "); Yellow($"{threat.ProcessName} (PID: {threat.ProcessId})"); Console.WriteLine();
                Dim($"  Path      : "); White(threat.ProcessPath); Console.WriteLine();
                Dim($"  Sources   : "); Yellow(threat.ActiveSources); Console.WriteLine();

                foreach (var sig in threat.ContributingSignals)
                {
                    Dim($"    [{sig.Source,-14}] score={sig.RawScore:F2}  ");
                    if (sig.Indicators.Count > 0)
                        Yellow(string.Join(", ", sig.Indicators));
                    Console.WriteLine();
                }

                Console.ForegroundColor = color;
                Console.WriteLine($"  ─────────────────────────────────────────────────────────────────");
                Console.ResetColor();
                Console.WriteLine();
            }
        }

        private static string ShortenPath(string path, int maxLen)
        {
            if (path.Length <= maxLen) return path.PadRight(maxLen);
            return "..." + path[^(maxLen - 3)..];
        }
    }
}
