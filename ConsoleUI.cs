using System;
using System.Collections.Generic;
using System.Linq;
using HoneytokenWatcher.Alerting;
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
        private static void Green(string s)  { Console.ForegroundColor = ConsoleColor.Green;   Console.Write(s); Console.ResetColor(); }
        private static void Red(string s)    { Console.ForegroundColor = ConsoleColor.Red;     Console.Write(s); Console.ResetColor(); }
        private static void Yellow(string s) { Console.ForegroundColor = ConsoleColor.Yellow;  Console.Write(s); Console.ResetColor(); }
        private static void Cyan(string s)   { Console.ForegroundColor = ConsoleColor.Cyan;    Console.Write(s); Console.ResetColor(); }
        private static void Dim(string s)    { Console.ForegroundColor = ConsoleColor.DarkGray; Console.Write(s); Console.ResetColor(); }
        private static void White(string s)  { Console.ForegroundColor = ConsoleColor.White;   Console.Write(s); Console.ResetColor(); }

        public void DrawBanner()
        {
            Console.Clear();
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
                for (int i = 0; i < _boardHeight; i++)
                {
                    Console.SetCursorPosition(0, renderStart + i);
                    Console.Write(new string(' ', Console.WindowWidth));
                }
                Console.SetCursorPosition(0, renderStart);
            }

            var now = DateTime.Now.ToString("HH:mm:ss");
            var watching = tokens.Count(t => t.Status == TokenStatus.Watching);
            var triggered = tokens.Count(t => t.Status == TokenStatus.Triggered);

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
            Dim($"   Alerts logged: ");
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
                }
                Dim("  ");
                var name = t.ShortName.PadRight(32);
                if (t.Status == TokenStatus.Triggered)
                    Red(name);
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
                if (Console.CursorTop < belowBoard)
                    Console.SetCursorPosition(0, belowBoard);
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

        private static string ShortenPath(string path, int maxLen)
        {
            if (path.Length <= maxLen) return path.PadRight(maxLen);
            return "..." + path[^(maxLen - 3)..];
        }
    }
}
