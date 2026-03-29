using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Threading;
using System.Windows.Forms;
using HoneytokenWatcher.Config;
using HoneytokenWatcher.Core;
using HoneytokenWatcher.UI;

namespace HoneytokenWatcher
{
    class Program
    {
        [DllImport("kernel32.dll")]
        private static extern bool AllocConsole();

        [STAThread]
        static void Main(string[] args)
        {
            // ── Self-elevate if not already running as Administrator ───────────
            // Belt-and-suspenders alongside app.manifest requireAdministrator.
            // Catches cases where the manifest UAC prompt was skipped or bypassed.
            if (!IsAdmin())
            {
                try
                {
                    var psi = new ProcessStartInfo
                    {
                        FileName        = Process.GetCurrentProcess().MainModule?.FileName
                                          ?? System.Reflection.Assembly.GetExecutingAssembly().Location,
                        Verb            = "runas",
                        UseShellExecute = true,
                    };
                    // Forward original arguments to the elevated instance
                    foreach (var a in args) psi.ArgumentList.Add(a);
                    Process.Start(psi);
                }
                catch { /* user cancelled UAC — exit silently */ }
                return;
            }

            // ── Elevated from here ─────────────────────────────────────────────
            var config = ConfigManager.Load();

            bool consoleMode = Array.Exists(args,
                a => a.Equals("--console", StringComparison.OrdinalIgnoreCase));

            if (consoleMode)
            {
                AllocConsole();
                RunConsoleMode(config);
            }
            else
            {
                Application.SetHighDpiMode(HighDpiMode.SystemAware);
                Application.SetCompatibleTextRenderingDefault(false);
                SynchronizationContext.SetSynchronizationContext(
                    new System.Windows.Forms.WindowsFormsSynchronizationContext());
                Application.Run(new TrayApplication(config));
            }
        }

        private static bool IsAdmin()
        {
            using var identity = WindowsIdentity.GetCurrent();
            return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
        }

        // ── Console mode (--console flag) ─────────────────────────────────────

        private static void RunConsoleMode(RdrsConfig config)
        {
            Console.OutputEncoding = System.Text.Encoding.UTF8;
            try { Console.CursorVisible = false; } catch { }

            var cts = new CancellationTokenSource();
            Console.CancelKeyPress += (s, e) => { e.Cancel = true; cts.Cancel(); };

            try
            {
                var engine = new DeceptionEngine(config);
                engine.Run(cts.Token);
            }
            catch (Exception ex)
            {
                Console.ResetColor();
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"\n[FATAL] {ex.Message}");
                Console.ResetColor();
                Environment.Exit(1);
            }
            finally
            {
                try { Console.CursorVisible = true; } catch { }
            }
        }
    }
}
