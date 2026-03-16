using System;
using System.Threading;
using HoneytokenWatcher.Core;

namespace HoneytokenWatcher
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.OutputEncoding = System.Text.Encoding.UTF8;
            try { Console.CursorVisible = false; } catch { }

            var cts = new CancellationTokenSource();

            Console.CancelKeyPress += (s, e) =>
            {
                e.Cancel = true;
                cts.Cancel();
            };

            try
            {
                // 1. Plant honeytokens
                // 2. Start watchers
                // 3. Initialize alert manager
                // 4. Start console UI
                // 5. Wait for Ctrl+C
                // 6. Cleanup tokens
                // (All steps are orchestrated inside DeceptionEngine.Run)
                var engine = new DeceptionEngine();
                engine.Run(cts.Token);
            }
            catch (Exception ex)
            {
                Console.ResetColor();
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"\n[FATAL] Unhandled error: {ex.Message}");
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
