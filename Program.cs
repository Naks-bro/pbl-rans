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
            Console.CursorVisible = false;

            var cts = new CancellationTokenSource();

            Console.CancelKeyPress += (s, e) =>
            {
                e.Cancel = true;
                cts.Cancel();
            };

            var engine = new DeceptionEngine();
            engine.Run(cts.Token);
        }
    }
}
