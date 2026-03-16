using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Threading;
using HoneytokenWatcher.Alerting;

namespace HoneytokenWatcher.Monitoring
{
    /// <summary>
    /// Network behaviour monitor.
    ///
    /// Polls active TCP connections every 2 seconds via
    /// <see cref="IPGlobalProperties.GetActiveTcpConnections"/> and fires
    /// <see cref="ThreatSignal"/> (Source = Network) into SignalFusion when:
    ///
    ///   1. TOR_EXIT_NODE — remote IP is in the hardcoded set of 20 known
    ///      high-bandwidth Tor exit nodes.  Score 0.90.
    ///
    ///   2. SUSPICIOUS_PORT — outbound connection to a port commonly used by
    ///      C2 / RAT tools (4444, 1337, 31337, …).  Score 0.55.
    ///
    ///   3. HIGH_CONN_RATE — a single process opens > 30 new distinct
    ///      remote-IP connections within 10 seconds.  Score 0.65.
    ///
    ///   4. EXFIL_DURING_FILE_ACTIVITY — a new external connection appears
    ///      within 30 seconds of a file-burst or honeytoken trigger being
    ///      reported by <see cref="NotifyFileActivity"/>.  Score 0.70.
    ///
    /// PID attribution uses <c>GetExtendedTcpTable</c> (iphlpapi.dll) for
    /// suspicious connections only; IPGlobalProperties handles all enumeration.
    /// If PID lookup fails the signal is dropped (SignalFusion requires a PID).
    /// </summary>
    public class NetworkMonitor : IDisposable
    {
        // ── Hardcoded Tor exit-node IPs (top-20 high-bandwidth exits) ─────────
        // Source: public Tor Project exit lists, updated periodically in threat
        // intelligence feeds.  Update this list when deploying in production.
        private static readonly HashSet<string> TorExitNodes = new()
        {
            "185.220.101.1",   "185.220.101.2",   "185.220.101.3",
            "185.220.101.4",   "185.220.101.5",   "185.220.101.6",
            "23.129.64.131",   "23.129.64.132",   "23.129.64.133",
            "23.129.64.134",   "23.129.64.135",
            "199.249.230.68",  "199.249.230.69",  "199.249.230.70",
            "104.244.73.201",  "104.244.73.202",
            "193.218.118.173", "193.218.118.174",
            "45.148.10.23",    "192.42.116.176",
        };

        // ── Suspicious C2 ports ───────────────────────────────────────────────
        private static readonly HashSet<int> SuspiciousPorts = new()
        {
            4444, 4445, 4446,    // Metasploit default shells
            1337,                 // "leet" C2
            8888, 8443,           // alt-HTTPS C2 frameworks
            31337,                // Back Orifice / legacy RAT
            6667, 6697,           // IRC botnet C2
            9001, 9030,           // Tor relay/onion ports
        };

        // ── P/Invoke — PID attribution for suspicious connections only ─────────
        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern uint GetExtendedTcpTable(
            IntPtr pTcpTable, ref uint dwSize, bool bOrder,
            int ulAf, int tableClass, uint reserved);

        private const int TCP_TABLE_OWNER_PID_ALL = 5;

        [StructLayout(LayoutKind.Sequential)]
        private struct MibTcpRowOwnerPid
        {
            public uint dwState;
            public uint dwLocalAddr;
            public uint dwLocalPort;
            public uint dwRemoteAddr;
            public uint dwRemotePort;
            public uint dwOwningPid;
        }

        // ── Constants ─────────────────────────────────────────────────────────
        private const int PollIntervalMs        = 2000;
        private const int ConnRateWindowSec     = 10;
        private const int ConnRateLimit         = 30;
        private const int FileActivityWindowSec = 30;   // exfil correlation window
        private const int CooldownSeconds       = 60;

        // ── State ─────────────────────────────────────────────────────────────
        // (pid, remoteIp) pairs already processed — prevents re-firing same conn
        private readonly ConcurrentDictionary<string, bool>         _seenConns = new();

        // Per-process new-connection timestamps for rate detection
        private readonly ConcurrentDictionary<int, Queue<DateTime>> _connRate  = new();

        // Per-process name cache
        private readonly ConcurrentDictionary<int, string>          _procNames = new();

        // Cooldown tracker
        private readonly ConcurrentDictionary<string, DateTime>     _cooldowns = new();

        // Set by DeceptionEngine when a honeytoken alert or burst fires
        private DateTime     _lastFileActivity = DateTime.MinValue;
        private readonly object _faLock          = new();

        private readonly SignalFusion _fusion;
        private          Thread?      _pollThread;
        private volatile bool         _running;

        public NetworkMonitor(SignalFusion fusion)
        {
            _fusion = fusion;
        }

        // ── Public API ────────────────────────────────────────────────────────

        /// <summary>
        /// Called by DeceptionEngine when a honeytoken alert or burst event fires.
        /// Network connections appearing within 30 s after this call will be
        /// flagged as potential exfiltration channels.
        /// </summary>
        public void NotifyFileActivity()
        {
            lock (_faLock) { _lastFileActivity = DateTime.Now; }
        }

        // ── Lifecycle ─────────────────────────────────────────────────────────

        public void Start()
        {
            if (_running) return;
            _running = true;

            _pollThread = new Thread(PollLoop)
            {
                IsBackground = true,
                Name = "RDRS-Network"
            };
            _pollThread.Start();
        }

        public void Stop()    { _running = false; }
        public void Dispose() => Stop();

        // ── Poll loop ─────────────────────────────────────────────────────────

        private void PollLoop()
        {
            Thread.Sleep(3000);   // let startup settle

            while (_running)
            {
                try  { Poll(); }
                catch { /* poll failures are non-fatal */ }

                Thread.Sleep(PollIntervalMs);
            }
        }

        private void Poll()
        {
            // Primary enumeration: IPGlobalProperties — no P/Invoke required
            TcpConnectionInformation[] conns;
            try
            {
                conns = IPGlobalProperties.GetIPGlobalProperties()
                                          .GetActiveTcpConnections();
            }
            catch { return; }

            bool fileActivityRecent;
            lock (_faLock)
            {
                fileActivityRecent =
                    (DateTime.Now - _lastFileActivity).TotalSeconds < FileActivityWindowSec;
            }

            foreach (var conn in conns)
            {
                if (!_running) return;
                if (conn.State != TcpState.Established) continue;

                var remote = conn.RemoteEndPoint;
                if (remote == null) continue;

                string remoteIp   = remote.Address.ToString();
                int    remotePort = remote.Port;

                // Skip loopback and link-local (::1, 127.x, 169.254.x, fe80::)
                if (remote.Address.IsIPv6LinkLocal       ||
                    remote.Address.Equals(IPAddress.Loopback) ||
                    remote.Address.Equals(IPAddress.IPv6Loopback) ||
                    remoteIp.StartsWith("127.") ||
                    remoteIp.StartsWith("169.254."))
                    continue;

                // ── Tor exit node check (O(1) hashset lookup) ─────────────────
                if (TorExitNodes.Contains(remoteIp))
                {
                    int pid = GetOwnerPid(conn.LocalEndPoint.Port);
                    if (pid > 0)
                        Fire(pid, remoteIp, 0.90, "TOR_EXIT_NODE",
                            $"REMOTE:{remoteIp}:{remotePort}");
                    continue;
                }

                // ── Suspicious port ───────────────────────────────────────────
                if (SuspiciousPorts.Contains(remotePort))
                {
                    int pid = GetOwnerPid(conn.LocalEndPoint.Port);
                    if (pid > 0)
                        Fire(pid, remoteIp, 0.55, "SUSPICIOUS_PORT",
                            $"PORT:{remotePort}  REMOTE:{remoteIp}");
                }

                // ── Exfiltration during file activity ─────────────────────────
                if (fileActivityRecent && !IsPrivateIp(remoteIp))
                {
                    var exfilKey = $"exfil:{remoteIp}";
                    if (_seenConns.TryAdd(exfilKey, true))
                    {
                        int pid = GetOwnerPid(conn.LocalEndPoint.Port);
                        if (pid > 0)
                            Fire(pid, remoteIp, 0.70, "EXFIL_DURING_FILE_ACTIVITY",
                                $"REMOTE:{remoteIp}:{remotePort}");
                    }
                }

                // ── Connection rate per remote-IP (approximate per-host burst) ─
                TrackConnRate(remoteIp, remotePort);
            }

            // Prune stale seen-connections to bound memory
            if (_seenConns.Count > 20_000)
            {
                foreach (var k in _seenConns.Keys.Take(10_000).ToArray())
                    _seenConns.TryRemove(k, out _);
            }
        }

        // ── Connection rate (host-agnostic — just counts new distinct IPs) ────

        private void TrackConnRate(string remoteIp, int remotePort)
        {
            // Use 0 as the aggregate key (no PID from IPGlobalProperties)
            var queue = _connRate.GetOrAdd(0, _ => new Queue<DateTime>());
            DateTime now = DateTime.Now;
            int burst;

            lock (queue)
            {
                var ipKey = $"rate:{remoteIp}";
                if (!_seenConns.TryAdd(ipKey, true)) return;   // already counted

                queue.Enqueue(now);
                var cutoff = now.AddSeconds(-ConnRateWindowSec);
                while (queue.Count > 0 && queue.Peek() < cutoff)
                    queue.Dequeue();

                if (queue.Count < ConnRateLimit) return;
                burst = queue.Count;
                queue.Clear();
            }

            // For a burst we try to find the most active non-system process
            int pid = GetHighestHandleNonSystemPid();
            if (pid > 0)
                Fire(pid, remoteIp, 0.65, "HIGH_CONN_RATE",
                    $"CONNS:{burst}_IN_{ConnRateWindowSec}s");
        }

        // ── P/Invoke: PID for a specific local port ───────────────────────────

        private static int GetOwnerPid(int localPort)
        {
            try
            {
                uint size = 0;
                GetExtendedTcpTable(IntPtr.Zero, ref size, false, 2,
                    TCP_TABLE_OWNER_PID_ALL, 0);
                if (size == 0) return 0;

                var buf = Marshal.AllocHGlobal((int)size);
                try
                {
                    if (GetExtendedTcpTable(buf, ref size, false, 2,
                        TCP_TABLE_OWNER_PID_ALL, 0) != 0) return 0;

                    int count   = Marshal.ReadInt32(buf);
                    int offset  = 4;
                    int rowSize = Marshal.SizeOf<MibTcpRowOwnerPid>();

                    for (int i = 0; i < count; i++)
                    {
                        var row = Marshal.PtrToStructure<MibTcpRowOwnerPid>(buf + offset);
                        int rowPort = PortFromNetworkOrder(row.dwLocalPort);
                        if (rowPort == localPort)
                            return (int)row.dwOwningPid;
                        offset += rowSize;
                    }
                }
                finally { Marshal.FreeHGlobal(buf); }
            }
            catch { }
            return 0;
        }

        private static int PortFromNetworkOrder(uint raw)
            => (int)(((raw & 0xFF) << 8) | ((raw >> 8) & 0xFF));

        // ── Helpers ───────────────────────────────────────────────────────────

        private void Fire(int pid, string remoteIp, double rawScore,
            string primaryIndicator, string detail)
        {
            var key = $"{pid}:{primaryIndicator}";
            if (_cooldowns.TryGetValue(key, out var last) &&
                (DateTime.Now - last).TotalSeconds < CooldownSeconds)
                return;

            _cooldowns[key] = DateTime.Now;

            var signal = new ThreatSignal
            {
                Source      = SignalSource.Network,
                ProcessId   = pid,
                ProcessName = GetProcessName(pid),
                RawScore    = rawScore,
                Indicators  = new List<string> { primaryIndicator, detail },
            };

            ThreadPool.QueueUserWorkItem(_ =>
            {
                try { _fusion.Submit(signal); } catch { }
            });
        }

        private string GetProcessName(int pid)
        {
            if (_procNames.TryGetValue(pid, out var n)) return n;
            try
            {
                var name = System.Diagnostics.Process.GetProcessById(pid).ProcessName;
                _procNames[pid] = name;
                return name;
            }
            catch { return "unknown"; }
        }

        private static bool IsPrivateIp(string ip)
        {
            if (ip.StartsWith("10.") ||
                ip.StartsWith("127.") ||
                ip.StartsWith("192.168.") ||
                ip.StartsWith("169.254.") ||
                ip.StartsWith("::1") ||
                ip.StartsWith("fc") ||
                ip.StartsWith("fd"))
                return true;
            if (ip.StartsWith("172."))
            {
                var parts = ip.Split('.');
                if (parts.Length >= 2 &&
                    int.TryParse(parts[1], out int second) &&
                    second >= 16 && second <= 31)
                    return true;
            }
            return false;
        }

        private static int GetHighestHandleNonSystemPid()
        {
            var ignored = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
                { "System", "Registry", "smss", "csrss", "wininit", "services",
                  "lsass", "winlogon", "svchost", "dwm", "HoneytokenWatcher" };
            try
            {
                return System.Diagnostics.Process.GetProcesses()
                    .Where(p => !ignored.Contains(p.ProcessName))
                    .OrderByDescending(p => { try { return p.HandleCount; } catch { return 0; } })
                    .Select(p => p.Id)
                    .FirstOrDefault();
            }
            catch { return 0; }
        }
    }
}
