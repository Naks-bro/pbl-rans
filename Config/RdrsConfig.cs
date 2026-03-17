namespace HoneytokenWatcher.Config
{
    public enum ContainmentMode
    {
        KillAndSuspend,   // suspend then kill (default)
        SuspendOnly,      // freeze process but do not terminate
        AlertOnly,        // log and notify only — no process action
    }

    public enum NotificationLevel
    {
        Critical,   // balloon only for CRITICAL alerts (default)
        High,       // CRITICAL + HIGH
        All,        // every alert
    }

    public class RdrsConfig
    {
        public bool              EnableHoneytokens  { get; set; } = true;
        public bool              EnableEtwMonitor   { get; set; } = true;
        public bool              EnableNetworkMonitor { get; set; } = true;
        public ContainmentMode   ContainmentMode    { get; set; } = ContainmentMode.KillAndSuspend;
        public NotificationLevel NotificationLevel  { get; set; } = NotificationLevel.Critical;
    }
}
