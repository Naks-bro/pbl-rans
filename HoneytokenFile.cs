using System;

namespace HoneytokenWatcher.Honeytokens
{
    public enum TokenStatus
    {
        Watching,
        Triggered,
        Missing,    // deleted by attacker
        Contained   // attacker process was killed/suspended by containment
    }

    public class HoneytokenFile
    {
        public string FullPath { get; set; } = "";
        public string FileName { get; set; } = "";
        public string Directory { get; set; } = "";
        public string FileType { get; set; } = "";   // docx, pdf, jpg, etc.
        public long FileSizeBytes { get; set; }
        public DateTime PlantedAt { get; set; }
        public TokenStatus Status { get; set; } = TokenStatus.Watching;
        public DateTime? TriggeredAt { get; set; }
        public int TriggerCount { get; set; } = 0;

        public string ShortName => FileName.Length > 28
            ? FileName[..25] + "..."
            : FileName;
    }
}
