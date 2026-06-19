namespace CyberBrief.Models.Web_Scaning
{
    /// <summary>
    /// Structured result of a web scan, mirroring the container <c>Summary</c>.
    /// One per <see cref="ScanRecord"/>, holding severity counts and the parsed
    /// findings (one row per finding, one row per CVE for vulners blocks).
    /// </summary>
    public class WebScanSummary
    {
        public string Id { get; set; } = string.Empty;

        public string ScanRecordId { get; set; } = string.Empty;
        public ScanRecord ScanRecord { get; set; } = null!;

        public DateTime StartedAt { get; set; } = DateTime.UtcNow;
        public DateTime FinishedAt { get; set; } = DateTime.UtcNow;

        public int TotalFindings { get; set; }
        public int CriticalCount { get; set; }
        public int HighCount { get; set; }
        public int MediumCount { get; set; }
        public int LowCount { get; set; }
        public int InfoCount { get; set; }

        public ICollection<WebFinding> Findings { get; set; } = new List<WebFinding>();
    }
}
