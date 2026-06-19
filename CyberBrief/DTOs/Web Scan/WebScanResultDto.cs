namespace CyberBrief.DTOs.Web_Scan
{
    public class WebScanResultDto
    {
        public string ScanId { get; set; } = string.Empty;
        public string Target { get; set; } = string.Empty;
        public string Status { get; set; } = string.Empty;

        public int TotalFindings { get; set; }
        public int CriticalCount { get; set; }
        public int HighCount { get; set; }
        public int MediumCount { get; set; }
        public int LowCount { get; set; }
        public int InfoCount { get; set; }

        public List<WebFindingDto> Findings { get; set; } = new();
    }
}
