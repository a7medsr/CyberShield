namespace CyberBrief.DTOs.Web_Scan
{
    public class WebFindingDto
    {
        public string Source { get; set; } = string.Empty;
        public string? Cve { get; set; }
        public string Issue { get; set; } = string.Empty;
        public string Severity { get; set; } = string.Empty;
        public string? Endpoint { get; set; }
        public string? Description { get; set; }
        public string? Explanation { get; set; }
        public string? Patch { get; set; }
        public string? ReferenceUrl { get; set; }
    }
}
