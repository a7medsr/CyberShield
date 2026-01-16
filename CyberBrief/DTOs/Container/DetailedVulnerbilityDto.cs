namespace CyberBrief.DTOs.Container
{
    public class DetailedVulnerbilityDto
    {
        public string Package { get; set; }
        public string Vulnerability { get; set; }
        public string Severity { get; set; }
        public string Source { get; set; }

        public string? Exploration { get; set; }
        public string? Batch { get; set; }
    }
}
