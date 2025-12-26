namespace CyberBrief.DTOs.Container
{
    public class ScanResultDto
    {
        public string Id { get; set; }
        public string Name { get; set; }
        public string Tag { get; set; }
        public DateTime StartedAt { get; set; }
        public DateTime FinishedAt { get; set; }
        public VulnerabilityCountsDto Counts { get; set; }
        public List<VulnerabilityDto> Vulnerabilities { get; set; }
    }
}
