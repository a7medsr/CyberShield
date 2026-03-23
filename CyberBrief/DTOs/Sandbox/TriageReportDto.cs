namespace CyberBrief.DTOs.Sandbox
{
    public class TriageReportDto
    {
        public string SampleId { get; set; }
        public int Score { get; set; }
        public string Target { get; set; }
        public List<string> Tags { get; set; } = new();
        public List<SignatureDto> HighRiskSignatures { get; set; } = new();
        public List<string> FoundIps { get; set; } = new();
        public List<string> FoundDomains { get; set; } = new();
    }
}
