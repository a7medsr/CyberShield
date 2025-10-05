namespace CyberBrief.Dtos.Sandbox
{
    public class TriageSummaryDto
    {
        public string Sample { get; set; }
        public string Status { get; set; }
        public string Target { get; set; }
        public int Score { get; set; }
        public Dictionary<string, TriageTaskDto> Tasks { get; set; }
    }
}
