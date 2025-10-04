namespace CyberBrief.Models.Sandbox
{
    public class TriageTaskDto
    {
        public string Kind { get; set; }
        public string Status { get; set; }
        public List<string> Tags { get; set; }
        public int Score { get; set; }
        public string Target { get; set; }
    }
}
