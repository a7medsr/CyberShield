namespace CyberBrief.Models.URLModels
{
    public class SafetyAnalysisResultDto
    {
        public bool IsSafe { get; set; }
        public string SafetyLevel { get; set; } = "Unknown";
        public List<string> Warnings { get; set; } = new List<string>();
        public List<string> RedFlags { get; set; } = new List<string>();
        public string Message { get; set; } = string.Empty;
    }
}
