namespace CyberBrief.Dtos.URLModels
{
    public class SafetyAnalysisResultDto
    {
        public bool IsSafe { get; set; }
        public string SafetyLevel { get; set; } = "Unknown";
        public List<string> Warnings { get; set; } = new List<string>();
        public List<string> RedFlags { get; set; } = new List<string>();
        public string Message { get; set; } = string.Empty;

        // Model prediction result
        public string? ModelVerdict { get; set; }
        public double? ModelConfidence { get; set; }
        public List<string> ModelFlags { get; set; } = new();
    }
}
