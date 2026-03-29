namespace CyberBrief.Dtos.URLModels
{
    public class SafetyAnalysisResultDto
    {
        public bool IsSafe { get; set; } = true;
        public string SafetyLevel { get; set; } = "Unknown";
        public string Message { get; set; } = string.Empty;

        public int VtScore { get; set; }   // 0–4
        public int GsbScore { get; set; }  // 0–3
        public int MlScore { get; set; }   // 0–3

        public int ThreatScore => VtScore + GsbScore + MlScore;

        public List<string> Warnings { get; set; } = new();
        public List<string> RedFlags { get; set; } = new();

        public string? ModelVerdict { get; set; }
        public double ModelConfidence { get; set; }
        public List<string> ModelFlags { get; set; } = new();
    }
}
