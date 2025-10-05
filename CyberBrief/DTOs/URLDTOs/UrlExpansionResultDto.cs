namespace CyberBrief.Dtos.URLModels
{
    public class UrlExpansionResultDto
    {
        public string? FinalUrl { get; set; }
        public List<string> RedirectionLinks { get; set; } = new List<string>();
        public bool IsSuccess { get; set; }
        public string? ErrorMessage { get; set; }
        public SafetyAnalysisResultDto? SafetyAnalysis { get; set; }

    }
}
