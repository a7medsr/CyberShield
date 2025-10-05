using CyberBrief.Dtos.URLModels;

namespace CyberBrief.Services.IServices
{
    public interface ISafetyAnalyzerService
    {
        SafetyAnalysisResultDto AnalyzeUrlSafety(string url, List<string> redirectionChain);
        Task<SafetyAnalysisResultDto> AnalyzeUrlSafetyAsync(string url, List<string> redirectionChain);
    }
}
