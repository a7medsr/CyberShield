using CyberBrief.DTOs.Dashboard;

namespace CyberBrief.Services.IServices
{
    public interface IDashboardService
    {
        Task<List<UrlsScoresDto>> AllScannedUrls();
    }
}
