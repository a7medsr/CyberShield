using CyberBrief.Context;
using CyberBrief.DTOs.Dashboard;
using CyberBrief.Services.IServices;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace CyberBrief.Services.Dashboard_Services
{
    public class DashboardService: IDashboardService
    {
        private readonly CyberBriefDbContext _Context;
        public DashboardService(CyberBriefDbContext context)
        {
            _Context = context;
        }
        public async Task<List<UrlsScoresDto>> AllScannedUrls()
        {
            var l1 = await _Context.UrlAnalysisRecords
                .Select(r => new { r.Url, Score = r.VtScore + r.GsbScore + r.MlScore })
                .ToListAsync();

            var l2 = await _Context.TriageCaches
                .Select(x => new { x.ResourceHash, x.Score })
                .ToListAsync();

            var mp = new Dictionary<string, int?>();
            var result = new List<UrlsScoresDto>();

            foreach (var l in l2)
            {
                mp[l.ResourceHash] = l.Score;
                result.Add(new UrlsScoresDto { Url = l.ResourceHash, Score = l.Score });
            }

            foreach (var l in l1)
            {
                if (!mp.ContainsKey(l.Url))
                {
                    mp[l.Url] = l.Score;
                    result.Add(new UrlsScoresDto { Url = l.Url, Score = l.Score });
                }
            }

            return result;
        }
    }
}
