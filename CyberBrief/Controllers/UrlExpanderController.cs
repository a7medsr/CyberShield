using CyberBrief.Context;
using CyberBrief.Models.Url_shalow_scanning;
using CyberBrief.Services.IServices;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.Text.Json;

namespace CyberBrief.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UrlExpanderController : ControllerBase
    {
        private readonly IUrlExpanderService _urlExpanderService;
        private readonly CyberBriefDbContext _db;

        public UrlExpanderController(IUrlExpanderService urlExpanderService, CyberBriefDbContext db)
        {
            _urlExpanderService = urlExpanderService;
            _db = db;
        }

        [HttpGet("extract")]
        public async Task<IActionResult> Extract([FromQuery] string url)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(url))
                    return BadRequest(new { error = "No URL provided" });

                // Check if we already have a result for this URL
                var cached = await _db.UrlAnalysisRecords.FindAsync(url);
                if (cached is not null)
                    return Ok(JsonSerializer.Deserialize<object>(cached.ResultJson));

                var result = await _urlExpanderService.ExtractShortUrlAsync(url);

                if (!result.IsSuccess)
                {
                    return StatusCode(500, new
                    {
                        error = "Failed to expand the URL",
                        message = result.ErrorMessage,
                        details = result.RedirectionLinks
                    });
                }

                // Build the response object
                var response = new
                {
                    Status = "Success",
                    OriginalURL = url,
                    ExpandedURL = result.FinalUrl,
                    RedirectChain = result.RedirectionLinks,
                    RedirectCount = result.RedirectionLinks.Count,
                    SecurityAnalysis = new
                    {
                        IsSafe = result.SafetyAnalysis?.IsSafe ?? false,
                        ThreatLevel = result.SafetyAnalysis?.SafetyLevel ?? "Unknown",
                        Message = result.SafetyAnalysis?.Message ?? "Analysis unavailable",
                        Warnings = result.SafetyAnalysis?.Warnings ?? new List<string>(),
                        RedFlags = result.SafetyAnalysis?.RedFlags ?? new List<string>(),
                        WarningCount = result.SafetyAnalysis?.Warnings?.Count ?? 0,
                        RedFlagCount = result.SafetyAnalysis?.RedFlags?.Count ?? 0
                    },
                    ProcessedAt = DateTime.UtcNow
                };

                // Save to DB
                _db.UrlAnalysisRecords.Add(new UrlAnalysisRecord
                {
                    Url = url,
                    ResultJson = JsonSerializer.Serialize(response),
                    AnalyzedAt = DateTime.UtcNow
                });
                await _db.SaveChangesAsync();

                return Ok(response);
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { error = "Internal server error", message = ex.Message });
            }
        }
    }
}