using CyberBrief.Context;
using CyberBrief.Models.Url_shalow_scanning;
using CyberBrief.Services.IServices;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;
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
        [Authorize]  // ← added
        public async Task<IActionResult> Extract([FromQuery] string url)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(url))
                    return BadRequest(new { error = "No URL provided" });

                var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);

                var cached = await _db.UrlAnalysisRecords
                    .Include(r => r.Users)
                    .FirstOrDefaultAsync(r => r.Url == url);

                if (cached is not null)
                {
                    await LinkToUserAsync(cached, userId);

                    // inject live score data from the DB columns into the cached response
                    var cachedResult = JsonSerializer.Deserialize<JsonElement>(cached.ResultJson);
                    return Ok(new
                    {
                        Cached = true,
                        ThreatScore = cached.ThreatScore,
                        ThreatLevel = cached.ThreatLevel,
                        Data = cachedResult
                    });
                }
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
                        ThreatScore = result.SafetyAnalysis?.ThreatScore ?? 0,
                        ScoreBreakdown = new
                        {
                            VirusTotal = result.SafetyAnalysis?.VtScore ?? 0,
                            GoogleSafeBrowsing = result.SafetyAnalysis?.GsbScore ?? 0,
                            MlModel = result.SafetyAnalysis?.MlScore ?? 0,
                        },
                        Message = result.SafetyAnalysis?.Message ?? "Analysis unavailable",
                        Warnings = result.SafetyAnalysis?.Warnings ?? new List<string>(),
                        RedFlags = result.SafetyAnalysis?.RedFlags ?? new List<string>(),
                        WarningCount = result.SafetyAnalysis?.Warnings?.Count ?? 0,
                        RedFlagCount = result.SafetyAnalysis?.RedFlags?.Count ?? 0
                    },
                    ProcessedAt = DateTime.UtcNow
                };

                var record = new UrlAnalysisRecord
                {
                    Url = url,
                    ResultJson = JsonSerializer.Serialize(response),
                    AnalyzedAt = DateTime.UtcNow,

                    VtScore = result.SafetyAnalysis?.VtScore ?? 0,
                    GsbScore = result.SafetyAnalysis?.GsbScore ?? 0,
                    MlScore = result.SafetyAnalysis?.MlScore ?? 0,
                    ThreatLevel = result.SafetyAnalysis?.SafetyLevel ?? "Unknown"
                };

                _db.UrlAnalysisRecords.Add(record);
                await _db.SaveChangesAsync();

                await LinkToUserAsync(record, userId);

                return Ok(response);
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { error = "Internal server error", message = ex.Message });
            }
        }

        [HttpGet("my-history")]
        [Authorize]
        public async Task<IActionResult> MyHistory()
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);

            // ← fetch first, then deserialize in memory (fixes CS0854)
            var records = await _db.UrlAnalysisRecords
                .Include(r => r.Users)
                .Where(r => r.Users.Any(u => u.Id == userId))
                .OrderByDescending(r => r.AnalyzedAt)
                .Select(r => new
                {
                    r.Url,
                    r.AnalyzedAt,
                    r.ResultJson      // ← pull raw string from DB
                })
                .ToListAsync();

            // ← deserialize AFTER the query, in memory
            var result = records.Select(r => new
            {
                r.Url,
                r.AnalyzedAt,
                Result = JsonSerializer.Deserialize<object>(r.ResultJson)
            });

            return Ok(result);
        }

        // ── private helper ────────────────────────────────────────────────────
        private async Task LinkToUserAsync(UrlAnalysisRecord record, string? userId)
        {
            if (userId is null) return;

            // avoid duplicate link
            var alreadyLinked = record.Users.Any(u => u.Id == userId);
            if (alreadyLinked) return;

            var user = await _db.Users.FindAsync(userId);
            if (user is null) return;

            record.Users.Add(user);
            await _db.SaveChangesAsync();
        }
    }
}