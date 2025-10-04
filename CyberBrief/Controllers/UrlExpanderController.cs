using CyberBrief.Services.IServices;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace CyberBrief.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UrlExpanderController : ControllerBase
    {
        private readonly IUrlExpanderService _urlExpanderService;

        public UrlExpanderController(IUrlExpanderService urlExpanderService)
        {
            _urlExpanderService = urlExpanderService;
        }

        [HttpGet("extract")]
        public async Task<IActionResult> Extract([FromQuery] string url)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(url))
                {
                    return BadRequest(new { error = "No URL provided" });
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

                // Return comprehensive response
                return Ok(new
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
                });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new
                {
                    error = "Internal server error",
                    message = ex.Message
                });
            }
        }

   
    }
}