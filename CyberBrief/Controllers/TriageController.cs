using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;
using CyberBrief.Services;
using CyberBrief.Context;
using System.Security.Claims;
using System.Text.Json;

namespace CyberBrief.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class TriageController : ControllerBase
    {
        private readonly TriageService _triageService;
        private readonly CyberBriefDbContext _db;

        public TriageController(TriageService triageService, CyberBriefDbContext db)
        {
            _triageService = triageService;
            _db = db;
        }

        [HttpPost("url")]
        [Authorize]                          // ← added
        public async Task<IActionResult> SubmitUrl([FromQuery] string url)
        {
            if (string.IsNullOrWhiteSpace(url))
                return BadRequest(new { message = "URL is required" });

            try
            {
                var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);

                var result = await _triageService.ProcessUrlAsync(url);

                // link the triage cache record to the user
                await LinkToUserAsync(url, userId);

                return Ok(JsonSerializer.Deserialize<object>(result));
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { message = "Analysis request failed", error = ex.Message });
            }
        }

        [HttpPost("file")]
        [Authorize]                          // ← added
        public async Task<IActionResult> SubmitFile(IFormFile file)
        {
            if (file == null || file.Length == 0)
                return BadRequest(new { message = "File is required and cannot be empty" });

            try
            {
                // no caching, no history — just submit
                var result = await _triageService.ProcessFileAsync(file);
                return Ok(JsonSerializer.Deserialize<object>(result));
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { message = "File submission failed", error = ex.Message });
            }
        }

        [HttpGet("sample/{id}")]
        public async Task<IActionResult> GetSample(string id)
        {
            try
            {
                var result = await _triageService.GetSampleAsync(id);
                return Ok(JsonSerializer.Deserialize<object>(result));
            }
            catch (Exception ex)
            {
                return NotFound(new { message = "Sample not found", error = ex.Message });
            }
        }

        [HttpGet("sample/{id}/overview")]
        public async Task<IActionResult> GetOverview(string id)
        {
            try
            {
                var report = await _triageService.GetFullReportAsync(id);
                if (report == null)
                    return NotFound(new { message = "Report not ready or not found." });

                return Ok(report);
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { message = "Error mapping report", error = ex.Message });
            }
        }

        [HttpGet("my-history")]
        [Authorize]
        public async Task<IActionResult> MyHistory()
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);

            var records = await _db.TriageCaches
                .Include(t => t.Users)
                .Where(t => t.Users.Any(u => u.Id == userId))
                .OrderByDescending(t => t.CreatedAt)
                .Select(t => new
                {
                    t.ResourceHash,
                    t.SampleId,
                    t.Status,
                    t.Score,
                    t.CreatedAt
                })
                .ToListAsync();

            return Ok(records);
        }

        // ── private helper ─────────────────────────────────────────────────
        private async Task LinkToUserAsync(string url, string? userId)
        {
            if (userId is null) return;

            var urlId = url.ToLower().Trim().TrimEnd('/');

            var record = await _db.TriageCaches
                .Include(t => t.Users)
                .FirstOrDefaultAsync(t => t.ResourceHash == urlId);

            if (record is null) return;

            var alreadyLinked = record.Users.Any(u => u.Id == userId);
            if (alreadyLinked) return;

            var user = await _db.Users.FindAsync(userId);
            if (user is null) return;

            record.Users.Add(user);
            await _db.SaveChangesAsync();
        }
    }
}