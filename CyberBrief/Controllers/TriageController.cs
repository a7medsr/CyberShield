using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;
using CyberBrief.Context;
using System.Security.Claims;
using System.Text.Json;
using CyberBrief.Services.TriageSerivces;

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

        // ─────────────────────────────────────────────────────────────────────
        // POST /api/Triage/url
        // Submits a URL for scanning. Returns sampleId immediately so the
        // frontend can start polling /sample/{id} for status.
        // ─────────────────────────────────────────────────────────────────────
        [HttpPost("url")]
        [Authorize]
        public async Task<IActionResult> SubmitUrl([FromQuery] string url)
        {
            if (string.IsNullOrWhiteSpace(url))
                return BadRequest(new { success = false, message = "URL is required." });

            try
            {
                var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);

                // Check cache first — no need to re-submit
                var urlId = url.ToLower().Trim().TrimEnd('/');
                var cached = await _db.TriageCaches.FirstOrDefaultAsync(x => x.ResourceHash == urlId);

                if (cached != null)
                {
                    await LinkToUserAsync(urlId, userId, isCachedKey: true);

                    return Ok(new
                    {
                        success = true,
                        alreadyCached = true,
                        sampleId = cached.SampleId,
                        message = "This URL was already scanned. Use the sampleId to fetch results."
                    });
                }

                // Submit fresh scan
                var rawJson = await _triageService.SubmitUrlRawAsync(url);
                using var doc = JsonDocument.Parse(rawJson);
                var sampleId = doc.RootElement.GetProperty("id").GetString();

                // Save to DB
                _db.TriageCaches.Add(new CyberBrief.Models.TriageCache
                {
                    ResourceHash = urlId,
                    SampleId = sampleId,
                    Status = "pending",
                    CreatedAt = DateTime.UtcNow
                });
                await _db.SaveChangesAsync();

                await LinkToUserAsync(urlId, userId, isCachedKey: true);

                return Accepted(new
                {
                    success = true,
                    alreadyCached = false,
                    sampleId,
                    message = "Scan submitted successfully. Poll /api/Triage/sample/{id} for status."
                });
            }
            catch (HttpRequestException ex)
            {
                return StatusCode(502, new { success = false, message = "Failed to reach Triage API.", error = ex.Message });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { success = false, message = "Unexpected error during submission.", error = ex.Message });
            }
        }

        // ─────────────────────────────────────────────────────────────────────
        // POST /api/Triage/file
        // Submits a file for scanning. Returns sampleId for polling.
        // No caching — every file submission is treated as fresh.
        // ─────────────────────────────────────────────────────────────────────
        [HttpPost("file")]
        [Authorize]
        public async Task<IActionResult> SubmitFile(IFormFile file)
        {
            if (file == null || file.Length == 0)
                return BadRequest(new { success = false, message = "A non-empty file is required." });

            try
            {
                var rawJson = await _triageService.ProcessFileAsync(file);
                using var doc = JsonDocument.Parse(rawJson);
                var sampleId = doc.RootElement.GetProperty("id").GetString();

                return Accepted(new
                {
                    success = true,
                    sampleId,
                    message = "File submitted successfully. Poll /api/Triage/sample/{id} for status."
                });
            }
            catch (HttpRequestException ex)
            {
                return StatusCode(502, new { success = false, message = "Failed to reach Triage API.", error = ex.Message });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { success = false, message = "Unexpected error during file submission.", error = ex.Message });
            }
        }

        // ─────────────────────────────────────────────────────────────────────
        // GET /api/Triage/sample/{id}
        // Polls the scan status. Frontend should keep calling this until
        // status == "reported", then switch to /overview.
        // ─────────────────────────────────────────────────────────────────────
        [HttpGet("sample/{id}")]
        public async Task<IActionResult> GetStatus(string id)
        {
            try
            {
                // Check local DB cache first
                var cached = await _db.TriageCaches.FirstOrDefaultAsync(t => t.SampleId == id);
                if (cached?.Status == "reported")
                {
                    return Ok(new
                    {
                        success = true,
                        sampleId = id,
                        status = "reported",
                        score = cached.Score,
                        message = "Scan complete. Fetch the full report at /api/Triage/sample/{id}/overview"
                    });
                }

               
                var rawJson = await _triageService.GetSampleAsync(id);
                using var doc = JsonDocument.Parse(rawJson);
                var root = doc.RootElement;

                var status = root.TryGetProperty("status", out var s) ? s.GetString() : "pending";

                if (status == "reported")
                {
                    var record = await _db.TriageCaches.FirstOrDefaultAsync(t => t.SampleId == id);
                    if (record != null && record.Status != "reported")
                    {
                        record.Status = "reported";
                        await _db.SaveChangesAsync();
                    }

                    return Ok(new
                    {
                        success = true,
                        sampleId = id,
                        status = "reported",
                        message = "Scan complete. Fetch the full report at /api/Triage/sample/{id}/overview"
                    });
                }

                return Ok(new
                {
                    success = true,
                    sampleId = id,
                    status,   
                    message = "Scan is still in progress. Please poll again shortly."
                });
            }
            catch (HttpRequestException ex)
            {
                return StatusCode(502, new { success = false, message = "Failed to reach Triage API.", error = ex.Message });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { success = false, message = "Unexpected error while checking status.", error = ex.Message });
            }
        }

        // ─────────────────────────────────────────────────────────────────────
        // GET /api/Triage/sample/{id}/overview
        // Returns the full structured report. Call this only after status
        // is "reported". Returns 409 Conflict if the scan is not done yet.
        // ─────────────────────────────────────────────────────────────────────
        [HttpGet("sample/{id}/overview")]
        public async Task<IActionResult> GetOverview(string id)
        {
            try
            {
                // Guard: don't try to build a report for an unfinished scan
                var cached = await _db.TriageCaches.FirstOrDefaultAsync(t => t.SampleId == id);
                if (cached != null && cached.Status != "reported")
                {
                    return Conflict(new
                    {
                        success = false,
                        sampleId = id,
                        status = cached.Status,
                        message = "Scan is not complete yet. Keep polling /api/Triage/sample/{id} until status is 'reported'."
                    });
                }

                var report = await _triageService.GetFullReportAsync(id);

                if (report == null)
                {
                    return NotFound(new
                    {
                        success = false,
                        sampleId = id,
                        message = "Report not found or scan may still be running."
                    });
                }

                return Ok(new
                {
                    success = true,
                    sampleId = id,
                    score = report.Score,
                    severity = ScoreToSeverity(report.Score),
                    target = report.Target,
                    tags = report.Tags,
                    highRiskSignatures = report.HighRiskSignatures.Select(sig => new
                    {
                        name = sig.Name,
                        score = sig.Score,
                        description = sig.Description
                    }),
                    message = "Report fetched successfully."
                });
            }
            catch (HttpRequestException ex)
            {
                return StatusCode(502, new { success = false, message = "Failed to reach Triage API.", error = ex.Message });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { success = false, message = "Unexpected error while fetching report.", error = ex.Message });
            }
        }

        // ─────────────────────────────────────────────────────────────────────
        // GET /api/Triage/my-history
        // Returns the current user's scan history.
        // ─────────────────────────────────────────────────────────────────────
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
                    url = t.ResourceHash,
                    sampleId = t.SampleId,
                    status = t.Status,
                    score = t.Score,
                    severity = ScoreToSeverity(t.Score ?? 0),
                    scannedAt = t.CreatedAt
                })
                .ToListAsync();

            return Ok(new
            {
                success = true,
                count = records.Count,
                scans = records
            });
        }

        // ── Private Helpers ───────────────────────────────────────────────────

        private static string ScoreToSeverity(int score) => score switch
        {
            >= 8 => "critical",
            >= 6 => "high",
            >= 4 => "medium",
            >= 2 => "low",
            _    => "clean"
        };

        private async Task LinkToUserAsync(string key, string? userId, bool isCachedKey = false)
        {
            if (userId is null) return;

            var record = await _db.TriageCaches
                .Include(t => t.Users)
                .FirstOrDefaultAsync(t => t.ResourceHash == key);

            if (record is null) return;
            if (record.Users.Any(u => u.Id == userId)) return;

            var user = await _db.Users.FindAsync(userId);
            if (user is null) return;

            record.Users.Add(user);
            await _db.SaveChangesAsync();
        }
    }
}