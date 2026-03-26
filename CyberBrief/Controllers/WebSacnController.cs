using CyberBrief.Context;
using CyberBrief.DTOs.Web_Scan;
using CyberBrief.Models.Web_Scaning;
using CyberBrief.Services.IServices;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;

namespace CyberBrief.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [Authorize]                              // ← all endpoints require login
    public class WebScanController : ControllerBase
    {
        private readonly IScanService _scanService;
        private readonly CyberBriefDbContext _db;

        public WebScanController(IScanService scanService, CyberBriefDbContext db)
        {
            _scanService = scanService;
            _db = db;
        }

        [HttpPost("start")]
        public async Task<IActionResult> Start(string request)
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            var body = new WebScanRequest { Target = request };

            // check if already exists before calling service
            var existing = await _db.ScanRecords
                .Include(s => s.Users)
                .FirstOrDefaultAsync(s => s.Target == body.Target);

            if (existing is not null)
            {
                await LinkToUserAsync(existing, userId);

                return Ok(new
                {
                    scan_id = existing.ScanId,
                    status = existing.Status,
                    cached = true,
                    message = "This target was already scanned. You can check its status or download the report."
                });
            }

            var (alreadyDone, scanId) = await _scanService.StartScanAsync(body.Target);

            // fetch newly created record and link user
            var newRecord = await _db.ScanRecords
                .Include(s => s.Users)
                .FirstOrDefaultAsync(s => s.ScanId == scanId);

            await LinkToUserAsync(newRecord, userId);

            return Ok(new { scan_id = scanId, status = "started", cached = false });
        }

        [HttpGet("status")]
        public async Task<IActionResult> Status([FromQuery] string target)
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);

            var record = await _db.ScanRecords
                .Include(s => s.Users)
                .FirstOrDefaultAsync(s => s.Target == target);

            if (record is null)
                return NotFound(new { message = "No scan found for this target." });

            if (!record.Users.Any(u => u.Id == userId))
                return Forbid();

            var (scanId, tgt, status) = await _scanService.CheckStatusAsync(target);
            return Ok(new { scan_id = scanId, target = tgt, status });
        }

        [HttpGet("report")]
        public async Task<IActionResult> Report([FromQuery] string target)
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);

            var record = await _db.ScanRecords
                .Include(s => s.Users)
                .FirstOrDefaultAsync(s => s.Target == target);

            if (record is null)
                return NotFound(new { message = "No scan found for this target." });

            if (!record.Users.Any(u => u.Id == userId))
                return Forbid();

            var (_, _, status) = await _scanService.CheckStatusAsync(target);

            if (status != "completed")
                return BadRequest(new { error = "Scan not completed yet.", status });

            var pdf = await _scanService.GetReportPdfAsync(target);
            return File(pdf, "application/pdf", $"report_{target}.pdf");
        }

        [HttpGet("my-history")]
        public async Task<IActionResult> MyHistory()
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);

            var records = await _db.ScanRecords
                .Include(s => s.Users)
                .Where(s => s.Users.Any(u => u.Id == userId))
                .OrderByDescending(s => s.CreatedAt)
                .Select(s => new
                {
                    s.Target,
                    s.Status,
                    s.CreatedAt
                })
                .ToListAsync();

            return Ok(records);
        }

        // ── private helper ─────────────────────────────────────────────────
        private async Task LinkToUserAsync(ScanRecord? record, string? userId)
        {
            if (record is null || userId is null) return;

            var alreadyLinked = record.Users.Any(u => u.Id == userId);
            if (alreadyLinked) return;

            var user = await _db.Users.FindAsync(userId);
            if (user is null) return;

            record.Users.Add(user);
            await _db.SaveChangesAsync();
        }
    }
}