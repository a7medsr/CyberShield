using CyberBrief.Context;
using CyberBrief.DTOs.Container;
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
    public class ContainerController : ControllerBase
    {
        private readonly IContainerServices _containerServices;
        private readonly CyberBriefDbContext _db;

        public ContainerController(IContainerServices containerServices, CyberBriefDbContext db)
        {
            _containerServices = containerServices;
            _db = db;
        }

        [HttpPost("start-scan")]
        public async Task<IActionResult> StartScan([FromBody] imgforscan img)
        {
            try
            {
                var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);

                // check if image already exists
                var existing = await _db.Images
                    .Include(i => i.Users)
                    .FirstOrDefaultAsync(i => i.Name == img.image);

                if (existing is not null)
                {
                    // link user to existing image
                    await LinkToUserAsync(existing, userId);

                    return Accepted(new
                    {
                        message = "This image was already scanned. You can check its summary now.",
                        imageName = existing.Name,
                        status = existing.Status,
                        progress = existing.Progres
                    });
                }

                // fresh scan
                var message = await _containerServices.StratScanAsync(img);

                // fetch the newly created image record and link user
                var newImage = await _db.Images
                    .Include(i => i.Users)
                    .FirstOrDefaultAsync(i => i.Name == img.image);

                await LinkToUserAsync(newImage, userId);

                return Accepted(new { message });
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }

        [HttpGet("image-summary")]
        public async Task<IActionResult> GetSummary(string imagename)
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);

            // make sure this image belongs to the user
            var image = await _db.Images
                .Include(i => i.Users)
                .FirstOrDefaultAsync(i => i.Name == imagename);

            if (image is null)
                return NotFound(new { message = "Image not found." });

            var isLinked = image.Users.Any(u => u.Id == userId);
            if (!isLinked)
                return Forbid();

            var result = await _containerServices.GetSummary(imagename);
            return Ok(result);
        }

        [HttpGet("my-history")]
        public async Task<IActionResult> MyHistory()
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);

            var images = await _db.Images
                .Include(i => i.Users)
                .Where(i => i.Users.Any(u => u.Id == userId))
                .OrderByDescending(i => i.Id)
                .Select(i => new
                {
                    i.Id,
                    i.Name,
                    i.Tag,
                    i.Status,
                    i.Progres,
                    i.SummaryId
                })
                .ToListAsync();

            return Ok(images);
        }

        // ── private helper ─────────────────────────────────────────────────
        private async Task LinkToUserAsync(Image? image, string? userId)
        {
            if (image is null || userId is null) return;

            var alreadyLinked = image.Users.Any(u => u.Id == userId);
            if (alreadyLinked) return;

            var user = await _db.Users.FindAsync(userId);
            if (user is null) return;

            image.Users.Add(user);
            await _db.SaveChangesAsync();
        }
    }
}