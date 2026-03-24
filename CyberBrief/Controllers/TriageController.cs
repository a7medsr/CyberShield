using Microsoft.AspNetCore.Mvc;
using CyberBrief.Services;
using Microsoft.AspNetCore.Http;
using System.Text.Json;

namespace CyberBrief.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class TriageController : ControllerBase
    {
        private readonly TriageService _triageService;
        
        public TriageController(TriageService triageService)
        {
            _triageService = triageService;
        }

        // POST: api/triage/url
        [HttpPost("url")]
        public async Task<IActionResult> SubmitUrl([FromQuery] string url)
        {
            if (string.IsNullOrWhiteSpace(url))
                return BadRequest(new { message = "URL is required" });

            try
            {
                // ProcessUrlAsync handles Hashing, DB Lookup, and API Submission
                var result = await _triageService.ProcessUrlAsync(url);
                return Ok(JsonSerializer.Deserialize<object>(result));
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { message = "Analysis request failed", error = ex.Message });
            }
        }

        // POST: api/triage/file

        [HttpPost("File")]
        public async Task<IActionResult> SubmitFile(IFormFile file)
        {
            if (file == null || file.Length == 0)
                return BadRequest(new { message = "File is required and cannot be empty" });

            try
            {
                // ProcessFileAsync ensures we don't upload the same file twice
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
        //// GET: api/triage/sample/{id}/overview
        [HttpGet("sample/{id}/overview")]
        public async Task<IActionResult> GetOverview(string id)
        {
            try
            {
                var report = await _triageService.GetFullReportAsync(id);

                if (report == null)
                    return NotFound(new { message = "Report not ready or not found." });

                return Ok(report); // .NET handles the JSON conversion automatically here
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { message = "Error mapping report", error = ex.Message });
            }
        }
    }
}
