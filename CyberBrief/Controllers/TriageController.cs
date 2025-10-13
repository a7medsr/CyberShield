using Microsoft.AspNetCore.Mvc;
using CyberBrief.Services;
using Microsoft.AspNetCore.Http;

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
        public async Task<IActionResult> SubmitUrl(string url)
        {
            if (string.IsNullOrWhiteSpace(url))
                return BadRequest("URL is required");

            var result = await _triageService.SubmitUrlAsync(url);
            return Ok(result);
        }

        // POST: api/triage/file

        [HttpPost("File")]
        public async Task<IActionResult> SubmitFile(IFormFile file)
        {
            if (file == null || file.Length == 0)
                return BadRequest("File is required");

            var result = await _triageService.SubmitFileAsync(file);
            return Ok(result);
        }
        
        [HttpGet("sample/{id}")]
        public async Task<IActionResult> GetSample(string id)
        {
            var result = await _triageService.GetSampleAsync(id);
            return Ok(result);
        }

        //// GET: api/triage/sample/{id}/overview
        [HttpGet("sample/{id}/overview")]
        public async Task<IActionResult> GetOverview(string id)
        {
            var result = await _triageService.GetOverviewAsync(id);
            return Ok(result);
        }
    }
}
