using CyberBrief.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using static PasswordInspectorService;

namespace CyberBrief.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class SecurityController : ControllerBase
    {
        private readonly BreachDirectoryService _breachService;
        private readonly PasswordInspectorService _inspector;

        public SecurityController(BreachDirectoryService breachService, PasswordInspectorService inspector)
        {
            _breachService = breachService;
            _inspector = inspector;
        }

        [HttpGet("check-email")]
        public async Task<IActionResult> Check(string email)
        {
            var result = await _breachService.CheckEmailAsync(email);

            if (result == null)
                return StatusCode(500, "Unknown error occurred.");

            if (!result.Success)
                return StatusCode(429, result.Message);

            if (result.Found > 0)
                return Ok(result);

            return NotFound("No breaches found for this email.");
        }

     
        [HttpPost("inspect-password")]
        public async Task<IActionResult> InspectPassword(string password)
        {
            if (string.IsNullOrWhiteSpace(password))
                return BadRequest(new { message = "Password is required." });

            var report = await _inspector.InspectAsync(password);
            return Ok(report); 
        }

    }

}
