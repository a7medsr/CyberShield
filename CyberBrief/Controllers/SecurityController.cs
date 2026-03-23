using CyberBrief.Models.Email_Checking;
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

        [HttpGet("check/{email}")]
        public async Task<ActionResult<Result>> CheckEmail(string email)
        {
            if (string.IsNullOrEmpty(email))
            {
                return BadRequest("Email is required.");
            }

            try
            {
                var result = await _breachService.CheckEmail(email);

                if (result == null)
                {
                    return NotFound(new { message = "No data found or API limit exceeded." });
                }

                return Ok(result);
            }
            catch (Exception ex)
            {
                // In a real app, log this exception
                return StatusCode(500, $"Internal server error: {ex.Message}");
            }
        }


        [HttpGet("inspect-password")]
        public async Task<IActionResult> InspectPassword(string password)
        {
            if (string.IsNullOrWhiteSpace(password))
                return BadRequest(new { message = "Password is required." });

            var report = await _inspector.InspectAsync(password);
            return Ok(report); 
        }

    }

}
