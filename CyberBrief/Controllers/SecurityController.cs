using CyberBrief.Context;
using CyberBrief.DTOs.Gmail;
using CyberBrief.Models.Email_Checking;
using CyberBrief.Services;
using CyberBrief.Services.Email_sending;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace CyberBrief.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class SecurityController : ControllerBase
    {
        private readonly BreachDirectoryService _breachService;
        private readonly PasswordInspectorService _inspector;
        private readonly CyberBriefDbContext _context;
        private readonly IEmailService _emailService;

        public SecurityController(BreachDirectoryService breachService, PasswordInspectorService inspector,CyberBriefDbContext context, IEmailService emailService)
        {
            _breachService = breachService;
            _inspector = inspector;
            _context = context;
            _emailService = emailService;
        }

        //private readonly BreachDirectoryService _breachService;
        //private readonly IEmailService _emailService;
        //private readonly CyberBriefDbContext _context;

        //public BreachController(
        //    BreachDirectoryService breachService,
        //    IEmailService emailService,
        //    CyberBriefDbContext context)
        //{
        //    _breachService = breachService;
        //    _emailService = emailService;
        //    _context = context;
        //}

        // STEP 1: Request OTP
        [HttpPost("request-otp")]
        public async Task<IActionResult> RequestOtp(string email)
        {
            if (string.IsNullOrWhiteSpace(email))
                return BadRequest(new { message = "Email is required." });

            // Generate 6-digit OTP
            var otp = new Random().Next(100000, 999999).ToString();

            // Save to Database (Upsert logic)
            var verification = await _context.EmailVerifications
                .FirstOrDefaultAsync(v => v.Email == email);

            if (verification == null)
            {
                verification = new EmailVerification { Email = email };
                _context.EmailVerifications.Add(verification);
            }

            verification.OtpCode = otp;
            verification.Expiry = DateTime.UtcNow.AddMinutes(10);
            verification.IsVerified = false;

            await _context.SaveChangesAsync();

            // Send Email
            try
            {
                await _emailService.SendOtpAsync(email, otp);
                return Ok(new { message = "Verification code sent to your email." });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { message = "Failed to send email.", details = ex.Message });
            }
        }

        // STEP 2: Verify OTP and Get Data
        [HttpGet("verify-and-check")]
        public async Task<ActionResult<BreachCheckResultDto>> VerifyAndCheck(string email, string otp)
        {
            var verification = await _context.EmailVerifications
                .FirstOrDefaultAsync(v => v.Email == email && v.OtpCode == otp);

            if (verification == null || verification.Expiry < DateTime.UtcNow)
            {
                return BadRequest(new { message = "Invalid or expired verification code." });
            }

            // Execute the breach scan
            var result = await _breachService.CheckEmail(email);

            // Clean up the OTP so it can't be reused
            _context.EmailVerifications.Remove(verification);
            await _context.SaveChangesAsync();

            if (result == null) return NotFound(new { message = "No data found." });

            return Ok(result);
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
