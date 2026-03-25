using CyberBrief.DTOs.Web_Scan;
using CyberBrief.Services.IServices;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace CyberBrief.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class WebSacnController : ControllerBase
    {
        private readonly IScanService _scanService;

        public WebSacnController(IScanService scanService)
            => _scanService = scanService;


        [HttpPost("start")]
        public async Task<IActionResult> Start(string request)
        {
            var body = new WebScanRequest { Target = request };
            var (alreadyDone, scanId) = await _scanService.StartScanAsync(body.Target);

            if (alreadyDone)
                return Ok(new { scan_id = scanId, status = "completed", cached = true });

            return Ok(new { scan_id = scanId, status = "started", cached = false });
        }

        [HttpGet("status")]
        public async Task<IActionResult> Status([FromQuery] string target)
        {
            var (scanId, tgt, status) = await _scanService.CheckStatusAsync(target);
            return Ok(new { scan_id = scanId, target = tgt, status });
        }

        [HttpGet("report")]
        public async Task<IActionResult> Report([FromQuery] string target)
        {
            var (_, _, status) = await _scanService.CheckStatusAsync(target);

            if (status != "completed")
                return BadRequest(new { error = "Scan not completed yet.", status });

            var pdf = await _scanService.GetReportPdfAsync(target);
            return File(pdf, "application/pdf", $"report_{target}.pdf");
        }
    }
}
