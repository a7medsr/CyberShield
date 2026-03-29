using CyberBrief.Services.IServices;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace CyberBrief.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class DashboardController : ControllerBase
    {
        private readonly IDashboardService _service;
        public DashboardController(IDashboardService service)
        {
            _service = service;
        }
        [HttpGet("all-scanned-urls")]
        public async Task<IActionResult> Get() 
        { 
             var result=await _service.AllScannedUrls();
            return Ok(result);
        }

    }
}
