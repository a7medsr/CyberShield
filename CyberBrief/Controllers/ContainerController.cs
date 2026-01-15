using CyberBrief.DTOs.Container;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.Text.Json;
using CyberBrief.Services;
using CyberBrief.Context;
namespace CyberBrief.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class ContainerController : ControllerBase
    {
        private readonly ContainerServices _containerServices;
        private readonly CyberBriefDbContext _context;
        public ContainerController(ContainerServices containerServices, CyberBriefDbContext context)
        {
            _containerServices = containerServices;
            _context = context;

        }
        
        [HttpPost("scan-scan")]
        public async Task<IActionResult> StartScan([FromBody] imgforscan img)
        {
            var result = await _containerServices.StratScanAsync(img);
          
            return Ok(result);
        }

        [HttpGet("Image-Summary")]
        public async Task<IActionResult> GetSummary(string imagename)
        {
            var result=await _containerServices.GetSummary(imagename);
            return Ok(result);
        }

    }
}
