using CyberBrief.Context;
using CyberBrief.DTOs.Container;
using CyberBrief.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.Text.Json;
using static CyberBrief.Services.CVEexplanationService;
namespace CyberBrief.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class ContainerController : ControllerBase
    {
        private readonly ContainerServices _containerServices;
        private readonly CyberBriefDbContext _context;
        private readonly CVEexplanationService _cvEexplanationService;
        public ContainerController(ContainerServices containerServices, CyberBriefDbContext context, CVEexplanationService cvEexplanationService)
        {
            _containerServices = containerServices;
            _context = context;
            _cvEexplanationService = cvEexplanationService;

        }
        
        [HttpPost("scan-scan")]
        public async Task<IActionResult> StartScan([FromBody] imgforscan img)
        {
            try
            {
                var result = await _containerServices.StratScanAsync(img);
                return Ok(result);
            }
            catch(Exception ex)
            {
                return BadRequest(ex.Message);
            }
           
        }

        [HttpGet("Image-Summary")]
        public async Task<IActionResult> GetSummary(string imagename)
        {
            var result=await _containerServices.GetSummary(imagename);
            return Ok(result);
        }
        [HttpGet("cve-explenation")]
        public async Task<IActionResult> GetSummaryAsync(string imagename)
        {
            var result = await _cvEexplanationService.GetExplanation(imagename);
            return Ok(result);
        }

    }
}
