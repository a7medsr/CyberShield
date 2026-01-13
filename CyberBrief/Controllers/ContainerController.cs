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

        //[HttpPost("scan-image")]
        //public async Task<IActionResult> ScanImage(string name)
        //{

        //    ScanResultDto resultDto =await _containerServices.GetSummaryAsync(name);

        //    return Ok(resultDto);
        //}
        [HttpPost("start-scan")]
        public async Task<IActionResult> StartScan([FromBody] imgforscan img)
        {
            var result = await _containerServices.StratScanAsync(img);
          
            return Ok(result);
        }
        [HttpGet("status")]
        public async Task<Status> status(string imgname)
        {

            var result = await _containerServices.GetStatusAsync(imgname);
            
            return result;
        }
    }
}
