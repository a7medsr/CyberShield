using CyberBrief.Context;
using CyberBrief.DTOs.Container;
using CyberBrief.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.Text.Json;
using CyberBrief.Services.IServices;
using static CyberBrief.Services.CVEexplanationService;
namespace CyberBrief.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class ContainerController : ControllerBase
    {
        private readonly IContainerServices _containerServices;
        public ContainerController(IContainerServices containerServices)
        {
            _containerServices = containerServices;
        }
        
        [HttpPost("start-scan")]
        public async Task<IActionResult> StartScan([FromBody] imgforscan img)
        {
            try
            {
                var message = await _containerServices.StratScanAsync(img);
                return Accepted(new { message }); 
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
      

    }
}
