using CyberBrief.DTOs.Container;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.Text.Json;
using CyberBrief.Services;
namespace CyberBrief.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class ContainerController : ControllerBase
    {
        private readonly ContainerServices _containerServices;
        public ContainerController(ContainerServices containerServices)
        {
            _containerServices = containerServices;
        }

        [HttpPost("scan-image")]
        public async Task<IActionResult> ScanImage(string name, string scanId)
        {
            string safeName = name.Replace("/", "%");
            var url =
                $"https://containerscanner.tecisfun.cloud//api/image/{safeName}/scan/{scanId}/json-report";

            using var httpClient = new HttpClient();

            var response = await httpClient.GetAsync(url);

            if (!response.IsSuccessStatusCode)
            {
                return StatusCode(
                    (int)response.StatusCode,
                    "Failed to fetch scan report"
                );
            }

            var jsonString = await response.Content.ReadAsStringAsync();

            var raw = JsonSerializer.Deserialize<RawScanResponse>(
                jsonString,
                new JsonSerializerOptions
                {
                    PropertyNameCaseInsensitive = true
                }
            );

            if (raw == null)
                return BadRequest("Invalid scan response");

            ScanResultDto resultDto = _containerServices.MapToDto(raw);

            return Ok(resultDto);
        }
        [HttpPost("start-scan")]
        public async Task<IActionResult> StartScan([FromBody] imgforscan img)
        {
            var result = await _containerServices.StratScanAsync(img);
            if (result.StartsWith("Error:"))
            {
                return BadRequest(result);
            }
            return Ok(result);
        }
    }
}
