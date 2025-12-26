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
        public async Task<IActionResult> ScanImage(
    [FromQuery] string name,
    [FromQuery] string scanId)
        {
            var url =
                $"https://scannv4.proudforest-e230a1a0.francecentral.azurecontainerapps.io/api/image/{name}/scan/{scanId}/json-report";

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

    }
}
