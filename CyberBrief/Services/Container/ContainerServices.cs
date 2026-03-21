using Azure.Core;
using CyberBrief.Context;
using CyberBrief.DTOs.Container;
using Microsoft.EntityFrameworkCore;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json;
using CyberBrief.Services.IServices;
using static System.Net.Mime.MediaTypeNames;

namespace CyberBrief.Services
{
    public class ContainerServices:IContainerServices
    {
        private readonly CyberBriefDbContext _context;
        private readonly HttpClient _httpClient;
        private readonly ICVEexplanationService _cvEexplanationService;

        public ContainerServices(CyberBriefDbContext context, IHttpClientFactory factory, ICVEexplanationService cvEexplanationService)
        {
            _context = context;
            _httpClient = factory.CreateClient("ContainerScanner");
            _cvEexplanationService = cvEexplanationService;
        }

        public async Task<string> StratScanAsync(imgforscan img)
        {
            // 1. Check for existing scan
            var existingImage = await GetExistingImageAsync(img.image);
            if (existingImage != null) return "Scan already exists or is in progress.";

            // 2. Initiate the scan and get IDs
            var scanResponse = await InitiateScanRequestAsync(img);

            // 3. Create initial record in DB with 0 progress
            var image = new Image
            {
                Id = Guid.NewGuid().ToString(),
                Name = img.image,
                Tag = img.tag ?? "latest",
                requestId = scanResponse.requestId,
                scanId = scanResponse.scanId,
                Status = "Started",
                Progres = 0
            };

            await _context.Images.AddAsync(image);
            await _context.SaveChangesAsync();

            return "Scan started successfully";
        }

        public async Task<object> GetSummary(string Imagename)
        {
            var image = await _context.Images.FirstOrDefaultAsync(x => x.Name == Imagename);
            if (image == null) return new { message = "Image not found" };

            // If not finished in DB, check remote status
            if (image.Progres < 100)
            {
                var currentStatus = await getstatusbyid(image.requestId);
                
                // Update DB with latest progress
                image.Progres = currentStatus.progress;
                image.Status = currentStatus.status;
                await _context.SaveChangesAsync();

                if (currentStatus.progress < 100)
                {
                    return new { message = "Scan is not finished yet", progress = image.Progres, status = image.Status };
                }

                // If it just hit 100%, process the results now
                var scanResultDto = await GetSummaryAsync(image.Name, image.scanId);
                await SaveScanResultsToDatabaseAsync(image, scanResultDto);
                await _cvEexplanationService.GetExplanation(image.Name);
            }

            // Return the full summary
            var summary = await _context.Summarys
                .Include(x => x.Vulnerabilities)
                .FirstOrDefaultAsync(x => x.ImageId == image.Id);

            return new summaryDto
            {
                Id = summary.Id,
                ImageName = Imagename,
                StartedAt = summary.StartedAt,
                FinishedAt = summary.FinishedAt,
                TotalVulnerabilities = summary.Vulnerabilities.Count,
                CriticalVulnerabilities = summary.CriticalVulnerabilities,
                HighetVulnerabilities = summary.HighVulnerabilities,
                MediumVulnerabilities = summary.MediumVulnerabilities,
                LowetVulnerabilities = summary.LowVulnerabilities,
                Vulnerabilities = summary.Vulnerabilities.Select(v => new VulnerabilityDto
                {
                    Package = v.Package,
                    Vulnerability = v.Id,
                    Source = v.Source,
                    Severity = v.Severity,
                    Explenation = v.Explanation,
                    Batch = v.Batch
                }).ToList()
            };
        }

        #region Logic Methods
        private async Task<Image> SaveScanResultsToDatabaseAsync(Image image, ScanResultDto dto)
        {
            var uniqueVulDtos = dto.Vulnerabilities
                .GroupBy(v => v.Vulnerability)
                .Select(g => g.First())
                .ToList();

            var summary = MapDtoToSummary(image.Id, dto, uniqueVulDtos);

            var incomingIds = uniqueVulDtos.Select(v => v.Vulnerability).ToList();
            var existingVuls = await _context.Vulnerabilities
                .Where(v => incomingIds.Contains(v.Id))
                .ToDictionaryAsync(v => v.Id);

            foreach (var vDto in uniqueVulDtos)
            {
                if (existingVuls.TryGetValue(vDto.Vulnerability, out var existing))
                {
                    summary.Vulnerabilities.Add(existing);
                }
                else
                {
                    var newVul = new Vulnerability
                    {
                        Id = vDto.Vulnerability,
                        Package = vDto.Package,
                        Severity = vDto.Severity,
                        Source = vDto.Source
                    };
                    _context.Vulnerabilities.Add(newVul);
                    existingVuls[newVul.Id] = newVul;
                    summary.Vulnerabilities.Add(newVul);
                }
            }

            image.SummaryId = summary.Id;
            await _context.Summarys.AddAsync(summary);
            await _context.SaveChangesAsync();

            return image;
        }

        private Summary MapDtoToSummary(string imageId, ScanResultDto dto, List<RawVulnerability> uniqueVuls)
        {
            return new Summary
            {
                Id = Guid.NewGuid().ToString(),
                ImageId = imageId,
                StartedAt = dto.StartedAt,
                FinishedAt = dto.FinishedAt,
                TotalVulnerabilities = uniqueVuls.Count,
                CriticalVulnerabilities = uniqueVuls.Count(v => v.Severity.Equals("CRITICAL", StringComparison.OrdinalIgnoreCase)),
                HighVulnerabilities = uniqueVuls.Count(v => v.Severity.Equals("HIGH", StringComparison.OrdinalIgnoreCase)),
                MediumVulnerabilities = uniqueVuls.Count(v => v.Severity.Equals("MEDIUM", StringComparison.OrdinalIgnoreCase)),
                LowVulnerabilities = uniqueVuls.Count(v => v.Severity.Equals("LOW", StringComparison.OrdinalIgnoreCase)),
                Vulnerabilities = new List<Vulnerability>()
            };
        }

        private async Task<ScanResponse> InitiateScanRequestAsync(imgforscan img)
        {
            var request = new ScanRequest(
                img.image,
                img.tag ?? "latest",
                img.Source ?? "registry",
                img.dockerImageId ?? string.Empty,
                img.repositoryId ?? string.Empty
            );

            var response = await _httpClient.PostAsJsonAsync("api/scans/start", request);
            response.EnsureSuccessStatusCode();

            return await response.Content.ReadFromJsonAsync<ScanResponse>()
                   ?? throw new Exception("Failed to parse scan response.");
        }

        private async Task<Image?> GetExistingImageAsync(string name) =>
            await _context.Images.FirstOrDefaultAsync(x => x.Name == name);

        private async Task<ScanResultDto> GetSummaryAsync(string name, string scanId)
        {
            string safeName = Uri.EscapeDataString(name);
            var response = await _httpClient.GetAsync($"api/image/{safeName}/scan/{scanId}/json-report");
            response.EnsureSuccessStatusCode();

            var jsonString = await response.Content.ReadAsStringAsync();
            var apiResponse = JsonSerializer.Deserialize<ScanApiResponse>(jsonString, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });

            if (apiResponse == null || apiResponse.Summary == null) return null;

            return new ScanResultDto
            {
                Id = apiResponse.Summary.Id,
                Name = apiResponse.Summary.Image.Name,
                Tag = apiResponse.Summary.Image.Tag,
                StartedAt = apiResponse.Summary.StartedAt,
                FinishedAt = apiResponse.Summary.FinishedAt,
                Critical = apiResponse.Summary.Counts.Critical,
                High = apiResponse.Summary.Counts.High,
                Medium = apiResponse.Summary.Counts.Medium,
                Low = apiResponse.Summary.Counts.Low,
                Total = apiResponse.Summary.Counts.Total,
                Vulnerabilities = apiResponse.Vulnerabilities?.ToList() ?? new List<RawVulnerability>()
            };
        }

        private async Task<Status> getstatusbyid(string reqid)
        {
            if (reqid == null) throw new Exception("Request ID is null");
            HttpResponseMessage response = await _httpClient.GetAsync($"api/scans/status/{reqid}");
            string responseBody = await response.Content.ReadAsStringAsync();
            return JsonSerializer.Deserialize<Status>(responseBody);
        }
        #endregion
    }
}