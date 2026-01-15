using Azure.Core;
using CyberBrief.Context;
using CyberBrief.DTOs.Container;
using Microsoft.EntityFrameworkCore;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json;
using static System.Net.Mime.MediaTypeNames;
namespace CyberBrief.Services
{
    public class ContainerServices
    {
        private readonly CyberBriefDbContext _context;
        private readonly HttpClient _httpClient;

        public ContainerServices(CyberBriefDbContext context, IHttpClientFactory factory)
        {
            _context = context;
            _httpClient = factory.CreateClient("ContainerScanner");
        }
        
        public async Task<summaryDto?> StratScanAsync(imgforscan img)
        {
            // 1. Check for existing scan to avoid redundant work
            var existingImage = await GetExistingImageAsync(img.image);
            if (existingImage != null) return await GetSummary(img.image);
            // 2. Initiate the scan and poll for completion
            var scanResponse = await InitiateScanRequestAsync(img);
            var finalStatus = await PollScanStatusUntilCompleteAsync(scanResponse.requestId);

            if (finalStatus.progress != 100)
            {
                throw new Exception($"Scan failed to complete. Final status: {finalStatus.status}");
            }

            // 3. Fetch findings
            var scanResultDto = await GetSummaryAsync(img.image, scanResponse.scanId);

            // 4. Process and Save results
             await SaveScanResultsToDatabaseAsync(img, scanResponse, finalStatus, scanResultDto);
             return await GetSummary(img.image);
        }
        
        #region start scann logic
        private async Task<Status> PollScanStatusUntilCompleteAsync(string requestId)
        {
            Status status = null;
            int attempts = 0;
            const int maxAttempts = 10;

            while (attempts < maxAttempts)
            {
                status = await getstatusbyid(requestId);
                if (status.progress == 100) return status;

                attempts++;
                await Task.Delay(TimeSpan.FromSeconds(30));
            }

            throw new Exception("Scan timed out before reaching 100%.");
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
        
                // Ensure counting logic uses the RawVulnerability properties
                CriticalVulnerabilities = uniqueVuls.Count(v => v.Severity.Equals("CRITICAL", StringComparison.OrdinalIgnoreCase)),
                HighVulnerabilities = uniqueVuls.Count(v => v.Severity.Equals("HIGH", StringComparison.OrdinalIgnoreCase)),
                MediumVulnerabilities = uniqueVuls.Count(v => v.Severity.Equals("MEDIUM", StringComparison.OrdinalIgnoreCase)),
                LowVulnerabilities = uniqueVuls.Count(v => v.Severity.Equals("LOW", StringComparison.OrdinalIgnoreCase)),
        
                // Initialize the collection (don't try to assign the list here yet)
                Vulnerabilities = new List<Vulnerability>()
            };
        }
        private async Task<Image> SaveScanResultsToDatabaseAsync(imgforscan img, ScanResponse scanRes, Status status, ScanResultDto dto)
        {
            var image = new Image
            {
                Id = Guid.NewGuid().ToString(),
                Name = img.image,
                Tag = img.tag ?? "latest",
                requestId = scanRes.requestId,
                scanId = scanRes.scanId,
                Status = status.status,
                Progres = status.progress
            };

            var uniqueVulDtos = dto.Vulnerabilities
                .GroupBy(v => v.Vulnerability)
                .Select(g => g.First())
                .ToList();

            var summary = MapDtoToSummary(image.Id, dto, uniqueVulDtos);

            // Resolve which vulnerabilities already exist in DB
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
                    existingVuls[newVul.Id] = newVul; // Prevent duplicates in same loop
                    summary.Vulnerabilities.Add(newVul);
                }
            }

            image.SummaryId = summary.Id;
            await _context.Images.AddAsync(image);
            await _context.Summarys.AddAsync(summary);
            await _context.SaveChangesAsync();

            return image;
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
        private async Task<ScanResultDto> GetSummaryAsync(string name,string scanId)
        {
            string safeName = Uri.EscapeDataString(name);

            var response = await _httpClient.GetAsync($"api/image/{safeName}/scan/{scanId}/json-report");


            response.EnsureSuccessStatusCode();

            var jsonString = await response.Content.ReadAsStringAsync();

            var apiResponse = JsonSerializer.Deserialize<ScanApiResponse>(
                jsonString,
                new JsonSerializerOptions { PropertyNameCaseInsensitive = true }
            );

            if (apiResponse == null || apiResponse.Summary == null)
                return null;


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
                Vulnerabilities = apiResponse.Vulnerabilities? .ToList() ?? new List<RawVulnerability>()
            };
        }
        #endregion

        
        private async Task<Status> getstatusbyid(string reqid)
        {
            if (reqid == null) throw new Exception("the image dont exest");
          
            HttpResponseMessage response = await _httpClient.GetAsync($"api/scans/status/{reqid}");

            string responseBody = await response.Content.ReadAsStringAsync();

            Status scanStatus = JsonSerializer.Deserialize<Status>(responseBody);
            return scanStatus;
        }

        public async Task<summaryDto> GetSummary(string Imagename)
        {
          Image image= await _context.Images.Where(x=>x.Name==Imagename).FirstOrDefaultAsync();
          var summary = await _context.Summarys
              .Include(x => x.Vulnerabilities)
              .FirstOrDefaultAsync(x => x.ImageId == image.Id);
        
          return new summaryDto 
          {
              Id = summary.Id,
              ImageName = Imagename,
              StartedAt =  summary.StartedAt,
              FinishedAt =  summary.FinishedAt,
              TotalVulnerabilities =  summary.Vulnerabilities.Count,
              CriticalVulnerabilities =   summary.CriticalVulnerabilities,
              HighetVulnerabilities =  summary.HighVulnerabilities,
              MediumVulnerabilities = summary.MediumVulnerabilities,
              LowetVulnerabilities =   summary.LowVulnerabilities,
              Vulnerabilities = summary.Vulnerabilities.Select(v => new VulnerabilityDto {
                  Package =  v.Package,
                  Vulnerability = v.Id,
                  Source =   v.Source,
                  Severity = v.Severity
              }).ToList()
             
          };
        }
        
    }
}
