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

        
          public async Task<Image?> StratScanAsync(imgforscan img)
        {
            Image? existingImage = await _context.Images.Where(x => x.Name == img.image).FirstOrDefaultAsync();
            if (existingImage != null) return existingImage;
            
            var scanRequest = new ScanRequest(
                img.image,
                img.tag ?? "latest",
                img.Source ?? "registry",
                img.dockerImageId ?? string.Empty, 
                img.repositoryId ?? string.Empty
            );
            HttpResponseMessage response = await _httpClient.PostAsJsonAsync("api/scans/start", scanRequest);
            response.EnsureSuccessStatusCode();
            string responseBody = await response.Content.ReadAsStringAsync();
            ScanResponse result = JsonSerializer.Deserialize<ScanResponse>(responseBody);
            
            if (result == null || string.IsNullOrEmpty(result.requestId))
            {
                throw new Exception("Failed to parse scan response or requestId is missing.");
            } 
            Status status = null;
            bool isCompleted = false;
            int maxAttempts = 10; 
            int attempts = 0;

            while (!isCompleted && attempts < maxAttempts)
            {
                status = await getstatusbyid(result.requestId);

                if (status.progress == 100)
                {
                    isCompleted = true;
                }
                else
                {
                    attempts++;
                    await Task.Delay(TimeSpan.FromSeconds(30));
                }
            }
            
            if (status?.progress != 100)
            {
                throw new Exception("Scan timed out or failed to reach 100%.");
            }
            
            ScanResultDto summarydto=await GetSummaryAsync(scanRequest.image, result.scanId);
            
            // 4. Save to Database
            Image image = new Image
            {
                Id = Guid.NewGuid().ToString(),
                Name = scanRequest.image,
                Tag = scanRequest.tag,
                requestId = result.requestId,
                scanId = result.scanId,
                Status = status.status,
                Progres = status.progress
            };
            Summary summary = new Summary
            {
                Id = Guid.NewGuid().ToString(),
                ImageId = image.Id,
                StartedAt=summarydto.StartedAt,
                FinishedAt=summarydto.FinishedAt,
                //TotalVulnerabilities=summarydto.Total,
                //CriticalVulnerabilities=summarydto.Critical,
               // HighVulnerabilities=summarydto.High,
               // MediumVulnerabilities=summarydto.Medium,
               // LowVulnerabilities=summarydto.Low,
                Vulnerabilities = new List<Vulnerability>()
            };
            // 1. Calculate counts directly from the raw DTO data first
            var uniqueVulnerabilities = summarydto.Vulnerabilities
                .GroupBy(v => v.Vulnerability)
                .Select(g => g.First()) // Take the first occurrence of each unique CVE
                .ToList();
           // summary.CriticalVulnerabilities = summarydto.Vulnerabilities.Count(x => x.Severity.Equals("Critical", StringComparison.OrdinalIgnoreCase));
           // summary.HighVulnerabilities = summarydto.Vulnerabilities.Count(x => x.Severity.Equals("High", StringComparison.OrdinalIgnoreCase));
          //  summary.MediumVulnerabilities = summarydto.Vulnerabilities.Count(x => x.Severity.Equals("Medium", StringComparison.OrdinalIgnoreCase));
          //  summary.LowVulnerabilities = summarydto.Vulnerabilities.Count(x => x.Severity.Equals("Low", StringComparison.OrdinalIgnoreCase));
         //   summary.TotalVulnerabilities = summarydto.Vulnerabilities.Count;

// 2. Handle database persistence
            var incomvulIds = summarydto.Vulnerabilities.Select(v => v.Vulnerability).Distinct().ToList();
            var exestvulId = await _context.Vulnerabilities.Where(v => incomvulIds.Contains(v.Id)).ToDictionaryAsync(v => v.Id);
            var localCache = new Dictionary<string, Vulnerability>(exestvulId);
            foreach (var vulDto in summarydto.Vulnerabilities)
            {
                if (localCache.TryGetValue(vulDto.Vulnerability, out var existingVul))
                {
                    summary.Vulnerabilities.Add(existingVul);
                }
                else
                {
                    var newVul = new Vulnerability
                    {
                        Id = vulDto.Vulnerability, 
                        Package = vulDto.Package,
                        Severity = vulDto.Severity,
                        Source = vulDto.Source
                    };
                    _context.Vulnerabilities.Add(newVul); // Track the new entity
                    localCache[vulDto.Vulnerability] = newVul;
                    summary.Vulnerabilities.Add(newVul);
                }
            }

            var mp = new Dictionary<string, int>();
            int c = 0;
            mp["low"] = 0;
            mp["high"] = 0;
            mp["critical"] = 0;
            mp["medium"] = 0;
            foreach (var i in localCache)
            {
                if (i.Value.Severity == "CRITICAL" || i.Value.Severity == "Critical")
                {
                    mp[i.Value.Severity.ToLower()]++;
                }
                if (i.Value.Severity == "HIGH" || i.Value.Severity == "High")
                {
                    mp[i.Value.Severity.ToLower()]++;
                }
                if (i.Value.Severity == "Medium" || i.Value.Severity == "MEDIUM")
                {
                    mp[i.Value.Severity.ToLower()]++;
                }
                if (i.Value.Severity == "LOW" || i.Value.Severity == "Low")
                {
                    mp[i.Value.Severity.ToLower()]++;
                }

                c++;
            }

            summary.LowVulnerabilities = mp["low"];
            summary.MediumVulnerabilities = mp["medium"];
            summary.HighVulnerabilities = mp["high"];
            summary.TotalVulnerabilities = c;
            
            image.SummaryId = summary.Id;
            await _context.Images.AddAsync(image);
            await _context.Summarys.AddAsync(summary);
            await _context.SaveChangesAsync(); 
            return image;
        }

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
        private async Task<Status> getstatusbyid(string reqid)
        {
           // string? reqid = await _context.Images.Where(x => x.Name == imgname).Select(x => x.requestId).FirstOrDefaultAsync();
            if (reqid == null) throw new Exception("the image dont exest");
           // using HttpClient client = new HttpClient();
           // client.Timeout = TimeSpan.FromMinutes(5);
            //string url = $"https://containerscanner.tecisfun.cloud/api/scans/status/{reqid}";
            // var httpClient = new HttpClient();
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
         // var vuls=summary.Vulnerabilities;
        //  int criticalCount = vuls.Count(x => x.Severity.Equals("CRITICAL", StringComparison.OrdinalIgnoreCase));     
          
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
