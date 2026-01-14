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

        // Add this where you initialize the client



        public async Task<ScanResultDto> GetSummaryAsync(string name,string scanId)
        {
            string safeName = Uri.EscapeDataString(name);

            //string scanId = _context.Images.Where(x => x.Name == name).Select(x => x.scanId).FirstOrDefault();

            //if (scanId == null) 
            //{
            //    throw new Exception("the image dont exest");
            //}

            //Status status =await GetStatusAsync(name);


          //  var url = $"https://containerscanner.tecisfun.cloud/api/image/{safeName}/scan/{scanId}/json-report";

            //using var httpClient = new HttpClient();
            //httpClient.Timeout = TimeSpan.FromMinutes(5);
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

                Vulnerabilities = apiResponse.Vulnerabilities?
                    .GroupBy(v => new { v.Package, v.Vulnerability })
                    .Select(g => g.First())
                    .ToList() ?? new List<RawVulnerability>()
            };
        }



       

        public async Task<Status> GetStatusAsync(string imgname)
        {
            string? reqid =await _context.Images.Where(x => x.Name == imgname).Select(x => x.requestId).FirstOrDefaultAsync();
            if (reqid == null) throw new Exception("the image dont exest");
            
            string url = $"https://containerscanner.tecisfun.cloud/api/scans/status/{reqid}";
            // var httpClient = new HttpClient();
            HttpResponseMessage response =  await _httpClient.GetAsync(url);
            
            string responseBody = await response.Content.ReadAsStringAsync();

            Status scanStatus = JsonSerializer.Deserialize<Status>(responseBody);
            return scanStatus;
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


        public async Task<Image?> StratScanAsync(imgforscan img)
        {
            // 1. Check if image was already scanned
            Image? existingImage = await _context.Images
                .Where(x => x.Name == img.image)
                .FirstOrDefaultAsync();

            if (existingImage != null) return existingImage;

            // 2. Start the scan
            //using HttpClient client = new HttpClient(); // Note: Ideally, use IHttpClientFactory
           // string url = "https://containerscanner.tecisfun.cloud/api/scans/start";

            var scanRequest = new ScanRequest(
                img.image,
                img.tag ?? "latest",
                img.Source ?? "registry",
                img.dockerImageId ?? string.Empty,
                img.repositoryId ?? string.Empty
            );
            //client.Timeout = TimeSpan.FromMinutes(5);
            HttpResponseMessage response = await _httpClient.PostAsJsonAsync("api/scans/start", scanRequest);
            

            response.EnsureSuccessStatusCode();

            string responseBody = await response.Content.ReadAsStringAsync();
            ScanResponse result = JsonSerializer.Deserialize<ScanResponse>(responseBody);

            if (result == null || string.IsNullOrEmpty(result.requestId))
            {
                throw new Exception("Failed to parse scan response or requestId is missing.");
            }

            // 3. Polling Loop: Check status every 30 seconds
            Status status = null;
            bool isCompleted = false;
            int maxAttempts = 10; // Optional: Stop after 10 minutes (20 * 30s)
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
                    // Wait for 30 seconds before the next check
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
                TotalVulnerabilities=summarydto.Total,
                CriticalVulnerabilities=summarydto.Critical,
                HighVulnerabilities=summarydto.High,
                MediumVulnerabilities=summarydto.Medium,
                LowVulnerabilities=summarydto.Low,
            };
            foreach(var vul in summarydto.Vulnerabilities)
            {
                Vulnerability vvulnerability = new Vulnerability
                {
                    Id = Guid.NewGuid().ToString(),
                    Package = vul.Package,
                    vulnerability = vul.Vulnerability,
                    Severity = vul.Severity,
                    Source = vul.Source,
                    SummaryId = summary.Id
                };
                await _context.Vulnerabilities.AddAsync(vvulnerability);
            }
            image.SummaryId = summary.Id;

            
            await _context.Images.AddAsync(image);
            await _context.Summarys.AddAsync(summary);
            await _context.SaveChangesAsync(); // Use Async version for DB saves
            return image;
        }


    }
}
