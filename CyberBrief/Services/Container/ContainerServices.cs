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
        public ContainerServices(CyberBriefDbContext context)
        {
            _context = context;
        }

        public async Task<ScanResultDto> GetSummaryAsync(string name)
        {
            string safeName = name.Replace("/", "%");

            string scanId = _context.Images
                .Where(x => x.Name == name)
                .Select(x => x.scanId)
                .FirstOrDefault();

            if (string.IsNullOrEmpty(scanId))
                return null;

            var url = $"https://containerscanner.tecisfun.cloud/api/image/{safeName}/scan/{scanId}/json-report";

            using var httpClient = new HttpClient();
            var response = await httpClient.GetAsync(url);

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
            using HttpClient client= new HttpClient();
            string url = $"https://containerscanner.tecisfun.cloud/api/scans/status/{reqid}";
            var httpClient = new HttpClient();

            HttpResponseMessage response =  await httpClient.GetAsync(url);
            
            string responseBody = await response.Content.ReadAsStringAsync();

            Status scanStatus = JsonSerializer.Deserialize<Status>(responseBody);
            return scanStatus;
        }


        public async Task<Image?> StratScanAsync(imgforscan img)
        {
           
            Image? exstingimage = await _context.Images.Where(x => x.Name == img.image).FirstOrDefaultAsync();
            if (exstingimage != null)
            {
                return exstingimage;
            }

            
            using HttpClient client = new HttpClient();

            string url ="https://containerscanner.tecisfun.cloud//api//scans/start";   
            var scanRequest = new ScanRequest(
                img.image,
                img.tag ?? "latest",
                img.Source ?? "registry",
                img.dockerImageId ?? string.Empty,
                img.repositoryId ?? string.Empty
            );
            
                HttpResponseMessage respone= await client.PostAsJsonAsync(url, scanRequest);
                
                respone.EnsureSuccessStatusCode();
                
                string responseBody = await respone.Content.ReadAsStringAsync();
                
                ScanResponse result = JsonSerializer.Deserialize<ScanResponse>(responseBody);
                if (result == null || string.IsNullOrEmpty(result.requestId))
                {
                    throw new Exception("Failed to parse scan response or requestId is missing.");
                }

                //Status status =await GetStatusAsync(result.requestId);
                Image image = new Image
                {
                    Id = Guid.NewGuid().ToString(),
                    Name = scanRequest.image,
                    Tag= scanRequest.tag,
                    requestId=result.requestId,
                    scanId=result.scanId,
                  //  Status=status.status,
                 //   Progres=status.progress
                };

               await _context.Images.AddAsync(image);
               _context.SaveChanges();
                return image;
            
        }
    }
}
