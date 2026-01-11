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

        public ScanResultDto MapToDto(ScanResultDto raw)
        {
            if (raw == null)
                return null;

            return new ScanResultDto
            {
                Id = raw.Id,
                Name = raw.Name,
                Tag = raw.Tag,
                StartedAt = raw.StartedAt,
                FinishedAt = raw.FinishedAt,

                Critical = raw.Critical,
                High = raw.High,
                Medium = raw.Medium,
                Low = raw.Low,
                Total = raw.Total,

                Vulnerabilities = raw.Vulnerabilities?
                    .GroupBy(v => new { v.Package, v.Vulnerability })
                    .Select(g => g.First())
                    .Select(v => new RawVulnerability
                    {
                        Package = v.Package,
                        Vulnerability = v.Vulnerability,
                        Severity = v.Severity,
                        Source = v.Source
                    })
                    .ToList() ?? new List<RawVulnerability>()
            };
        }


        public async Task<ScanResultDto> GetSummaryAsync(string name)
        {
            var exstingsummary = _context.Images.Where(x => x.Name == name).Select(x => x.SummaryId).FirstOrDefault();
            if(exstingsummary == null)
            {
               // return await _context.Summarys.Where(x => x.Id == exstingsummary).FirstOrDefaultAsync();
            }
            string safeName = name.Replace("/", "%");
            string scanId = _context.Images.Where(x => x.Name == name).Select(x => x.scanId).FirstOrDefault();
            var url = $"https://containerscanner.tecisfun.cloud//api/image/{safeName}/scan/{scanId}/json-report";
            using var httpClient = new HttpClient();
            var response = await httpClient.GetAsync(url);
            var jsonString = await response.Content.ReadAsStringAsync();
            var raw = JsonSerializer.Deserialize<ScanResultDto>(
                jsonString,
                new JsonSerializerOptions
                {
                    PropertyNameCaseInsensitive = true
                }
            );
            ScanResultDto resultDto = MapToDto(raw);

            return resultDto;
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
