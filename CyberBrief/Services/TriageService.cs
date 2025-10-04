using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;

namespace CyberBrief.Services
{
    public class TriageService
    {
        private readonly HttpClient _httpClient;

        public TriageService(HttpClient httpClient, IConfiguration config)
        {
            _httpClient = httpClient;
            var apiKey = config["TriageCloud:ApiKey"];
            _httpClient.BaseAddress = new Uri(config["TriageCloud:BaseUrl"]);
            _httpClient.DefaultRequestHeaders.Accept.Clear();
            _httpClient.DefaultRequestHeaders.Accept.Add(
                new MediaTypeWithQualityHeaderValue("application/json"));
            _httpClient.DefaultRequestHeaders.Authorization =
                new AuthenticationHeaderValue("Bearer", apiKey);
        }

        // Submit a URL for analysis
        public async Task<string> SubmitUrlAsync(string url)
        {
            var payload = JsonSerializer.Serialize(new
            {
                kind = "url",
                url = url
            });

            var response = await _httpClient.PostAsync("samples",
                new StringContent(payload, Encoding.UTF8, "application/json"));
            response.EnsureSuccessStatusCode();

            return await response.Content.ReadAsStringAsync();
        }

        // Submit a file for analysis
        public async Task<string> SubmitFileAsync(IFormFile file)
        {
            using var content = new MultipartFormDataContent();
            content.Add(new StreamContent(file.OpenReadStream()), "file", file.FileName);

            var json = JsonSerializer.Serialize(new { kind = "file" });
            content.Add(new StringContent(json, Encoding.UTF8, "application/json"), "_json");

            var response = await _httpClient.PostAsync("samples", content);
            response.EnsureSuccessStatusCode();

            return await response.Content.ReadAsStringAsync();
        }

        // Get sample details by ID
        public async Task<string> GetSampleAsync(string sampleId)
        {
            var response = await _httpClient.GetAsync($"samples/{sampleId}");
            response.EnsureSuccessStatusCode();
            return await response.Content.ReadAsStringAsync();
        }

        // Get overview report
        public async Task<string> GetOverviewAsync(string sampleId)
        {
            var response = await _httpClient.GetAsync($"samples/{sampleId}/overview.json");
            response.EnsureSuccessStatusCode();
            return await response.Content.ReadAsStringAsync();
        }
    }
}
