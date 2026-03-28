using CyberBrief.Context;
using CyberBrief.DTOs.Sandbox;
using CyberBrief.Models;
using Microsoft.EntityFrameworkCore;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;

namespace CyberBrief.Services
{
    public class TriageService
    {
        private readonly HttpClient _httpClient;
        private readonly CyberBriefDbContext _context;

        public TriageService(HttpClient httpClient, IConfiguration config, CyberBriefDbContext context)
        {
            _httpClient = httpClient;
            _context = context;

            var apiKey = config["TriageCloud:ApiKey"];
            _httpClient.BaseAddress = new Uri(config["TriageCloud:BaseUrl"]);
            _httpClient.DefaultRequestHeaders.Accept.Clear();
            _httpClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", apiKey);
        }

        // ── Public: raw submission (controller handles caching logic) ─────────

        /// <summary>
        /// Submits a URL to Triage and returns the raw JSON response.
        /// Caching and DB logic is handled by the controller.
        /// </summary>
        public Task<string> SubmitUrlRawAsync(string url) => SubmitUrlAsync(url);

        /// <summary>
        /// Submits a file to Triage and returns the raw JSON response.
        /// </summary>
        public Task<string> ProcessFileAsync(IFormFile file)
        {
            if (file == null) throw new ArgumentNullException(nameof(file));
            return SubmitFileAsync(file);
        }

        /// <summary>
        /// Fetches the live sample status from Triage.
        /// Returns the raw JSON so the controller can extract what it needs.
        /// </summary>
        public async Task<string> GetSampleAsync(string sampleId)
        {
            var response = await _httpClient.GetAsync($"samples/{sampleId}");
            response.EnsureSuccessStatusCode();
            return await response.Content.ReadAsStringAsync();
        }

        /// <summary>
        /// Fetches the full overview report and maps it to TriageReportDto.
        /// Also updates the DB cache record to status "reported".
        /// Returns null if the overview endpoint fails.
        /// </summary>
        public async Task<TriageReportDto?> GetFullReportAsync(string sampleId)
        {
            var response = await _httpClient.GetAsync($"samples/{sampleId}/overview.json");
            if (!response.IsSuccessStatusCode) return null;

            var jsonContent = await response.Content.ReadAsStringAsync();
            using var doc = JsonDocument.Parse(jsonContent);
            var root = doc.RootElement;

            if (!root.TryGetProperty("sample", out var sampleEl)) return null;

            var report = new TriageReportDto
            {
                SampleId = sampleId,
                Score = sampleEl.TryGetProperty("score", out var s) ? s.GetInt32() : 0,
                Target = sampleEl.TryGetProperty("target", out var t) ? t.GetString() : "Unknown",
            };

            // Tags
            if (root.TryGetProperty("analysis", out var analysis) &&
                analysis.TryGetProperty("tags", out var tags))
            {
                report.Tags = tags.EnumerateArray()
                    .Select(x => x.GetString()!)
                    .ToList();
            }

            // High Risk Signatures (score >= 3)
            if (root.TryGetProperty("signatures", out var sigs))
            {
                foreach (var sig in sigs.EnumerateArray())
                {
                    int score = sig.TryGetProperty("score", out var sc) ? sc.GetInt32() : 0;
                    if (score >= 3)
                    {
                        report.HighRiskSignatures.Add(new SignatureDto
                        {
                            Name = sig.TryGetProperty("name", out var n) ? n.GetString() : "Unknown",
                            Score = score,
                            Description = sig.TryGetProperty("desc", out var d) ? d.GetString() : ""
                        });
                    }
                }
            }

            // Persist to DB cache
            var cacheRecord = await _context.TriageCaches
                .FirstOrDefaultAsync(x => x.SampleId == sampleId);

            if (cacheRecord != null)
            {
                cacheRecord.Status = "reported";
                cacheRecord.Score = report.Score;
                cacheRecord.RawJson = jsonContent;
                await _context.SaveChangesAsync();
            }

            return report;
        }

        // ── Private Helpers ───────────────────────────────────────────────────

        private async Task<string> SubmitUrlAsync(string url)
        {
            var payload = JsonSerializer.Serialize(new { kind = "url", url });
            var response = await _httpClient.PostAsync("samples",
                new StringContent(payload, Encoding.UTF8, "application/json"));
            response.EnsureSuccessStatusCode();
            return await response.Content.ReadAsStringAsync();
        }

        private async Task<string> SubmitFileAsync(IFormFile file)
        {
            using var content = new MultipartFormDataContent();
            var streamContent = new StreamContent(file.OpenReadStream());
            content.Add(streamContent, "file", file.FileName);
            content.Add(new StringContent(
                JsonSerializer.Serialize(new { kind = "file" }),
                Encoding.UTF8, "application/json"), "_json");

            var response = await _httpClient.PostAsync("samples", content);
            response.EnsureSuccessStatusCode();
            return await response.Content.ReadAsStringAsync();
        }
    }
}