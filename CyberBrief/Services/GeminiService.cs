using System.Net.Http.Json;
using System.Text.Json;

namespace CyberBrief.Services
{
    public class GeminiService
    {
        private readonly HttpClient _httpClient;
        private readonly string _apiKey;
        private const string GeminiUrl = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent";

        public GeminiService(HttpClient httpClient, IConfiguration config)
        {
            _httpClient = httpClient;
            _apiKey = config["Gemini:ApiKey"] ?? "AIzaSyChc8d9JWBTThcePYhzKaKqllJkhvvxmGw";

            if (!_httpClient.DefaultRequestHeaders.Contains("X-goog-api-key"))
            {
                _httpClient.DefaultRequestHeaders.Add("X-goog-api-key", _apiKey);
            }
        }

        public async Task<List<CveAnalysis>> GetVulnerabilityAnalysisAsync(List<string> cveIds)
        {
            if (cveIds == null || !cveIds.Any()) return new List<CveAnalysis>();

            // 1. Define the detailed prompt
            var prompt = $@"
                Analyze the following CVE IDs: {string.Join(", ", cveIds)}.
                
                For each CVE, provide:
                1. 'cveId': The ID of the vulnerability.
                2. 'explanation': A one-sentence summary of the risk.
                3. 'patch': The version or action required to fix it.

                Format Requirement:
                Return ONLY a raw JSON array. 
                Do not include markdown tags, code blocks (like ```json), or any introductory text.
                Use these exact keys: ""cveId"", ""explanation"", ""patch"".";

            // 2. USE the prompt variable in the request body
            var requestBody = new
            {
                contents = new[]
                {
                    new { parts = new[] { new { text = prompt } } }
                }
            };

            var response = await _httpClient.PostAsJsonAsync(GeminiUrl, requestBody);
            response.EnsureSuccessStatusCode();

            var jsonResponse = await response.Content.ReadFromJsonAsync<JsonElement>();

            // Navigate the response tree to get the text string
            string rawJson = jsonResponse.GetProperty("candidates")[0]
                                         .GetProperty("content")
                                         .GetProperty("parts")[0]
                                         .GetProperty("text").GetString() ?? "[]";

            // 3. Clean any accidental markdown formatting
            rawJson = rawJson.Replace("```json", "").Replace("```", "").Trim();

            return JsonSerializer.Deserialize<List<CveAnalysis>>(rawJson) ?? new List<CveAnalysis>();
        }

        public class CveAnalysis
        {
            public string cveId { get; set; } = string.Empty;
            public string explanation { get; set; } = string.Empty;
            public string patch { get; set; } = string.Empty;
        }
    }
}