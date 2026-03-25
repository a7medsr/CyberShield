using CyberBrief.Models;
using CyberBrief.Dtos.URLModels;
using CyberBrief.Services.IServices;
using System.Text.Json;
using System.Text;

namespace CyberBrief.Services
{
    public class AdvancedSafetyAnalyzerService : ISafetyAnalyzerService
    {
        private readonly HttpClient _httpClient;
        private readonly IConfiguration _configuration;
        private const string ModelBaseUrl = "http://147.93.55.224:7000";

        public AdvancedSafetyAnalyzerService(HttpClient httpClient, IConfiguration configuration)
        {
            _httpClient = httpClient;
            _configuration = configuration;
        }

        public SafetyAnalysisResultDto AnalyzeUrlSafety(string finalUrl, List<string> redirectionChain)
        {
            return AnalyzeUrlSafetyAsync(finalUrl, redirectionChain).GetAwaiter().GetResult();
        }

        public async Task<SafetyAnalysisResultDto> AnalyzeUrlSafetyAsync(string finalUrl, List<string> redirectionChain)
        {
            var result = new SafetyAnalysisResultDto
            {
                IsSafe = true,
                SafetyLevel = "Unknown",
                Message = "🔍 Analyzing URL safety..."
            };

            try
            {
                // Step 1: Basic URL validation
                if (!IsValidUrl(finalUrl))
                {
                    result.IsSafe = false;
                    result.SafetyLevel = "Dangerous";
                    result.Message = "🚨 Invalid or malformed URL detected.";
                    result.RedFlags.Add("Invalid URL format");
                    return result;
                }

                // Step 2: VirusTotal & Google Safe Browsing
                await CheckWithVirusTotalAsync(result, finalUrl);
                await CheckWithGoogleSafeBrowsingAsync(result, finalUrl);

                // If either flagged it → no need to run the model
                if (result.RedFlags.Any())
                {
                    DetermineFinalSafety(result);
                    return result;
                }

                // Step 3: Both clean → run ML model
                await CheckWithMlModelAsync(result, finalUrl);

                // Step 4: Final determination
                DetermineFinalSafety(result);

                return result;
            }
            catch (Exception ex)
            {
                result.IsSafe = false;
                result.SafetyLevel = "Unknown";
                result.Message = "❓ Unable to complete safety analysis.";
                result.Warnings.Add($"Analysis error: {ex.Message}");
                return result;
            }
        }

        private bool IsValidUrl(string url)
        {
            return Uri.TryCreate(url, UriKind.Absolute, out var uri) &&
                   (uri.Scheme == Uri.UriSchemeHttp || uri.Scheme == Uri.UriSchemeHttps);
        }

        private async Task CheckWithMlModelAsync(SafetyAnalysisResultDto result, string url)
        {
            try
            {
                var body = new StringContent(
                    JsonSerializer.Serialize(new { url }),
                    Encoding.UTF8, "application/json");

                var response = await _httpClient.PostAsync($"{ModelBaseUrl}/analyze", body);

                if (!response.IsSuccessStatusCode)
                {
                    result.Warnings.Add($"ML model check failed: {response.StatusCode}");
                    return;
                }

                var prediction = JsonSerializer.Deserialize<UrlPredictionResponse>(
                    await response.Content.ReadAsStringAsync());

                if (prediction is null)
                {
                    result.Warnings.Add("ML model returned an empty response.");
                    return;
                }

                result.ModelVerdict = prediction.Verdict;
                result.ModelConfidence = prediction.Confidence;
                result.ModelFlags = prediction.Flags;

                switch (prediction.Verdict.ToLower())
                {
                    case "phishing":
                        result.IsSafe = false;
                        result.SafetyLevel = "Dangerous";
                        result.RedFlags.Add(
                            $"ML Model: Phishing detected (confidence: {prediction.Confidence:P0})");
                        foreach (var flag in prediction.Flags)
                            result.RedFlags.Add($"Model flag: {flag}");
                        break;

                    case "malware":
                        result.IsSafe = false;
                        result.SafetyLevel = "Dangerous";
                        result.RedFlags.Add(
                            $"ML Model: Malware detected (confidence: {prediction.Confidence:P0})");
                        foreach (var flag in prediction.Flags)
                            result.RedFlags.Add($"Model flag: {flag}");
                        break;

                    case "safe":
                        result.IsSafe = true;
                        result.SafetyLevel = "Safe";
                        if (prediction.Flags.Any())
                            foreach (var flag in prediction.Flags)
                                result.Warnings.Add($"Model notice: {flag}");
                        break;

                    default:
                        result.Warnings.Add($"ML model returned unknown verdict: {prediction.Verdict}");
                        break;
                }
            }
            catch (HttpRequestException ex) { result.Warnings.Add($"ML model API error: {ex.Message}"); }
            catch (TaskCanceledException) { result.Warnings.Add("ML model API timeout."); }
            catch (Exception ex) { result.Warnings.Add($"ML model check failed: {ex.Message}"); }
        }

        private void DetermineFinalSafety(SafetyAnalysisResultDto result)
        {
            if (result.RedFlags.Any())
            {
                result.IsSafe = false;
                result.SafetyLevel = "Dangerous";
                result.Message = "🚨 This link appears to be dangerous. Threats detected.";
            }
            else if (result.Warnings.Count >= 3)
            {
                result.IsSafe = false;
                result.SafetyLevel = "Suspicious";
                result.Message = "⚠️ This link shows multiple suspicious characteristics. Proceed with extreme caution.";
            }
            else if (result.Warnings.Any())
            {
                result.IsSafe = true;
                result.SafetyLevel = "Suspicious";
                result.Message = "⚠️ This link shows some suspicious characteristics. Proceed with caution.";
            }
            else if (result.SafetyLevel == "Safe")
            {
                result.Message = "✅ No threats detected by security engines or ML model.";
            }
            else
            {
                result.IsSafe = true;
                result.SafetyLevel = "Likely Safe";
                result.Message = "✅ No obvious threats detected, but always be cautious with unfamiliar links.";
            }
        }

        private async Task CheckWithVirusTotalAsync(SafetyAnalysisResultDto result, string url)
        {
            try
            {
                var apiKey = _configuration["SecurityAnalysis:VirusTotal:ApiKey"];
                var enabled = _configuration.GetValue<bool>("SecurityAnalysis:VirusTotal:Enabled");

                if (!enabled || string.IsNullOrEmpty(apiKey))
                {
                    result.Warnings.Add("VirusTotal check skipped (not configured)");
                    return;
                }

                var submitData = new StringContent(
                    $"url={Uri.EscapeDataString(url)}",
                    Encoding.UTF8, "application/x-www-form-urlencoded");

                var submitRequest = new HttpRequestMessage(HttpMethod.Post,
                    "https://www.virustotal.com/api/v3/urls")
                {
                    Content = submitData
                };
                submitRequest.Headers.Add("x-apikey", apiKey);

                var submitResponse = await _httpClient.SendAsync(submitRequest);
                if (!submitResponse.IsSuccessStatusCode)
                {
                    result.Warnings.Add($"VirusTotal submission failed: {submitResponse.StatusCode}");
                    return;
                }

                var submitResult = JsonSerializer.Deserialize<VirusTotalSubmitResponse>(
                    await submitResponse.Content.ReadAsStringAsync());

                if (submitResult?.Data?.Id == null)
                {
                    result.Warnings.Add("VirusTotal: Unable to get analysis ID");
                    return;
                }

                await Task.Delay(2000);

                var analysisRequest = new HttpRequestMessage(HttpMethod.Get,
                    $"https://www.virustotal.com/api/v3/analyses/{submitResult.Data.Id}");
                analysisRequest.Headers.Add("x-apikey", apiKey);

                var analysisResponse = await _httpClient.SendAsync(analysisRequest);
                if (!analysisResponse.IsSuccessStatusCode)
                {
                    result.Warnings.Add($"VirusTotal analysis retrieval failed: {analysisResponse.StatusCode}");
                    return;
                }

                var analysisResult = JsonSerializer.Deserialize<VirusTotalAnalysisResponse>(
                    await analysisResponse.Content.ReadAsStringAsync());

                if (analysisResult?.Data?.Attributes?.Stats != null)
                {
                    var stats = analysisResult.Data.Attributes.Stats;
                    var totalEngines = stats.Harmless + stats.Malicious + stats.Suspicious + stats.Undetected + stats.Timeout;
                    var threats = stats.Malicious + stats.Suspicious;

                    if (threats > 0)
                    {
                        result.IsSafe = false;
                        result.SafetyLevel = stats.Malicious > 0 ? "Dangerous" : "Suspicious";
                        result.RedFlags.Add($"VirusTotal: {threats}/{totalEngines} engines flagged this URL");

                        if (stats.Malicious > 0)
                            result.Message = "🚨 This URL has been flagged as malicious by security engines.";
                    }
                    else if (totalEngines > 0)
                    {
                        result.Warnings.Add($"VirusTotal: Scanned by {totalEngines} engines - appears clean");
                    }
                }
                else
                {
                    result.Warnings.Add("VirusTotal: Analysis still in progress or unavailable");
                }
            }
            catch (HttpRequestException ex) { result.Warnings.Add($"VirusTotal API error: {ex.Message}"); }
            catch (TaskCanceledException) { result.Warnings.Add("VirusTotal API timeout"); }
            catch (Exception ex) { result.Warnings.Add($"VirusTotal check failed: {ex.Message}"); }
        }

        private async Task CheckWithGoogleSafeBrowsingAsync(SafetyAnalysisResultDto result, string url)
        {
            try
            {
                var apiKey = _configuration["SecurityAnalysis:GoogleSafeBrowsing:ApiKey"];
                var enabled = _configuration.GetValue<bool>("SecurityAnalysis:GoogleSafeBrowsing:Enabled");

                if (!enabled || string.IsNullOrEmpty(apiKey))
                {
                    result.Warnings.Add("Google Safe Browsing check skipped (not configured)");
                    return;
                }

                var requestPayload = new
                {
                    client = new
                    {
                        clientId = "CyberShield",
                        clientVersion = "1.0.0"
                    },
                    threatInfo = new
                    {
                        threatTypes = new[]
        {
            "MALWARE",
            "SOCIAL_ENGINEERING",
            "UNWANTED_SOFTWARE",
            "POTENTIALLY_HARMFUL_APPLICATION"
        },
                        platformTypes = new[] { "ANY_PLATFORM" },
                        threatEntryTypes = new[] { "URL" },
                        threatEntries = new[]
        {
            new { url = url }  // explicit property name
        }
                    }
                };

                var content = new StringContent(
                    JsonSerializer.Serialize(requestPayload),
                    Encoding.UTF8, "application/json");

                var response = await _httpClient.PostAsync(
                    $"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={apiKey}", content);
                var responseBody = await response.Content.ReadAsStringAsync();

                if (!response.IsSuccessStatusCode)
                {
                    result.Warnings.Add($"Google Safe Browsing API error: {response.StatusCode} - {responseBody}");
                    return;
                }

                var responseContent = await response.Content.ReadAsStringAsync();

                if (string.IsNullOrWhiteSpace(responseContent) || responseContent == "{}")
                {
                    result.Warnings.Add("Google Safe Browsing: URL appears safe");
                    return;
                }

                var threatResponse = JsonSerializer.Deserialize<GoogleSafeBrowsingThreatResponse>(responseContent);

                if (threatResponse?.Matches != null && threatResponse.Matches.Any())
                {
                    result.IsSafe = false;
                    result.SafetyLevel = "Dangerous";
                    var threatList = string.Join(", ", threatResponse.Matches.Select(m => m.ThreatType).Distinct());
                    result.RedFlags.Add($"Google Safe Browsing: URL flagged for {threatList}");
                    result.Message = "🚨 This URL has been flagged by Google Safe Browsing as unsafe.";

                    foreach (var match in threatResponse.Matches.Take(3))
                        result.RedFlags.Add($"Threat detected: {match.ThreatType} on {match.PlatformType}");
                }
                else
                {
                    result.Warnings.Add("Google Safe Browsing: URL appears safe");
                }
            }
            catch (HttpRequestException ex) { result.Warnings.Add($"Google Safe Browsing API error: {ex.Message}"); }
            catch (TaskCanceledException) { result.Warnings.Add("Google Safe Browsing API timeout"); }
            catch (Exception ex) { result.Warnings.Add($"Google Safe Browsing check failed: {ex.Message}"); }
        }
    }
}
