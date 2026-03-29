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
            => AnalyzeUrlSafetyAsync(finalUrl, redirectionChain).GetAwaiter().GetResult();

        public async Task<SafetyAnalysisResultDto> AnalyzeUrlSafetyAsync(
            string finalUrl, List<string> redirectionChain)
        {
            var result = new SafetyAnalysisResultDto();

            try
            {
                if (!IsValidUrl(finalUrl))
                {
                    result.IsSafe = false;
                    result.VtScore = 4; result.GsbScore = 3; result.MlScore = 3; // max out = obvious bad
                    result.RedFlags.Add("Invalid or malformed URL");
                    ApplyFinalVerdict(result);
                    return result;
                }

                // ── Step 1 & 2: VirusTotal + GSB run in parallel ──────────
                await Task.WhenAll(
                    ScoreVirusTotalAsync(result, finalUrl),
                    ScoreGoogleSafeBrowsingAsync(result, finalUrl)
                );

                // ── Step 3: ML model — skip if already condemned ──────────
                bool alreadyFlagged = result.VtScore >= 3 || result.GsbScore >= 2;
                if (!alreadyFlagged)
                    await ScoreMlModelAsync(result, finalUrl);
                else
                    result.Warnings.Add("ML model skipped — threat already confirmed by external engines");

                // ── Step 4: derive final verdict from score ───────────────
                ApplyFinalVerdict(result);
                return result;
            }
            catch (Exception ex)
            {
                result.IsSafe = false;
                result.SafetyLevel = "Unknown";
                result.Message = "Unable to complete safety analysis.";
                result.Warnings.Add($"Analysis error: {ex.Message}");
                return result;
            }
        }

        // ── Scoring helpers ───────────────────────────────────────────────

        private async Task ScoreVirusTotalAsync(SafetyAnalysisResultDto result, string url)
        {
            try
            {
                var apiKey = _configuration["SecurityAnalysis:VirusTotal:ApiKey"];
                var enabled = _configuration.GetValue<bool>("SecurityAnalysis:VirusTotal:Enabled");

                if (!enabled || string.IsNullOrEmpty(apiKey))
                {
                    result.VtScore = 0; // benefit of the doubt
                    result.Warnings.Add("VirusTotal check skipped (not configured)");
                    return;
                }

                // Submit
                var submitReq = new HttpRequestMessage(HttpMethod.Post,
                    "https://www.virustotal.com/api/v3/urls")
                {
                    Content = new StringContent(
                        $"url={Uri.EscapeDataString(url)}",
                        Encoding.UTF8, "application/x-www-form-urlencoded")
                };
                submitReq.Headers.Add("x-apikey", apiKey);

                var submitResp = await _httpClient.SendAsync(submitReq);
                if (!submitResp.IsSuccessStatusCode)
                {
                    result.VtScore = 0;
                    result.Warnings.Add($"VirusTotal submission failed: {submitResp.StatusCode}");
                    return;
                }

                var submitData = JsonSerializer.Deserialize<VirusTotalSubmitResponse>(
                    await submitResp.Content.ReadAsStringAsync());

                if (submitData?.Data?.Id is null)
                {
                    result.VtScore = 0;
                    result.Warnings.Add("VirusTotal: could not get analysis ID");
                    return;
                }

                await Task.Delay(2000);

                // Retrieve analysis
                var analysisReq = new HttpRequestMessage(HttpMethod.Get,
                    $"https://www.virustotal.com/api/v3/analyses/{submitData.Data.Id}");
                analysisReq.Headers.Add("x-apikey", apiKey);

                var analysisResp = await _httpClient.SendAsync(analysisReq);
                if (!analysisResp.IsSuccessStatusCode)
                {
                    result.VtScore = 0;
                    result.Warnings.Add($"VirusTotal analysis retrieval failed: {analysisResp.StatusCode}");
                    return;
                }

                var analysis = JsonSerializer.Deserialize<VirusTotalAnalysisResponse>(
                    await analysisResp.Content.ReadAsStringAsync());

                var stats = analysis?.Data?.Attributes?.Stats;
                if (stats is null)
                {
                    result.VtScore = 0;
                    result.Warnings.Add("VirusTotal: analysis still in progress or unavailable");
                    return;
                }

                var totalEngines = stats.Harmless + stats.Malicious
                                 + stats.Suspicious + stats.Undetected + stats.Timeout;
                var flagged = stats.Malicious + stats.Suspicious;

                // Ratio-based scoring: 1 noisy engine out of 95 ≠ dangerous
                result.VtScore = flagged switch
                {
                    0 => 0,
                    <= 2 => 1,
                    <= 5 => 2,
                    <= 10 => 3,
                    _ => 4
                };

                var detail = $"VirusTotal: {flagged}/{totalEngines} engines flagged";
                if (result.VtScore >= 2)
                    result.RedFlags.Add(detail);
                else if (result.VtScore == 1)
                    result.Warnings.Add($"{detail} (low confidence — likely false positive)");
                else
                    result.Warnings.Add($"VirusTotal: scanned by {totalEngines} engines — clean");
            }
            catch (HttpRequestException ex) { result.VtScore = 0; result.Warnings.Add($"VirusTotal API error: {ex.Message}"); }
            catch (TaskCanceledException) { result.VtScore = 0; result.Warnings.Add("VirusTotal API timeout"); }
            catch (Exception ex) { result.VtScore = 0; result.Warnings.Add($"VirusTotal check failed: {ex.Message}"); }
        }

        private async Task ScoreGoogleSafeBrowsingAsync(SafetyAnalysisResultDto result, string url)
        {
            try
            {
                var apiKey = _configuration["SecurityAnalysis:GoogleSafeBrowsing:ApiKey"];
                var enabled = _configuration.GetValue<bool>("SecurityAnalysis:GoogleSafeBrowsing:Enabled");

                if (!enabled || string.IsNullOrEmpty(apiKey))
                {
                    result.GsbScore = 0;
                    result.Warnings.Add("Google Safe Browsing check skipped (not configured)");
                    return;
                }

                var payload = new
                {
                    client = new { clientId = "CyberBrief", clientVersion = "1.0.0" },
                    threatInfo = new
                    {
                        threatTypes = new[]
                        {
                            "MALWARE", "SOCIAL_ENGINEERING",
                            "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"
                        },
                        platformTypes = new[] { "ANY_PLATFORM" },
                        threatEntryTypes = new[] { "URL" },
                        threatEntries = new[] { new { url } }
                    }
                };

                var response = await _httpClient.PostAsync(
                    $"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={apiKey}",
                    new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json"));

                var body = await response.Content.ReadAsStringAsync();

                if (!response.IsSuccessStatusCode)
                {
                    result.GsbScore = 0;
                    result.Warnings.Add($"Google Safe Browsing error: {response.StatusCode}");
                    return;
                }

                if (string.IsNullOrWhiteSpace(body) || body == "{}")
                {
                    result.GsbScore = 0;
                    result.Warnings.Add("Google Safe Browsing: URL appears safe");
                    return;
                }

                var threatResp = JsonSerializer.Deserialize<GoogleSafeBrowsingThreatResponse>(body);
                if (threatResp?.Matches is null || !threatResp.Matches.Any())
                {
                    result.GsbScore = 0;
                    result.Warnings.Add("Google Safe Browsing: URL appears safe");
                    return;
                }

                var distinctThreats = threatResp.Matches.Select(m => m.ThreatType).Distinct().ToList();

                // 2 = any match, 3 = multiple distinct threat types
                result.GsbScore = distinctThreats.Count >= 2 ? 3 : 2;

                var threatList = string.Join(", ", distinctThreats);
                result.RedFlags.Add($"Google Safe Browsing: flagged for {threatList}");
            }
            catch (HttpRequestException ex) { result.GsbScore = 0; result.Warnings.Add($"GSB API error: {ex.Message}"); }
            catch (TaskCanceledException) { result.GsbScore = 0; result.Warnings.Add("GSB API timeout"); }
            catch (Exception ex) { result.GsbScore = 0; result.Warnings.Add($"GSB check failed: {ex.Message}"); }
        }

        private async Task ScoreMlModelAsync(SafetyAnalysisResultDto result, string url)
        {
            try
            {
                var body = new StringContent(
                    JsonSerializer.Serialize(new { url }),
                    Encoding.UTF8, "application/json");

                var response = await _httpClient.PostAsync($"{ModelBaseUrl}/analyze", body);

                if (!response.IsSuccessStatusCode)
                {
                    result.MlScore = 0;
                    result.Warnings.Add($"ML model check failed: {response.StatusCode}");
                    return;
                }

                var prediction = JsonSerializer.Deserialize<UrlPredictionResponse>(
                    await response.Content.ReadAsStringAsync());

                if (prediction is null)
                {
                    result.MlScore = 0;
                    result.Warnings.Add("ML model returned an empty response");
                    return;
                }

                result.ModelVerdict = prediction.Verdict;
                result.ModelConfidence = prediction.Confidence;
                result.ModelFlags = prediction.Flags;

                switch (prediction.Verdict.ToLower())
                {
                    case "phishing":
                    case "malware":
                        // High confidence (≥70%) = 3, lower = 2
                        result.MlScore = prediction.Confidence >= 0.70 ? 3 : 2;
                        result.RedFlags.Add(
                            $"ML model: {prediction.Verdict} detected " +
                            $"(confidence: {prediction.Confidence:P0})");
                        foreach (var flag in prediction.Flags)
                            result.RedFlags.Add($"Model flag: {flag}");
                        break;

                    case "safe":
                        // Safe but with flags → 1, purely safe → 0
                        result.MlScore = prediction.Flags.Any() ? 1 : 0;
                        foreach (var flag in prediction.Flags)
                            result.Warnings.Add($"Model notice: {flag}");
                        break;

                    default:
                        result.MlScore = 0;
                        result.Warnings.Add($"ML model returned unknown verdict: {prediction.Verdict}");
                        break;
                }
            }
            catch (HttpRequestException ex) { result.MlScore = 0; result.Warnings.Add($"ML model API error: {ex.Message}"); }
            catch (TaskCanceledException) { result.MlScore = 0; result.Warnings.Add("ML model API timeout"); }
            catch (Exception ex) { result.MlScore = 0; result.Warnings.Add($"ML model check failed: {ex.Message}"); }
        }

        // ── Final verdict from score ──────────────────────────────────────

        private static void ApplyFinalVerdict(SafetyAnalysisResultDto result)
        {
            (result.SafetyLevel, result.IsSafe, result.Message) = result.ThreatScore switch
            {
                <= 1 => ("Safe", true, "✅ No significant threats detected."),
                <= 3 => ("Low Risk", true, "✅ Minor signals detected — likely safe, but stay alert."),
                <= 5 => ("Suspicious", false, "⚠️ Suspicious characteristics found. Proceed with caution."),
                <= 7 => ("High Risk", false, "🔶 Multiple threat signals detected. Avoid if unsure."),
                _ => ("Dangerous", false, "🚨 This link appears dangerous. Do not proceed.")
            };
        }

        private static bool IsValidUrl(string url) =>
            Uri.TryCreate(url, UriKind.Absolute, out var uri) &&
            (uri.Scheme == Uri.UriSchemeHttp || uri.Scheme == Uri.UriSchemeHttps);
    }
}