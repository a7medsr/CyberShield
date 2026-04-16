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
                // ── Guard: validate URL first ─────────────────────────────
                if (!IsValidUrl(finalUrl))
                {
                    result.IsSafe = false;
                    result.SafetyLevel = "Dangerous";
                    result.Message = "Invalid or malformed URL.";
                    result.RedFlags.Add("Invalid or malformed URL — cannot be analyzed.");
                    return result;
                }

                // ── Stage 1: VirusTotal + Google Safe Browsing in parallel ─
                await Task.WhenAll(
                    CheckVirusTotalAsync(result, finalUrl),
                    CheckGoogleSafeBrowsingAsync(result, finalUrl)
                );

                // ── Stage 1 verdict: if EITHER engine flagged anything → stop
                bool flaggedByExternalEngines = result.VtFlagged || result.GsbFlagged;

                if (flaggedByExternalEngines)
                {
                    result.IsSafe = false;
                    result.SafetyLevel = "Dangerous";
                    result.Message = BuildExternalEngineMessage(result);
                    result.Warnings.Add("ML model analysis was skipped — threat already confirmed by external security engines.");
                    return result;
                }

                // ── Stage 2: External engines gave the all-clear → run ML ──
                result.Warnings.Add("URL was not flagged by VirusTotal or Google Safe Browsing. Proceeding to ML model analysis...");

                await CheckMlModelAsync(result, finalUrl);

                // ── Final verdict based on ML result ──────────────────────
                ApplyMlVerdict(result);
                return result;
            }
            catch (Exception ex)
            {
                result.IsSafe = false;
                result.SafetyLevel = "Unknown";
                result.Message = "Unable to complete safety analysis.";
                result.Warnings.Add($"Unexpected analysis error: {ex.Message}");
                return result;
            }
        }

        // ── Stage 1: VirusTotal ───────────────────────────────────────────

        private async Task CheckVirusTotalAsync(SafetyAnalysisResultDto result, string url)
        {
            try
            {
                var apiKey = _configuration["SecurityAnalysis:VirusTotal:ApiKey"];
                var enabled = _configuration.GetValue<bool>("SecurityAnalysis:VirusTotal:Enabled");

                if (!enabled || string.IsNullOrEmpty(apiKey))
                {
                    result.VtFlagged = false;
                    result.Warnings.Add("VirusTotal check skipped (not configured).");
                    return;
                }

                // Submit URL for scanning
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
                    result.VtFlagged = false;
                    result.Warnings.Add($"VirusTotal submission failed: {submitResp.StatusCode}.");
                    return;
                }

                var submitData = JsonSerializer.Deserialize<VirusTotalSubmitResponse>(
                    await submitResp.Content.ReadAsStringAsync());

                if (submitData?.Data?.Id is null)
                {
                    result.VtFlagged = false;
                    result.Warnings.Add("VirusTotal: could not retrieve analysis ID.");
                    return;
                }

                // Brief wait for analysis to complete
                await Task.Delay(2000);

                // Retrieve analysis results
                var analysisReq = new HttpRequestMessage(HttpMethod.Get,
                    $"https://www.virustotal.com/api/v3/analyses/{submitData.Data.Id}");
                analysisReq.Headers.Add("x-apikey", apiKey);

                var analysisResp = await _httpClient.SendAsync(analysisReq);
                if (!analysisResp.IsSuccessStatusCode)
                {
                    result.VtFlagged = false;
                    result.Warnings.Add($"VirusTotal analysis retrieval failed: {analysisResp.StatusCode}.");
                    return;
                }

                var analysis = JsonSerializer.Deserialize<VirusTotalAnalysisResponse>(
                    await analysisResp.Content.ReadAsStringAsync());

                var stats = analysis?.Data?.Attributes?.Stats;
                if (stats is null)
                {
                    result.VtFlagged = false;
                    result.Warnings.Add("VirusTotal: analysis still in progress or returned no stats.");
                    return;
                }

                var totalEngines = stats.Harmless + stats.Malicious
                                 + stats.Suspicious + stats.Undetected + stats.Timeout;
                var maliciousCount = stats.Malicious;
                var suspiciousCount = stats.Suspicious;
                var totalFlagged = maliciousCount + suspiciousCount;

                // ANY malicious or suspicious flag = flagged
                if (totalFlagged >= 1)
                {
                    result.VtFlagged = true;
                    result.VtScore = totalFlagged;

                    var threatParts = new List<string>();
                    if (maliciousCount > 0)
                        threatParts.Add($"{maliciousCount} malicious");
                    if (suspiciousCount > 0)
                        threatParts.Add($"{suspiciousCount} suspicious");

                    result.RedFlags.Add(
                        $"VirusTotal: flagged by {string.Join(" and ", threatParts)} engine(s) out of {totalEngines} total.");
                }
                else
                {
                    result.VtFlagged = false;
                    result.VtScore = 0;
                    result.Warnings.Add($"VirusTotal: scanned by {totalEngines} engines — no threats detected.");
                }
            }
            catch (HttpRequestException ex) { result.VtFlagged = false; result.Warnings.Add($"VirusTotal API error: {ex.Message}"); }
            catch (TaskCanceledException) { result.VtFlagged = false; result.Warnings.Add("VirusTotal API timeout."); }
            catch (Exception ex) { result.VtFlagged = false; result.Warnings.Add($"VirusTotal check failed: {ex.Message}"); }
        }

        // ── Stage 1: Google Safe Browsing ─────────────────────────────────

        private async Task CheckGoogleSafeBrowsingAsync(SafetyAnalysisResultDto result, string url)
        {
            try
            {
                var apiKey = _configuration["SecurityAnalysis:GoogleSafeBrowsing:ApiKey"];
                var enabled = _configuration.GetValue<bool>("SecurityAnalysis:GoogleSafeBrowsing:Enabled");

                if (!enabled || string.IsNullOrEmpty(apiKey))
                {
                    result.GsbFlagged = false;
                    result.Warnings.Add("Google Safe Browsing check skipped (not configured).");
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
                    result.GsbFlagged = false;
                    result.Warnings.Add($"Google Safe Browsing API error: {response.StatusCode}.");
                    return;
                }

                // Empty body or "{}" means no threats found
                if (string.IsNullOrWhiteSpace(body) || body.Trim() == "{}")
                {
                    result.GsbFlagged = false;
                    result.Warnings.Add("Google Safe Browsing: no threats detected.");
                    return;
                }

                var threatResp = JsonSerializer.Deserialize<GoogleSafeBrowsingThreatResponse>(body);
                if (threatResp?.Matches is null || !threatResp.Matches.Any())
                {
                    result.GsbFlagged = false;
                    result.Warnings.Add("Google Safe Browsing: no threats detected.");
                    return;
                }

                // ANY match = flagged
                result.GsbFlagged = true;
                result.GsbScore = threatResp.Matches.Count;

                var distinctThreats = threatResp.Matches
                    .Select(m => m.ThreatType)
                    .Distinct()
                    .ToList();

                result.RedFlags.Add(
                    $"Google Safe Browsing: flagged for {string.Join(", ", distinctThreats)}.");
            }
            catch (HttpRequestException ex) { result.GsbFlagged = false; result.Warnings.Add($"GSB API error: {ex.Message}"); }
            catch (TaskCanceledException) { result.GsbFlagged = false; result.Warnings.Add("GSB API timeout."); }
            catch (Exception ex) { result.GsbFlagged = false; result.Warnings.Add($"GSB check failed: {ex.Message}"); }
        }

        // ── Stage 2: ML Model ─────────────────────────────────────────────

        private async Task CheckMlModelAsync(SafetyAnalysisResultDto result, string url)
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
                    result.Warnings.Add($"ML model check failed: {response.StatusCode}.");
                    return;
                }

                var prediction = JsonSerializer.Deserialize<UrlPredictionResponse>(
                    await response.Content.ReadAsStringAsync());

                if (prediction is null)
                {
                    result.MlScore = 0;
                    result.Warnings.Add("ML model returned an empty response.");
                    return;
                }

                result.ModelVerdict = prediction.Verdict;
                result.ModelConfidence = prediction.Confidence;
                result.ModelFlags = prediction.Flags;

                switch (prediction.Verdict.ToLower())
                {
                    case "phishing":
                    case "malware":
                        result.MlScore = prediction.Confidence >= 0.70 ? 3 : 2;
                        result.RedFlags.Add(
                            $"ML model: {prediction.Verdict} detected " +
                            $"(confidence: {prediction.Confidence:P0}).");
                        foreach (var flag in prediction.Flags)
                            result.RedFlags.Add($"Model flag: {flag}");
                        break;

                    case "safe":
                        result.MlScore = prediction.Flags.Any() ? 1 : 0;
                        foreach (var flag in prediction.Flags)
                            result.Warnings.Add($"Model notice: {flag}");
                        break;

                    default:
                        result.MlScore = 0;
                        result.Warnings.Add($"ML model returned unknown verdict: {prediction.Verdict}.");
                        break;
                }
            }
            catch (HttpRequestException ex) { result.MlScore = 0; result.Warnings.Add($"ML model API error: {ex.Message}"); }
            catch (TaskCanceledException) { result.MlScore = 0; result.Warnings.Add("ML model API timeout."); }
            catch (Exception ex) { result.MlScore = 0; result.Warnings.Add($"ML model check failed: {ex.Message}"); }
        }

        // ── Verdict helpers ───────────────────────────────────────────────

        /// <summary>
        /// Builds a human-readable message when Stage 1 engines flag the URL.
        /// Describes exactly which engine(s) flagged it and what for.
        /// </summary>
        private static string BuildExternalEngineMessage(SafetyAnalysisResultDto result)
        {
            var sources = new List<string>();
            if (result.VtFlagged) sources.Add("VirusTotal");
            if (result.GsbFlagged) sources.Add("Google Safe Browsing");

            var engineList = string.Join(" and ", sources);
            var threats = result.RedFlags.Any()
                ? " Detected: " + string.Join("; ", result.RedFlags) + "."
                : string.Empty;

            return $"This URL was flagged as dangerous by {engineList}.{threats} Do not proceed.";
        }

        /// <summary>
        /// Sets the final verdict fields after the ML model has run (Stage 2 only).
        /// </summary>
        private static void ApplyMlVerdict(SafetyAnalysisResultDto result)
        {
            (result.SafetyLevel, result.IsSafe, result.Message) = result.MlScore switch
            {
                0 => ("Safe", true, "URL was not flagged by any engine. ML model found no threats."),
                1 => ("Low Risk", true, "ML model found minor signals — likely safe, but stay alert."),
                2 => ("Suspicious", false, "ML model detected suspicious characteristics. Proceed with caution."),
                _ => ("Dangerous", false, "ML model identified this URL as a threat. Do not proceed.")
            };
        }

        private static bool IsValidUrl(string url) =>
            Uri.TryCreate(url, UriKind.Absolute, out var uri) &&
            (uri.Scheme == Uri.UriSchemeHttp || uri.Scheme == Uri.UriSchemeHttps);
    }
}