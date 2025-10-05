using CyberBrief.Models;
using CyberBrief.Dtos.URLModels;
using CyberBrief.Services.IServices;

namespace CyberBrief.Services
{
    public class AdvancedSafetyAnalyzerService : ISafetyAnalyzerService
    {
        private readonly HttpClient _httpClient;
        private readonly IConfiguration _configuration;

        public AdvancedSafetyAnalyzerService(HttpClient httpClient, IConfiguration configuration)
        {
            _httpClient = httpClient;
            _configuration = configuration;
        }

        // Synchronous version (for interface compatibility)
        public SafetyAnalysisResultDto AnalyzeUrlSafety(string finalUrl, List<string> redirectionChain)
        {
            return AnalyzeUrlSafetyAsync(finalUrl, redirectionChain).GetAwaiter().GetResult();
        }

        // Main async analysis method
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

                // Step 2: Basic pattern analysis
                await PerformBasicAnalysis(result, finalUrl, redirectionChain);

                // Step 3: External API checks - WE'LL IMPLEMENT THESE NEXT
                await CheckWithVirusTotalAsync(result, finalUrl);
                await CheckWithGoogleSafeBrowsingAsync(result, finalUrl);

                // Step 4: Final safety determination
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

        private async Task PerformBasicAnalysis(SafetyAnalysisResultDto result, string finalUrl, List<string> redirectionChain)
        {
            var uri = new Uri(finalUrl);
            var domain = uri.Host.ToLower();

            // Check redirect count
            if (redirectionChain.Count > 5)
            {
                result.Warnings.Add($"Multiple redirects detected ({redirectionChain.Count} hops)");
            }

            // Check for IP addresses instead of domains
            if (System.Net.IPAddress.TryParse(domain, out _))
            {
                result.RedFlags.Add("URL uses IP address instead of domain name");
            }

            // Check for suspicious ports
            if (uri.Port != 80 && uri.Port != 443 && uri.Port != -1)
            {
                result.Warnings.Add($"Non-standard port detected: {uri.Port}");
            }

            // Check URL length (very long URLs can be suspicious)
            if (finalUrl.Length > 200)
            {
                result.Warnings.Add("Unusually long URL detected");
            }

            // Check for common suspicious keywords
            var suspiciousKeywords = new[] { "free", "win", "prize", "urgent", "click", "download", "virus", "warning" };
            var urlLower = finalUrl.ToLower();

            foreach (var keyword in suspiciousKeywords)
            {
                if (urlLower.Contains(keyword))
                {
                    result.Warnings.Add($"Suspicious keyword found: '{keyword}'");
                    break; // Don't spam warnings
                }
            }

            await Task.CompletedTask;
        }

        private void DetermineFinalSafety(SafetyAnalysisResultDto result)
        {
            if (result.RedFlags.Any())
            {
                result.IsSafe = false;
                result.SafetyLevel = "Dangerous";
                result.Message = "🚨 This link appears to be dangerous. Multiple red flags detected.";
            }
            else if (result.Warnings.Count >= 3)
            {
                result.IsSafe = false;
                result.SafetyLevel = "Suspicious";
                result.Message = "⚠️ This link shows multiple suspicious characteristics. Proceed with extreme caution.";
            }
            else if (result.Warnings.Any())
            {
                result.IsSafe = false;
                result.SafetyLevel = "Suspicious";
                result.Message = "⚠️ This link shows some suspicious characteristics. Proceed with caution.";
            }
            else if (result.SafetyLevel == "Unknown")
            {
                result.IsSafe = true;
                result.SafetyLevel = "Likely Safe";
                result.Message = "✅ No obvious red flags detected, but always be cautious with unfamiliar links.";
            }
        }

        private async Task CheckWithVirusTotalAsync(SafetyAnalysisResultDto result, string url)
        {
            try
            {
                // Check if VirusTotal is enabled and has API key
                var apiKey = _configuration["SecurityAnalysis:VirusTotal:ApiKey"];
                var enabled = _configuration.GetValue<bool>("SecurityAnalysis:VirusTotal:Enabled");

                if (!enabled || string.IsNullOrEmpty(apiKey))
                {
                    result.Warnings.Add("VirusTotal check skipped (not configured)");
                    return;
                }

                // VirusTotal API v3 URL analysis
                var vtUrl = $"https://www.virustotal.com/api/v3/urls";

                // Step 1: Submit URL for analysis
                var submitData = new StringContent($"url={Uri.EscapeDataString(url)}",
                    System.Text.Encoding.UTF8, "application/x-www-form-urlencoded");

                var submitRequest = new HttpRequestMessage(HttpMethod.Post, vtUrl)
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

                var submitContent = await submitResponse.Content.ReadAsStringAsync();
                var submitResult = System.Text.Json.JsonSerializer.Deserialize<VirusTotalSubmitResponse>(submitContent);

                if (submitResult?.Data?.Id == null)
                {
                    result.Warnings.Add("VirusTotal: Unable to get analysis ID");
                    return;
                }
                
                // Step 2: Wait a moment and then get the analysis result
                await Task.Delay(2000); // Wait 2 seconds for analysis

                var analysisUrl = $"https://www.virustotal.com/api/v3/analyses/{submitResult.Data.Id}";
                var analysisRequest = new HttpRequestMessage(HttpMethod.Get, analysisUrl);
                analysisRequest.Headers.Add("x-apikey", apiKey);

                var analysisResponse = await _httpClient.SendAsync(analysisRequest);

                if (!analysisResponse.IsSuccessStatusCode)
                {
                    result.Warnings.Add($"VirusTotal analysis retrieval failed: {analysisResponse.StatusCode}");
                    return;
                }

                var analysisContent = await analysisResponse.Content.ReadAsStringAsync();
                var analysisResult = System.Text.Json.JsonSerializer.Deserialize<VirusTotalAnalysisResponse>(analysisContent);

                if (analysisResult?.Data?.Attributes?.Stats != null)
                {
                    var stats = analysisResult.Data.Attributes.Stats;
                    var totalEngines = stats.Harmless + stats.Malicious + stats.Suspicious + stats.Undetected + stats.Timeout;
                    var threatsDetected = stats.Malicious + stats.Suspicious;

                    if (threatsDetected > 0)
                    {
                        result.IsSafe = false;
                        result.SafetyLevel = stats.Malicious > 0 ? "Dangerous" : "Suspicious";
                        result.RedFlags.Add($"VirusTotal: {threatsDetected}/{totalEngines} security engines flagged this URL");

                        if (stats.Malicious > 0)
                        {
                            result.Message = "🚨 This URL has been flagged as malicious by security engines.";
                        }
                    }
                    else if (totalEngines > 0)
                    {
                        result.Warnings.Add($"VirusTotal: URL scanned by {totalEngines} engines - appears clean");
                    }
                }
                else
                {
                    result.Warnings.Add("VirusTotal: Analysis still in progress or unavailable");
                }
            }
            catch (HttpRequestException ex)
            {
                result.Warnings.Add($"VirusTotal API error: {ex.Message}");
            }
            catch (TaskCanceledException)
            {
                result.Warnings.Add("VirusTotal API timeout");
            }
            catch (Exception ex)
            {
                result.Warnings.Add($"VirusTotal check failed: {ex.Message}");
            }
        }

        private async Task CheckWithGoogleSafeBrowsingAsync(SafetyAnalysisResultDto result, string url)
        {
            try
            {
                // Check if Google Safe Browsing is enabled and has API key
                var apiKey = _configuration["SecurityAnalysis:GoogleSafeBrowsing:ApiKey"];
                var enabled = _configuration.GetValue<bool>("SecurityAnalysis:GoogleSafeBrowsing:Enabled");

                if (!enabled || string.IsNullOrEmpty(apiKey))
                {
                    result.Warnings.Add("Google Safe Browsing check skipped (not configured)");
                    return;
                }

                var safeBrowsingUrl = $"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={apiKey}";

                // Create the request payload
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
                    new { url = url }
                }
                    }
                };

                var jsonPayload = System.Text.Json.JsonSerializer.Serialize(requestPayload);
                var content = new StringContent(jsonPayload, System.Text.Encoding.UTF8, "application/json");

                var response = await _httpClient.PostAsync(safeBrowsingUrl, content);

                if (!response.IsSuccessStatusCode)
                {
                    result.Warnings.Add($"Google Safe Browsing API error: {response.StatusCode}");
                    return;
                }

                var responseContent = await response.Content.ReadAsStringAsync();

                // Empty response means no threats found
                if (string.IsNullOrWhiteSpace(responseContent) || responseContent == "{}")
                {
                    result.Warnings.Add("Google Safe Browsing: URL appears safe");
                    return;
                }

                // Parse the threat response
                var threatResponse = System.Text.Json.JsonSerializer.Deserialize<GoogleSafeBrowsingThreatResponse>(responseContent);

                if (threatResponse?.Matches != null && threatResponse.Matches.Any())
                {
                    result.IsSafe = false;
                    result.SafetyLevel = "Dangerous";

                    var threatTypes = threatResponse.Matches.Select(m => m.ThreatType).Distinct().ToList();
                    var threatList = string.Join(", ", threatTypes);

                    result.RedFlags.Add($"Google Safe Browsing: URL flagged for {threatList}");
                    result.Message = "🚨 This URL has been flagged by Google Safe Browsing as unsafe.";

                    // Add specific threat details
                    foreach (var match in threatResponse.Matches.Take(3)) // Limit to avoid spam
                    {
                        result.RedFlags.Add($"Threat detected: {match.ThreatType} on {match.PlatformType}");
                    }
                }
                else
                {
                    result.Warnings.Add("Google Safe Browsing: URL appears safe");
                }
            }
            catch (HttpRequestException ex)
            {
                result.Warnings.Add($"Google Safe Browsing API error: {ex.Message}");
            }
            catch (TaskCanceledException)
            {
                result.Warnings.Add("Google Safe Browsing API timeout");
            }
            catch (Exception ex)
            {
                result.Warnings.Add($"Google Safe Browsing check failed: {ex.Message}");
            }
        }
    }


}
