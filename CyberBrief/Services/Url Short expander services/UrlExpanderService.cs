using CyberBrief.Dtos.URLModels;
using CyberBrief.Services.IServices;

namespace CyberBrief.Services
{
    public class UrlExpanderService : IUrlExpanderService
    {
        private readonly HttpClient _httpClient;
        private readonly ISafetyAnalyzerService _safetyAnalyzer;
        private const int MaxRedirects = 10;

        public UrlExpanderService(HttpClient httpClient, ISafetyAnalyzerService safetyAnalyzer)
        {
            _httpClient = httpClient;
            _safetyAnalyzer = safetyAnalyzer;
        }

        public async Task<UrlExpansionResultDto> ExtractShortUrlAsync(string shortUrl)
        {
            var result = new UrlExpansionResultDto();

            try
            {
                if (string.IsNullOrWhiteSpace(shortUrl))
                {
                    result.ErrorMessage = "URL cannot be null or empty";
                    return result;
                }

                // Ensure URL has a scheme
                if (!shortUrl.StartsWith("http://") && !shortUrl.StartsWith("https://"))
                {
                    shortUrl = "https://" + shortUrl;
                }

                var currentUrl = shortUrl;
                var redirectCount = 0;

                // Follow redirects manually
                while (redirectCount < MaxRedirects)
                {
                    var request = new HttpRequestMessage(HttpMethod.Get, currentUrl);
                    var response = await _httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead);

                    // Check if it's a redirect
                    if ((int)response.StatusCode >= 300 && (int)response.StatusCode < 400)
                    {
                        if (response.Headers.Location != null)
                        {
                            var redirectUrl = response.Headers.Location.IsAbsoluteUri
                                ? response.Headers.Location.ToString()
                                : new Uri(new Uri(currentUrl), response.Headers.Location).ToString();

                            result.RedirectionLinks.Add(redirectUrl);
                            currentUrl = redirectUrl;
                            redirectCount++;
                        }
                        else
                        {
                            break;
                        }
                    }
                    else
                    {
                        // Final destination reached — only add to chain if we actually redirected
                        result.FinalUrl = currentUrl;
                        if (redirectCount > 0 && !result.RedirectionLinks.Contains(currentUrl))
                        {
                            result.RedirectionLinks.Add(currentUrl);
                        }
                        break;
                    }

                    response.Dispose();
                }

                if (redirectCount >= MaxRedirects)
                {
                    result.ErrorMessage = $"Maximum redirects ({MaxRedirects}) exceeded";
                    return result;
                }

                result.FinalUrl ??= currentUrl;
                result.IsSuccess = true;

                // Perform safety analysis
                if (!string.IsNullOrEmpty(result.FinalUrl))
                {
                    result.SafetyAnalysis = await _safetyAnalyzer.AnalyzeUrlSafetyAsync(
                        result.FinalUrl, result.RedirectionLinks);
                }

                return result;
            }
            catch (HttpRequestException ex)
            {
                // Host unreachable / DNS failure — still run safety analysis on the URL string
                result.FinalUrl = shortUrl;
                result.IsSuccess = true;

                result.SafetyAnalysis = await _safetyAnalyzer.AnalyzeUrlSafetyAsync(
                    result.FinalUrl, result.RedirectionLinks);

                result.SafetyAnalysis.Warnings.Insert(0,
                    $"Host unreachable — URL could not be fetched: {ex.Message}");

                return result;
            }
            catch (Exception ex)
            {
                result.ErrorMessage = $"Unexpected error: {ex.Message}";
                return result;
            }
        }
    }
}