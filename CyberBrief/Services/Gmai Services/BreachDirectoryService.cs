using CyberBrief.Dtos.Gmail;
using Newtonsoft.Json;
namespace CyberBrief.Services
{
    public class BreachDirectoryService
    {
        private readonly HttpClient _httpClient;
        private readonly string _apiKey;

        public BreachDirectoryService(HttpClient httpClient, string apiKey)
        {
            _httpClient = httpClient;
            _apiKey = apiKey;
        }
        public async Task<BreachResponseDto?> CheckEmailAsync(string email)
        {
            var request = new HttpRequestMessage(HttpMethod.Get,
                $"?func=auto&term={Uri.EscapeDataString(email)}");

            request.Headers.Add("x-rapidapi-key", _apiKey);
            request.Headers.Add("x-rapidapi-host", "breachdirectory.p.rapidapi.com");

            try
            {
                var response = await _httpClient.SendAsync(request);

                if (response.StatusCode == System.Net.HttpStatusCode.TooManyRequests)
                {
                    // Return null if API limit exceeded
                    return new BreachResponseDto
                    {
                        Success = false,
                        Message = "Too many requests. Please try again later."
                    };
                }

                if (!response.IsSuccessStatusCode)
                {
                    return new BreachResponseDto
                    {
                        Success = false,
                        Message = $"API call failed with status {response.StatusCode}"
                    };
                }

                var body = await response.Content.ReadAsStringAsync();
                return JsonConvert.DeserializeObject<BreachResponseDto>(body);
            }
            catch (HttpRequestException ex)
            {
                return new BreachResponseDto
                {
                    Success = false,
                    Message = $"Network error: {ex.Message}"
                };
            }
            catch (Exception ex)
            {
                return new BreachResponseDto
                {
                    Success = false,
                    Message = $"Unexpected error: {ex.Message}"
                };
            }
        }





    }
}
