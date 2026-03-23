using CyberBrief.Context;
using CyberBrief.Dtos.Gmail;
using CyberBrief.DTOs.Gmail;
using CyberBrief.Models.Email_Checking;
using Microsoft.EntityFrameworkCore;
using Newtonsoft.Json;
namespace CyberBrief.Services
{
    public class BreachDirectoryService
    {
        private readonly HttpClient _httpClient;
        private readonly string _apiKey;
        private readonly CyberBriefDbContext _context;

        public BreachDirectoryService(HttpClient httpClient, string apiKey,CyberBriefDbContext context)
        {
            _httpClient = httpClient;
            _apiKey = apiKey;
            _context = context;
        }
        private async Task<BreachResponseDto?> CheckEmailOutsideDatabaseAsync(string email)
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

        public async Task<BreachCheckResultDto?> CheckEmail(string email)
        {
            // 1. Fetch from DB
            var existingEmail = await _context.Results
                .Include(x => x.Founds)
                .FirstOrDefaultAsync(x => x.Email == email);

            Result resultEntity;

            if (existingEmail == null)
            {
                // 2. Call API if not in DB
                var apiRes = await CheckEmailOutsideDatabaseAsync(email);
                if (apiRes == null || !apiRes.Success) return null;

                // 3. Create Entity and save to DB
                resultEntity = new Result
                {
                    Id = Guid.NewGuid().ToString(),
                    Email = email,
                    ResultsCount = apiRes.Found,
                    Status = apiRes.Success,
                    Founds = apiRes.Result?.Select(f => new Found
                    {
                        Id = Guid.NewGuid().ToString(),
                        Email = f.Email,
                        Passowrd = f.Password, // Mapping to your DB typo
                        Hash = f.Hash,
                        Source = f.Sources
                    }).ToList() ?? new List<Found>()
                };

                _context.Results.Add(resultEntity);
                await _context.SaveChangesAsync();
            }
            else
            {
                resultEntity = existingEmail;
            }

            // 4. Map Entity to Output DTO (This solves the Circular Reference!)
            return new BreachCheckResultDto
            {
                Email = resultEntity.Email,
                Status = resultEntity.Status,
                ResultsCount = resultEntity.ResultsCount,
                Founds = resultEntity.Founds?.Select(f => new FoundDto
                {
                    Email = f.Email,
                    Password = f.Passowrd,
                    Hash = f.Hash,
                    Source = f.Source
                }).ToList() ?? new List<FoundDto>()
            };
        }



    }
}
