using CyberBrief.Models.URLModels;

namespace CyberBrief.Services.IServices
{
    public interface IUrlExpanderService
    {
     Task<UrlExpansionResultDto> ExtractShortUrlAsync(string shortUrl);
    }
}
