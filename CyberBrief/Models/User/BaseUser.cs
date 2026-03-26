using CyberBrief.Models.Url_shalow_scanning;
using CyberBrief.Models.Web_Scaning;
using Microsoft.AspNetCore.Identity;

namespace CyberBrief.Models.User
{
    public class BaseUser: IdentityUser
    {
        public string FirstName { get; set; } = string.Empty;
        public string LastName { get; set; } = string.Empty;
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        public string FullName => $"{FirstName} {LastName}";
        // add this to BaseUser.cs
        public ICollection<UrlAnalysisRecord> ScannedUrls { get; set; } = new List<UrlAnalysisRecord>();
        public ICollection<TriageCache> TriageScans { get; set; } = new List<TriageCache>();
        public ICollection<Image> ContainerScans { get; set; } = new List<Image>();
        public ICollection<ScanRecord> WebScans { get; set; } = new List<ScanRecord>();




    }
}
