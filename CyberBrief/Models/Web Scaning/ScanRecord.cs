using CyberBrief.Models.User;
using System.ComponentModel.DataAnnotations;

namespace CyberBrief.Models.Web_Scaning
{
    public class ScanRecord
    {
        public string Id { get; set; }

        [Required]
        public string ScanId { get; set; } = string.Empty;

        [Required]
        public string Target { get; set; } = string.Empty;

        public string Status { get; set; } = string.Empty;

        public byte[]? PdfReport { get; set; }

        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        public ICollection<BaseUser> Users { get; set; } = new List<BaseUser>();

    }
}
