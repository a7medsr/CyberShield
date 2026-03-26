using CyberBrief.Models.User;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace CyberBrief.Models
{
    public class TriageCache
    {
        [Key]
        public string ResourceHash { get; set; } 
        public string SampleId { get; set; }     
        public string Status { get; set; }       
        public int? Score { get; set; }
        [Column(TypeName = "nvarchar(max)")]
        public string? RawJson { get; set; }
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        public ICollection<BaseUser> Users { get; set; } = new List<BaseUser>();

    }
}
