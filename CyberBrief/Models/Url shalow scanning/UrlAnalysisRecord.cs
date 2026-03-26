using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace CyberBrief.Models.Url_shalow_scanning
{
    public class UrlAnalysisRecord
    {
        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public string Url { get; set; } = string.Empty;

        public string ResultJson { get; set; } = string.Empty;

        public DateTime AnalyzedAt { get; set; } = DateTime.UtcNow;

    }
}
