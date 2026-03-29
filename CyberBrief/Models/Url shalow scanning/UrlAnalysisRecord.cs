using CyberBrief.Models.User;
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

        // ── score columns ──────────────────────────────────────────
        public int VtScore { get; set; }       // 0–4
        public int GsbScore { get; set; }      // 0–3
        public int MlScore { get; set; }       // 0–3

        [NotMapped]
        public int ThreatScore => VtScore + GsbScore + MlScore;  // 0–10, derived — no extra column needed

        public string ThreatLevel { get; set; } = string.Empty;  // "Safe" / "Low Risk" / "Suspicious" / "High Risk" / "Dangerous"

        // ── navigation ─────────────────────────────────────────────
        public ICollection<BaseUser> Users { get; set; } = new List<BaseUser>();
    }
}