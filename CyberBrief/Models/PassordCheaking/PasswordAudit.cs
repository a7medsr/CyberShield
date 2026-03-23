using System.ComponentModel.DataAnnotations;

namespace CyberBrief.Models.PassordCheaking
{
    public class PasswordAudit
    {
        [Key]
        public string PasswordHash { get; set; }
        public int PwnedCount { get; set; }
        public double Entropy { get; set; }
        public int Score { get; set; }
        public string CrackTimeDisplay { get; set; }
        public DateTime CheckedAt { get; set; } = DateTime.UtcNow;
    }
}
