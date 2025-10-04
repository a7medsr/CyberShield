namespace CyberBrief.Models.Gmail
{

    public class PasswordReportDto
    {
        public string MaskedPassword { get; set; }
        public int Score { get; set; }
        public string ScoreText { get; set; }
        public double EntropyBits { get; set; }
        public double CrackTimeSeconds { get; set; }
        public string CrackTimeDisplay { get; set; }
        public int PwnedCount { get; set; }
        public bool IsPwned { get; set; }
        public string Summary { get; set; }
    }

}
