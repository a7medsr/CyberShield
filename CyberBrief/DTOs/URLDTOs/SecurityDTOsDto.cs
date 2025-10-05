using System.Text.Json.Serialization;

namespace CyberBrief.Models
{
    // VirusTotal API Response Models
    public class VirusTotalSubmitResponse
    {
        [JsonPropertyName("data")]
        public VirusTotalSubmitData? Data { get; set; }
    }

    public class VirusTotalSubmitData
    {
        [JsonPropertyName("id")]
        public string? Id { get; set; }
    }

    public class VirusTotalAnalysisResponse
    {
        [JsonPropertyName("data")]
        public VirusTotalAnalysisData? Data { get; set; }
    }

    public class VirusTotalAnalysisData
    {
        [JsonPropertyName("attributes")]
        public VirusTotalAttributes? Attributes { get; set; }
    }

    public class VirusTotalAttributes
    {
        [JsonPropertyName("stats")]
        public VirusTotalStats? Stats { get; set; }

        [JsonPropertyName("status")]
        public string? Status { get; set; }
    }

    public class VirusTotalStats
    {
        [JsonPropertyName("harmless")]
        public int Harmless { get; set; }

        [JsonPropertyName("malicious")]
        public int Malicious { get; set; }

        [JsonPropertyName("suspicious")]
        public int Suspicious { get; set; }

        [JsonPropertyName("undetected")]
        public int Undetected { get; set; }

        [JsonPropertyName("timeout")]
        public int Timeout { get; set; }
    }

    // Google Safe Browsing API Response Models
    public class GoogleSafeBrowsingThreatResponse
    {
        [JsonPropertyName("matches")]
        public List<GoogleSafeBrowsingMatch>? Matches { get; set; }
    }

    public class GoogleSafeBrowsingMatch
    {
        [JsonPropertyName("threatType")]
        public string ThreatType { get; set; } = string.Empty;

        [JsonPropertyName("platformType")]
        public string PlatformType { get; set; } = string.Empty;

        [JsonPropertyName("threatEntryType")]
        public string ThreatEntryType { get; set; } = string.Empty;
    }
}
