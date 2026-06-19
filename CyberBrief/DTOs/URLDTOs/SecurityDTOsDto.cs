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
    public class UrlPredictionResponse
    {
        [JsonPropertyName("url")]
        public string Url { get; set; } = string.Empty;

        // The model now returns "label" instead of "verdict"
        // (vocabulary: benign | phishing | malware | defacement).
        [JsonPropertyName("label")]
        public string Verdict { get; set; } = string.Empty;

        [JsonPropertyName("confidence")]
        public double Confidence { get; set; }

        [JsonPropertyName("probabilities")]
        public UrlPredictionProbabilities Probabilities { get; set; } = new();

        [JsonPropertyName("is_malicious")]
        public bool IsMalicious { get; set; }

        // Replaces the old "layer" field.
        [JsonPropertyName("source")]
        public string Source { get; set; } = string.Empty;

        // Replaces the old "latency_ms" field.
        [JsonPropertyName("response_time_ms")]
        public double ResponseTimeMs { get; set; }

        // The model no longer returns per-prediction flags. Kept (and ignored
        // during deserialization) so existing consumers still get an empty list
        // instead of null.
        [JsonIgnore]
        public List<string> Flags { get; set; } = new();
    }

    public class UrlPredictionProbabilities
    {
        [JsonPropertyName("benign")]
        public double Benign { get; set; }

        [JsonPropertyName("defacement")]
        public double Defacement { get; set; }

        [JsonPropertyName("malware")]
        public double Malware { get; set; }

        [JsonPropertyName("phishing")]
        public double Phishing { get; set; }
    }
}
