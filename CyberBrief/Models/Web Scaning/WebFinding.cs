using System.ComponentModel.DataAnnotations.Schema;
using CyberBrief.Services.IServices;

namespace CyberBrief.Models.Web_Scaning
{
    /// <summary>
    /// A single web-scan finding, mirroring the container <c>Vulnerability</c>.
    /// CVE-bearing rows (<see cref="Cve"/> not null) are enriched with an
    /// NVD/OSV <see cref="Explanation"/> + <see cref="Patch"/> by the shared
    /// <see cref="ICVEexplanationService"/>.
    /// </summary>
    public class WebFinding : ICveEnrichable
    {
        public string Id { get; set; } = string.Empty;

        public string SummaryId { get; set; } = string.Empty;
        public WebScanSummary Summary { get; set; } = null!;

        public string Source { get; set; } = string.Empty;   // scanning tool (zap, nmap, nikto…)
        public string Severity { get; set; } = string.Empty;  // critical/high/medium/low/info
        public string Issue { get; set; } = string.Empty;     // finding title / affected product (cpe)
        public string? Cve { get; set; }                      // null for non-CVE findings
        public string? Endpoint { get; set; }
        public string? Description { get; set; }
        public string? Explanation { get; set; }
        public string? Patch { get; set; }
        public string? ReferenceUrl { get; set; }

        // ── ICveEnrichable ──
        [NotMapped]
        public string CveId => Cve ?? string.Empty;

        [NotMapped]
        public string Package => Issue;
    }
}
