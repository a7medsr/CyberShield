namespace CyberBrief.Services.IServices
{
    /// <summary>
    /// Anything that can be enriched with an NVD/OSV description + patch by the
    /// shared <see cref="ICVEexplanationService"/>. Implemented by both the
    /// container <c>Vulnerability</c> and the web-scan <c>WebFinding</c> so the
    /// same NVD/OSV logic powers both flows.
    /// </summary>
    public interface ICveEnrichable
    {
        string CveId { get; }
        string Package { get; }
        string? Explanation { get; set; }
        string? Patch { get; set; }
    }
}
