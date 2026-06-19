namespace CyberBrief.Services.IServices;

public interface ICVEexplanationService
{
    Task<List<Vulnerability>> GetExplanation(string imageName);

    /// <summary>
    /// Enrich any CVE-bearing items (container vulnerabilities or web findings)
    /// with an NVD/OSV description + patch. Persists changes.
    /// </summary>
    Task EnrichAsync(IList<ICveEnrichable> items);

    /// <summary>
    /// Enrich the web-scan findings of a given scan that carry a CVE and have no
    /// explanation yet. Reuses the same NVD/OSV logic as the container flow.
    /// </summary>
    Task EnrichWebCvesAsync(string scanId);
}
