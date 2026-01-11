public class Summary
{
    public string Id { get; set; }
    public Image Image { get; set; }
    public string ImageId { get; set; }
    
    public string StartedAt { get; set; }
    public string FinishedAt { get; set; }
    public int TotalVulnerabilities { get; set; }
    public int CriticalVulnerabilities { get; set; }
    public int HighVulnerabilities { get; set; }
    public int MediumVulnerabilities { get; set; }
    public int LowVulnerabilities { get; set; }
    public virtual List<Vulnerability> Vulnerabilities { get; set; }
}