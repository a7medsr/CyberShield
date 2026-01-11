using System.Diagnostics.Metrics;
using static System.Net.Mime.MediaTypeNames;

namespace CyberBrief.DTOs.Container
{
    //public class RawScanResponse
    //{
    //    public Summary Summary { get; set; }
    //    public List<RawVulnerability> Vulnerabilities { get; set; }
    //}
    public class ScanResultDto
    {
        public string Id { get; set; }
        public string Name { get; set; }
        public string Tag { get; set; }
        public DateTime StartedAt { get; set; }
        public DateTime FinishedAt { get; set; }
        public int Critical { get; set; }
        public int High { get; set; }
        public int Medium { get; set; }
        public int Low { get; set; }
        public int Total { get; set; }
        public List<RawVulnerability> Vulnerabilities { get; set; }
    }
    public class ScanApiResponse
    {
        public SummaryDto Summary { get; set; }
        public List<RawVulnerability> Vulnerabilities { get; set; }
    }
    public class SummaryDto
    {
        public string Id { get; set; }
        public ImageDto Image { get; set; }
        public string Status { get; set; }
        public DateTime StartedAt { get; set; }
        public DateTime FinishedAt { get; set; }
        public CountsDto Counts { get; set; }
    }
    public class ImageDto
    {
        public string Name { get; set; }
        public string Tag { get; set; }
        public string Id { get; set; }
    }
    public class CountsDto
    {
        public int Critical { get; set; }
        public int High { get; set; }
        public int Medium { get; set; }
        public int Low { get; set; }
        public int Total { get; set; }
    }



    //public class Summary
    //{
    //    public string Id { get; set; }
    //    public Image Image { get; set; }
    //    public DateTime StartedAt { get; set; }
    //    public DateTime FinishedAt { get; set; }
    //    public Counts Counts { get; set; }
    //}
    //public class Image
    //{
    //    public string Name { get; set; }
    //    public string Tag { get; set; }
    //}

    //public class Counts
    //{
    //    public int Critical { get; set; }
    //    public int High { get; set; }
    //    public int Medium { get; set; }
    //    public int Low { get; set; }
    //    public int Total { get; set; }
    //}
    public class RawVulnerability
    {
        public string Package { get; set; }
        public string Vulnerability { get; set; }
        public string Severity { get; set; }
        public string Source { get; set; }
    }


}
