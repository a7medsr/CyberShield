using CyberBrief.DTOs.Container;

namespace CyberBrief.Services
{
    public class ContainerServices
    {
        public  ScanResultDto MapToDto(RawScanResponse raw)
        {
            return new ScanResultDto
            {
                Id = raw.Summary.Id,
                Name = raw.Summary.Image.Name,
                Tag = raw.Summary.Image.Tag,
                StartedAt = raw.Summary.StartedAt,
                FinishedAt = raw.Summary.FinishedAt,
                Counts = new VulnerabilityCountsDto
                {
                    Critical = raw.Summary.Counts.Critical,
                    High = raw.Summary.Counts.High,
                    Medium = raw.Summary.Counts.Medium,
                    Low = raw.Summary.Counts.Low,
                    Total = raw.Summary.Counts.Total
                },
                Vulnerabilities = raw.Vulnerabilities
                .GroupBy(v => new { v.Vulnerability })
                .Select(g => g.First())
                .Select(v => new VulnerabilityDto
                {
                    Package = v.Package,
                    Vulnerability = v.Vulnerability,
                    Severity = v.Severity,
                    Source = v.Source
                })
                .ToList()

                        };
        }

    }
}
