using CyberBrief.Context;
using CyberBrief.DTOs.Web_Scan;
using CyberBrief.Models.Web_Scaning;
using CyberBrief.Services.IServices;
using Microsoft.EntityFrameworkCore;
using System;
using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace CyberBrief.Services.Web_scan_services
{
    public class ScanService : IScanService
    {
        private readonly HttpClient _httpClient;
        private readonly CyberBriefDbContext _db;
        private readonly ICVEexplanationService _cve;
        private const string BaseUrl = "http://147.93.55.224:8000/api/v1";

        // matches "CVE-2026-7210   7.5   https://vulners.com/cve/CVE-2026-7210"
        private static readonly Regex CveLine =
            new(@"(CVE-\d{4}-\d+)\s+([\d.]+)\s+(\S+)", RegexOptions.IgnoreCase | RegexOptions.Compiled);

        public ScanService(HttpClient httpClient, CyberBriefDbContext db, ICVEexplanationService cve)
        {
            _httpClient = httpClient;
            _db = db;
            _cve = cve;
        }

        public async Task<(bool AlreadyDone, string ScanId)> StartScanAsync(string target)
        {
            var existing = await _db.ScanRecords
                .FirstOrDefaultAsync(s => s.Target == target);

            // Already completed -> fully cached, nothing to do
            if (existing is not null && existing.Status == "completed")
                return (true, existing.ScanId);

            // Already in progress -> don't start another one
            if (existing is not null)
                return (false, existing.ScanId);

            // Never seen this target -> start fresh
            var body = new StringContent(
                JsonSerializer.Serialize(new
                {
                    target,
                    scan_type = "unified",
                    options = new { },
                    min_severity = "info",
                    exclude_patterns = Array.Empty<string>(),
                    include_tags = Array.Empty<string>(),
                    exclude_tags = Array.Empty<string>(),
                    deduplicate = true,
                    max_findings = 0,
                    sort_by = "severity"
                }),
                Encoding.UTF8, "application/json");

            var response = await _httpClient.PostAsync($"{BaseUrl}/scan/unified", body);
            response.EnsureSuccessStatusCode();

            var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            var scanId = json.RootElement.GetProperty("scan_id").GetString()!;

            _db.ScanRecords.Add(new ScanRecord
            {
                Id = scanId,
                ScanId = scanId,
                Target = target,
                Status = "started",
                CreatedAt = DateTime.UtcNow
            });
            await _db.SaveChangesAsync();

            return (false, scanId);
        }

        public async Task<(string ScanId, string Target, string Status)> CheckStatusAsync(string target)
        {
            var record = await _db.ScanRecords.FirstOrDefaultAsync(s => s.Target == target);

            if (record is null)
                throw new KeyNotFoundException($"No scan found for target: {target}");

            // Local state is the source of truth once completed: don't ask the
            // third-party scanner again -- it may be down or report a stale state.
            if (record.Status == "completed")
                return (record.ScanId, target, "completed");

            try
            {
                var response = await _httpClient.GetAsync($"{BaseUrl}/results/{record.ScanId}");
                response.EnsureSuccessStatusCode();

                var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
                var status = json.RootElement.GetProperty("status").GetString()!;

                record.Status = status;
                await _db.SaveChangesAsync();

                return (record.ScanId, target, status);
            }
            catch (HttpRequestException)
            {
                // Scanner unreachable -> return the last known status instead of
                // throwing a 500, so the client can keep polling / retry later.
                return (record.ScanId, target, record.Status);
            }
        }

        // ── JSON result (mirrors ContainerServices.GetSummary) ────────────────
        public async Task<WebScanResultDto> GetResultAsync(string target)
        {
            var record = await _db.ScanRecords
                .Include(s => s.Summary)
                    .ThenInclude(s => s.Findings)
                .FirstOrDefaultAsync(s => s.Target == target);

            if (record is null)
                throw new KeyNotFoundException($"No scan found for target: {target}");

            // Already built -> serve from DB
            if (record.Summary is not null)
                return MapToDto(record, record.Summary);

            // Confirm the remote scan is actually done before fetching results
            var (_, _, status) = await CheckStatusAsync(target);
            if (status != "completed")
            {
                return new WebScanResultDto
                {
                    ScanId = record.ScanId,
                    Target = target,
                    Status = status,
                    Findings = new List<WebFindingDto>()
                };
            }

            // Fetch + parse the unified JSON results
            var response = await _httpClient.GetAsync($"{BaseUrl}/results/{record.ScanId}");
            response.EnsureSuccessStatusCode();

            using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            var findings = ParseFindings(doc.RootElement);

            var summary = new WebScanSummary
            {
                Id = Guid.NewGuid().ToString(),
                ScanRecordId = record.Id,
                StartedAt = record.CreatedAt,
                FinishedAt = DateTime.UtcNow,
                TotalFindings = findings.Count,
                CriticalCount = findings.Count(f => f.Severity == "critical"),
                HighCount = findings.Count(f => f.Severity == "high"),
                MediumCount = findings.Count(f => f.Severity == "medium"),
                LowCount = findings.Count(f => f.Severity == "low"),
                InfoCount = findings.Count(f => f.Severity == "info"),
                Findings = findings
            };

            record.Status = "completed";
            _db.WebScanSummaries.Add(summary);
            await _db.SaveChangesAsync();

            // Reuse the container's NVD/OSV enrichment for the CVE rows
            await _cve.EnrichWebCvesAsync(record.ScanId);

            // Reload findings with the freshly written explanation/patch
            await _db.Entry(summary).Collection(s => s.Findings).LoadAsync();
            return MapToDto(record, summary);
        }

        // ── parse the unified findings[] into WebFinding rows ─────────────────
        private static List<WebFinding> ParseFindings(JsonElement root)
        {
            var result = new List<WebFinding>();
            var seenCves = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            if (!root.TryGetProperty("findings", out var findings) ||
                findings.ValueKind != JsonValueKind.Array)
                return result;

            foreach (var f in findings.EnumerateArray())
            {
                var tool = GetStr(f, "tool");
                var severity = NormalizeSeverity(GetStr(f, "severity"));
                var issue = GetStr(f, "issue");
                var endpoint = GetStr(f, "endpoint");
                var description = GetStr(f, "description");

                var isVulners = tool.Equals("nmap", StringComparison.OrdinalIgnoreCase)
                                && issue.Contains("vulners", StringComparison.OrdinalIgnoreCase);

                if (isVulners && !string.IsNullOrWhiteSpace(description))
                {
                    // explode the block into one row per CVE, tracking the cpe header
                    var currentProduct = "Unknown product";
                    foreach (var rawLine in description.Split('\n'))
                    {
                        var line = rawLine.Trim();
                        if (line.StartsWith("cpe:", StringComparison.OrdinalIgnoreCase))
                        {
                            currentProduct = line.TrimEnd(':');
                            continue;
                        }

                        var m = CveLine.Match(line);
                        if (!m.Success) continue;

                        var cve = m.Groups[1].Value.ToUpperInvariant();
                        if (!seenCves.Add(cve)) continue;

                        var cvss = double.TryParse(m.Groups[2].Value, NumberStyles.Float,
                            CultureInfo.InvariantCulture, out var s) ? s : 0;

                        result.Add(new WebFinding
                        {
                            Id = Guid.NewGuid().ToString(),
                            Source = tool,
                            Severity = SeverityFromCvss(cvss),
                            Issue = currentProduct,
                            Cve = cve,
                            Endpoint = string.IsNullOrWhiteSpace(endpoint) ? null : endpoint,
                            ReferenceUrl = m.Groups[3].Value,
                            // Explanation/Patch filled by the CVE enrichment service
                        });
                    }
                    continue;
                }

                // non-CVE finding: the scanner's own description is the explanation
                result.Add(new WebFinding
                {
                    Id = Guid.NewGuid().ToString(),
                    Source = tool,
                    Severity = severity,
                    Issue = string.IsNullOrWhiteSpace(issue) ? "Finding" : issue,
                    Cve = null,
                    Endpoint = string.IsNullOrWhiteSpace(endpoint) ? null : endpoint,
                    Description = string.IsNullOrWhiteSpace(description) ? null : description,
                    Explanation = string.IsNullOrWhiteSpace(description) ? null : description
                });
            }

            return result;
        }

        private static WebScanResultDto MapToDto(ScanRecord record, WebScanSummary summary)
        {
            return new WebScanResultDto
            {
                ScanId = record.ScanId,
                Target = record.Target,
                Status = record.Status,
                TotalFindings = summary.TotalFindings,
                CriticalCount = summary.CriticalCount,
                HighCount = summary.HighCount,
                MediumCount = summary.MediumCount,
                LowCount = summary.LowCount,
                InfoCount = summary.InfoCount,
                Findings = summary.Findings
                    .OrderBy(f => SeverityRank(f.Severity))
                    .Select(f => new WebFindingDto
                    {
                        Source = f.Source,
                        Cve = f.Cve,
                        Issue = f.Issue,
                        Severity = f.Severity,
                        Endpoint = f.Endpoint,
                        Description = f.Description,
                        Explanation = f.Explanation,
                        Patch = f.Patch,
                        ReferenceUrl = f.ReferenceUrl
                    })
                    .ToList()
            };
        }

        private static string GetStr(JsonElement el, string name) =>
            el.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String
                ? (v.GetString() ?? string.Empty)
                : string.Empty;

        private static string NormalizeSeverity(string sev)
        {
            var s = (sev ?? string.Empty).Trim().ToLowerInvariant();
            return s switch
            {
                "critical" => "critical",
                "high" => "high",
                "medium" => "medium",
                "low" => "low",
                "info" or "informational" => "info",
                _ => "info"
            };
        }

        private static string SeverityFromCvss(double score) => score switch
        {
            >= 9.0 => "critical",
            >= 7.0 => "high",
            >= 4.0 => "medium",
            > 0.0 => "low",
            _ => "info"
        };

        private static int SeverityRank(string sev) => sev switch
        {
            "critical" => 0,
            "high" => 1,
            "medium" => 2,
            "low" => 3,
            _ => 4
        };
    }
}
