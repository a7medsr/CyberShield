using System.Net.Http.Json;
using System.Text.Json;
using System.Text.RegularExpressions;
using CyberBrief.Context;
using Microsoft.EntityFrameworkCore;

namespace CyberBrief.Services
{
    public class CVEexplanationService
    {
        private readonly CyberBriefDbContext _context;
        private readonly HttpClient _http;

        private const string NvdUrl    = "https://services.nvd.nist.gov/rest/json/cves/2.0";
        private const string OsvUrl    = "https://api.osv.dev/v1/vulns";
        private const int    BatchSize = 4;

        private readonly string? _nvdApiKey;

        public CVEexplanationService(CyberBriefDbContext context, HttpClient http, IConfiguration config)
        {
            _context   = context;
            _http      = http;
            _nvdApiKey = config["NvdApiKey"];
        }

        // ── MAIN ENTRY POINT ─────────────────────────────────────────────────
        public async Task<List<Vulnerability>> GetExplanation(string imageName)
        {
            var imageId = await _context.Images
                .Where(x => x.Name == imageName)
                .Select(x => x.Id)
                .FirstOrDefaultAsync();

            var vulnerabilities = await _context.Summarys
                .Where(x => x.ImageId == imageId)
                .SelectMany(s => s.Vulnerabilities)
                .Where(x => x.Explanation == null)
                .ToListAsync();

            if (!vulnerabilities.Any())
                return vulnerabilities;

            var batches = vulnerabilities
                .Select((v, i) => new { v, i })
                .GroupBy(x => x.i / BatchSize)
                .Select(g => g.Select(x => x.v).ToList());

            foreach (var batch in batches)
                await Task.WhenAll(batch.Select(v => ProcessVulnerability(v)));

            await _context.SaveChangesAsync();
            return vulnerabilities;
        }

        // ── PROCESS ONE CVE ───────────────────────────────────────────────────
        private async Task ProcessVulnerability(Vulnerability vuln)
        {
            // fire NVD and OSV simultaneously
            var nvdTask = FetchNvdDescription(vuln.Id);
            var osvTask = FetchOsvRawPatch(vuln.Id);

            await Task.WhenAll(nvdTask, osvTask);

            var nvdDescription = await nvdTask;
            var osvResult      = await osvTask;

            // always try to extract version from whichever description we have
            var descriptionForExtraction = !string.IsNullOrEmpty(nvdDescription)
                ? nvdDescription
                : osvResult?.OsvDescription;

            var extractedVersion = ExtractVersionFromDescription(descriptionForExtraction, vuln.Package);

            // ── explanation: NVD → OSV details → fallback ──
            if (!string.IsNullOrEmpty(nvdDescription))
            {
                vuln.Explanation = nvdDescription;
            }
            else if (!string.IsNullOrEmpty(osvResult?.OsvDescription))
            {
                vuln.Explanation = osvResult.OsvDescription;
            }
            else
            {
                vuln.Explanation =
                    $"No description currently available for {vuln.Id}. " +
                    $"Check https://nvd.nist.gov/vuln/detail/{vuln.Id} for updates.";
            }

            // ── patch: clean version → extracted version → package manager → advisory ──
            if (osvResult == null)
            {
                vuln.Batch = extractedVersion != null
                    ? $"Update {vuln.Package} to version {extractedVersion} or later to remediate this vulnerability."
                    : "No patch information available. Monitor vendor advisories for updates.";
            }
            else if (osvResult.HasCommitHashes)
            {
                vuln.Batch = extractedVersion != null
                    ? $"Update {vuln.Package} to version {extractedVersion} or later to remediate this vulnerability."
                    : $"A patch is available for {vuln.Package}. Apply the latest security update " +
                      $"from your package manager (e.g. apk upgrade {vuln.Package} or apt upgrade {vuln.Package}).";
            }
            else
            {
                vuln.Batch = osvResult.RawPatch;
            }
        }

        // ── NVD: official description ─────────────────────────────────────────
        private async Task<string?> FetchNvdDescription(string cveId)
        {
            try
            {
                var request = new HttpRequestMessage(HttpMethod.Get,
                    $"{NvdUrl}?cveId={Uri.EscapeDataString(cveId)}");

                if (!string.IsNullOrEmpty(_nvdApiKey))
                    request.Headers.Add("apiKey", _nvdApiKey);

                var response = await _http.SendAsync(request);
                if (!response.IsSuccessStatusCode) return null;

                using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());

                var vulns = doc.RootElement.GetProperty("vulnerabilities");
                if (vulns.GetArrayLength() == 0) return null;

                foreach (var desc in vulns[0]
                    .GetProperty("cve")
                    .GetProperty("descriptions")
                    .EnumerateArray())
                {
                    if (desc.GetProperty("lang").GetString() == "en")
                        return desc.GetProperty("value").GetString();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[NVD] {cveId}: {ex.Message}");
            }

            return null;
        }

        // ── OSV: fixed version + fallback description ─────────────────────────
        private async Task<OsvPatchResult?> FetchOsvRawPatch(string cveId)
        {
            try
            {
                var response = await _http.GetAsync($"{OsvUrl}/{Uri.EscapeDataString(cveId)}");
                if (!response.IsSuccessStatusCode) return null;

                using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
                var root = doc.RootElement;

                // capture OSV description as fallback for when NVD has nothing
                string? osvDescription = null;
                if (root.TryGetProperty("details", out var details))
                    osvDescription = details.GetString();
                else if (root.TryGetProperty("summary", out var summary))
                    osvDescription = summary.GetString();

                if (!root.TryGetProperty("affected", out var affected))
                    return new OsvPatchResult
                    {
                        RawPatch        = "No patch information available. Monitor vendor advisories for updates.",
                        HasCommitHashes = false,
                        OsvDescription  = osvDescription
                    };

                var fixedVersions = new List<string>();
                var ecosystems    = new List<string>();

                foreach (var aff in affected.EnumerateArray())
                {
                    if (aff.TryGetProperty("package", out var pkg))
                    {
                        var eco = pkg.TryGetProperty("ecosystem", out var e) ? e.GetString() : null;
                        if (!string.IsNullOrEmpty(eco) && !ecosystems.Contains(eco))
                            ecosystems.Add(eco);
                    }

                    if (!aff.TryGetProperty("ranges", out var ranges)) continue;

                    foreach (var range in ranges.EnumerateArray())
                    {
                        if (!range.TryGetProperty("events", out var events)) continue;

                        foreach (var evt in events.EnumerateArray())
                            if (evt.TryGetProperty("fixed", out var fixedVal))
                            {
                                var version = fixedVal.GetString();
                                if (!string.IsNullOrEmpty(version) && !fixedVersions.Contains(version))
                                    fixedVersions.Add(version);
                            }
                    }
                }

                if (!fixedVersions.Any())
                    return new OsvPatchResult
                    {
                        RawPatch        = "A fix is being tracked but no patched version has been released yet. Monitor the vendor advisory.",
                        HasCommitHashes = false,
                        OsvDescription  = osvDescription
                    };

                // detect if all versions are git commit hashes (40 hex chars)
                var hasHashes  = fixedVersions.All(v =>
                    v.Length == 40 && v.All(c => "0123456789abcdef".Contains(c)));

                var ecoContext = ecosystems.Any() ? $" ({string.Join(", ", ecosystems)})" : "";
                var rawPatch   = hasHashes
                    ? string.Join(", ", fixedVersions)
                    : $"Update {fixedVersions[0]}{ecoContext} or later to remediate this vulnerability.";

                return new OsvPatchResult
                {
                    RawPatch        = rawPatch,
                    HasCommitHashes = hasHashes,
                    OsvDescription  = osvDescription
                };
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[OSV] {cveId}: {ex.Message}");
                return null;
            }
        }

        // ── extract version from description text ─────────────────────────────
        private static string? ExtractVersionFromDescription(string? description, string package)
        {
            if (string.IsNullOrEmpty(description)) return null;

            var patterns = new[]
            {
                @"This vulnerability is fixed in (\d+\.\d+[\.\d]*)",
                @"fixed in (\d+\.\d+[\.\d]*)",
                @"before (\d+\.\d+[\.\d]*)",
                @"prior to (\d+\.\d+[\.\d]*)",
                @"upgrade to (\d+\.\d+[\.\d]*)",
                @"update to (\d+\.\d+[\.\d]*)",
                @"version (\d+\.\d+[\.\d]*) or later",
                @"(\d+\.\d+[\.\d]*) fixes",
                @"patched in (\d+\.\d+[\.\d]*)",
            };

            foreach (var pattern in patterns)
            {
                var match = Regex.Match(description, pattern, RegexOptions.IgnoreCase);
                if (match.Success)
                    return match.Groups[1].Value.TrimEnd('.');
            }

            return null;
        }

        // ── DTOs ──────────────────────────────────────────────────────────────
        private class OsvPatchResult
        {
            public string  RawPatch        { get; set; } = string.Empty;
            public bool    HasCommitHashes { get; set; }
            public string? OsvDescription  { get; set; }
        }
    }
}