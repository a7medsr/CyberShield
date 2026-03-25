using CyberBrief.Context;
using CyberBrief.Models.Web_Scaning;
using CyberBrief.Services.IServices;
using Microsoft.EntityFrameworkCore;
using System;
using System.Diagnostics.Metrics;
using System.Text;
using System.Text.Json;

namespace CyberBrief.Services.Web_scan_services
{
    public class ScanService : IScanService
    {
        private readonly HttpClient _httpClient;
        private readonly CyberBriefDbContext _db;
        private const string BaseUrl = "http://147.93.55.224:8000/api/v1";

        public ScanService(HttpClient httpClient, CyberBriefDbContext db)
        {
            _httpClient = httpClient;
            _db = db;
        }

        public async Task<(bool AlreadyDone, string ScanId)> StartScanAsync(string target)
        {
            var existing = await _db.ScanRecords
                .FirstOrDefaultAsync(s => s.Target == target);

            // Already completed with PDF → fully cached, nothing to do
            if (existing is not null && existing.Status == "completed" && existing.PdfReport != null)
                return (true, existing.ScanId);

            // Already in progress → don't start another one
            if (existing is not null)
                return (false, existing.ScanId);

            // Never seen this target → start fresh
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

            var response = await _httpClient.GetAsync($"{BaseUrl}/results/{record.ScanId}");
            response.EnsureSuccessStatusCode();

            var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            var status = json.RootElement.GetProperty("status").GetString()!;

            record.Status = status;
            await _db.SaveChangesAsync();

            return (record.ScanId, target, status);
        }

        public async Task<byte[]> GetReportPdfAsync(string target)
        {
            var record = await _db.ScanRecords.FirstOrDefaultAsync(s => s.Target == target);

            if (record is null)
                throw new KeyNotFoundException($"No scan found for target: {target}");

            // Already cached → serve from DB
            if (record.PdfReport is not null)
                return record.PdfReport;

            // Fetch, store, return
            var response = await _httpClient.GetAsync($"{BaseUrl}/reports/{record.ScanId}/advanced-pdf");
            response.EnsureSuccessStatusCode();

            var pdf = await response.Content.ReadAsByteArrayAsync();

            record.PdfReport = pdf;
            await _db.SaveChangesAsync();

            return pdf;
        }
    }
}
