namespace CyberBrief.Services.IServices
{
    public interface IScanService
    {
        Task<(bool AlreadyDone, string ScanId)> StartScanAsync(string target);
        Task<(string ScanId, string Target, string Status)> CheckStatusAsync(string target);
        Task<byte[]> GetReportPdfAsync(string target);
    }
}
