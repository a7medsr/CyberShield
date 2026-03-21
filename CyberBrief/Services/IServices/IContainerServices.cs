namespace CyberBrief.Services.IServices;

public interface IContainerServices
{
    Task<object> GetSummary(string Imagename);
    Task<string> StratScanAsync(imgforscan img);
}