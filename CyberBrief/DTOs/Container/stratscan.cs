public class imgforscan
{
    public string image { get; set; }
    public string? tag{ get; set; }

    public string? Source { get; set; }
    public string? dockerImageId { get; set; }
    public string? repositoryId { get; set; }
}
public record ScanRequest(
    string image,
    string tag,
    string source,
    string dockerImageId,
    string repositoryId
);