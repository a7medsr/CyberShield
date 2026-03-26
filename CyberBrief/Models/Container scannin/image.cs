using CyberBrief.Models.User;

public class Image
{
    public string Id { get; set; }
    public string Name { get; set; }
    public string Tag { get; set; }
    public string requestId { get; set; }
    public string scanId { get; set; }
    public string? Status { get; set; }
    public int? Progres{ get; set; }
    public string? SummaryId { get; set; }
    public ICollection<BaseUser> Users { get; set; } = new List<BaseUser>();


}