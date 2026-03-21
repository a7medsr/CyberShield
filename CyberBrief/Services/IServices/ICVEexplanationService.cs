namespace CyberBrief.Services.IServices;

public interface ICVEexplanationService
{
    Task<List<Vulnerability>> GetExplanation(string imageName);
}