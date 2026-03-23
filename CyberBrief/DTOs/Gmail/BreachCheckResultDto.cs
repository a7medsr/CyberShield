namespace CyberBrief.DTOs.Gmail
{
    public class BreachCheckResultDto
    {
        public string Email { get; set; }
        public bool Status { get; set; }
        public int ResultsCount { get; set; }
        public List<FoundDto> Founds { get; set; }
    }
}
