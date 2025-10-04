namespace CyberBrief.Models.Gmail
{
    public class BreachResponseDto
    {
        public bool Success { get; set; }
        public int Found { get; set; }
        public List<BreachResultDto> Result { get; set; }
        public string Message { get; set; }
    }
}
