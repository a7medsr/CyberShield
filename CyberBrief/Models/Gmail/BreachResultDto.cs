namespace CyberBrief.Models.Gmail
{
    public class BreachResultDto
    {
        public string Email { get; set; }
        public bool Hash_Password { get; set; }
        public string Password { get; set; }
        public string Sha1 { get; set; }
        public string Hash { get; set; }
        public string Sources { get; set; }
    }
}
