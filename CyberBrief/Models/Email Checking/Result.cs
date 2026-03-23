namespace CyberBrief.Models.Email_Checking
{
    public class Result
    {
        public string Id { set; get; }
        public string Email { set; get; }
        public bool Status { set; get; }
        public int ResultsCount {  set; get; } = 0;
        public List<Found>? Founds { set; get; }
        
    }
}
