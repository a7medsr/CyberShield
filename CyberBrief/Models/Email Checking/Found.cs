using System.ComponentModel.DataAnnotations;

namespace CyberBrief.Models.Email_Checking
{
    public class Found
    {
        public string Id { get; set; }
        public string Email { get; set; }
        public string Passowrd { get; set; }

        public string Hash { get; set; }
        public string Source { get; set; }


        public string ResultId { get; set; }
        public Result Result { get; set; }
    }
}
