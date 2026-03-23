using System.ComponentModel.DataAnnotations;

namespace CyberBrief.Models.Email_Checking
{
    public class EmailVerification
    {
        [Key]
        public string Email { get; set; }
        public string OtpCode { get; set; }
        public DateTime Expiry { get; set; }
        public bool IsVerified { get; set; } = false;
    }
}
