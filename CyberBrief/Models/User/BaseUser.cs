using Microsoft.AspNetCore.Identity;

namespace CyberBrief.Models.User
{
    public class BaseUser: IdentityUser
    {
        public string FirstName { get; set; } = string.Empty;
        public string LastName { get; set; } = string.Empty;
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        public string FullName => $"{FirstName} {LastName}";


    }
}
