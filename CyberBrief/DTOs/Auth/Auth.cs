using System.ComponentModel.DataAnnotations;

namespace CyberBrief.DTOs.Auth
{
    // DTOs/Auth/RegisterDto.cs
    public class RegisterDto
    {
        [Required] public string FirstName { get; set; } = string.Empty;
        [Required] public string LastName { get; set; } = string.Empty;
        [Required][EmailAddress] public string Email { get; set; } = string.Empty;
        [Required][MinLength(8)] public string Password { get; set; } = string.Empty;

    }

    // DTOs/Auth/LoginDto.cs
    public class LoginDto
    {
        [Required][EmailAddress] public string Email { get; set; } = string.Empty;
        [Required] public string Password { get; set; } = string.Empty;
    }

    // DTOs/Auth/ForgotPasswordDto.cs
    public class ForgotPasswordDto
    {
        [Required][EmailAddress] public string Email { get; set; } = string.Empty;
    }

    // DTOs/Auth/ResetPasswordDto.cs
    public class ResetPasswordDto
    {
        [Required] public string Email { get; set; } = string.Empty;
        [Required] public string Token { get; set; } = string.Empty;
        [Required][MinLength(8)] public string NewPassword { get; set; } = string.Empty;
    }

    // DTOs/Auth/ChangePasswordDto.cs
    public class ChangePasswordDto
    {
        [Required] public string CurrentPassword { get; set; } = string.Empty;
        [Required][MinLength(8)] public string NewPassword { get; set; } = string.Empty;
    }
}
